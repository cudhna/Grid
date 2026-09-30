"""
Mock tools.py for running GRID without Dropbox dependency.
This file provides minimal implementations of functions required by GRID.
"""
import os
import time
import json
import threading
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional

# Timeout cho mỗi request lên vLLM. T4 sinh token chậm nên cần rộng.
REQUEST_TIMEOUT = int(os.environ.get("VLLM_REQUEST_TIMEOUT", "1800"))

# Nhật ký gọi vLLM (A1): giúp phân biệt 3 khả năng
#   1) model trả list rỗng        -> finish_reason="stop",  completion_tokens > 0
#   2) model bị cắt output        -> finish_reason="length"
#   3) request hỏng / timeout     -> error khác None
_CALL_LOG_DIR = os.environ.get("GRID_CALL_LOG_DIR") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "grid_raw"
)
_CALL_LOG_FILE = os.path.join(_CALL_LOG_DIR, "vllm_calls.jsonl")
_CALL_LOG_LOCK = threading.Lock()
_CALL_COUNT = 0


def _log_call(entry: Dict[str, Any]) -> None:
    """Ghi 1 dòng JSONL cho mỗi lần gọi vLLM. Lỗi ghi log không được làm hỏng run."""
    global _CALL_COUNT
    with _CALL_LOG_LOCK:
        _CALL_COUNT += 1
        entry = {"call_index": _CALL_COUNT,
                 "timestamp": datetime.now().isoformat(timespec="seconds"),
                 **entry}
        try:
            os.makedirs(_CALL_LOG_DIR, exist_ok=True)
            with open(_CALL_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as exc:  # noqa: BLE001
            print(f"(không ghi được vllm_calls.jsonl: {exc})")


def ask_group_link(
    prompt_list: List[List[Dict[str, str]]],
    model: str = "local",
    token: int = 16384,
    temp: float = 0.3,
    think: int = 0,
    streamprint: bool = False,
    check_history_cache: bool = True,
    retry: bool = False,
    force_api_do_huge_input_Cloud: bool = True,
    VllmSmartMode: bool = False,
    max_workers_Vllm: Any = 64,
    prompt_send_weight_VllmNotSmartMode: Optional[Dict[str, int]] = None,
    vllm_server_name: Optional[str] = None,
    top_p: Any = "NotSet",
    top_k: Any = "NotSet",
    extra_kwargs: Optional[Dict[str, Any]] = None,
    **kwargs
) -> List[str]:
    """
    Call vLLM server via OpenAI-compatible API.
    """
    vllm_url = os.environ.get("VLLM_URL", "http://localhost:8000/v1")
    api_key = os.environ.get("VLLM_API_KEY", "EMPTY")

    responses = []
    for messages in prompt_list:
        try:
            payload = {
                "model": model if model != "local" else os.environ.get("VLLM_MODEL_NAME", "Qwen3-4B-Instruct-2507"),
                "messages": messages,
                "max_tokens": token,
                "temperature": temp,
            }
            if top_p != "NotSet":
                payload["top_p"] = float(top_p)
            if top_k != "NotSet":
                payload["top_k"] = int(top_k)

            headers = {"Authorization": f"Bearer {api_key}"}
            started = time.time()
            resp = requests.post(
                f"{vllm_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            result = resp.json()
            usage = result.get("usage") or {}
            choice = (result.get("choices") or [{}])[0]
            content = choice.get("message", {}).get("content") or ""
            finish_reason = choice.get("finish_reason")
            elapsed = time.time() - started
            # finish_reason == "length" nghĩa là model bị cắt output -> có thể mất
            # #..._End#, nên parser chỉ cứu được một phần danh sách.
            truncated = (finish_reason == "length")
            print(
                f"  vLLM call: {elapsed:.1f}s | "
                f"prompt_tokens={usage.get('prompt_tokens')} "
                f"completion_tokens={usage.get('completion_tokens')} "
                f"chars={len(content)} finish_reason={finish_reason}"
                + ("  [BI CAT OUTPUT]" if truncated else "")
            )
            _log_call({
                "seconds": round(elapsed, 1),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
                "max_tokens": token,
                "temperature": temp,
                "chars": len(content),
                "finish_reason": finish_reason,
                "truncated": truncated,
                "prompt_chars": len(json.dumps(messages, ensure_ascii=False)),
                "error": None,
            })
            responses.append(content)
        except Exception as e:
            print(f"Error calling vLLM: {e}")
            # Ghi lại lỗi để phân biệt "model trả rỗng" với "request hỏng" (A1).
            _log_call({
                "seconds": None, "prompt_tokens": None, "completion_tokens": None,
                "max_tokens": token, "temperature": temp, "chars": 0,
                "finish_reason": None, "truncated": False, "prompt_chars": None,
                "error": f"{type(e).__name__}: {e}",
            })
            responses.append("")

    return responses


def llmname(server: str = "local", shortname: bool = False) -> str:
    """Return model name."""
    model_name = os.environ.get("VLLM_MODEL_NAME", "Qwen3-4B-Instruct-2507")
    if shortname:
        return model_name.split("/")[-1]
    return model_name


def get_vllm_realtime_stats(server: str = "local") -> Dict[str, Any]:
    """Return mock stats."""
    return {"success": True, "waiting": 0, "running": 0, "kv_usage": 0, "iteration_tokens": 0, "metrics_backend": "vllm"}


def check_cache_batch(
    prompt_list: List[List[Dict[str, str]]],
    model: str = "local",
    token: int = 16384,
    temp: float = 0.3,
    think: int = 0,
    max_workers_Vllm: Any = 64,
    model_name_override: Optional[str] = None,
    top_p: Any = "NotSet",
    top_k: Any = "NotSet",
    **kwargs
) -> tuple:
    """Return empty cache (no caching)."""
    return {}, list(range(len(prompt_list))), list(range(len(prompt_list)))


def get_prompt_hash(prompt: Any) -> str:
    """Return hash of prompt."""
    import hashlib
    import json
    return hashlib.md5(json.dumps(prompt, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def resolve_model_name(model: str, vllm_server_name: Optional[str] = None) -> str:
    """Return model name."""
    return os.environ.get("VLLM_MODEL_NAME", "Qwen3-4B-Instruct-2507")
