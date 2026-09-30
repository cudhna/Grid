"""
Mock tools.py for running GRID without Dropbox dependency.
This file provides minimal implementations of functions required by GRID.
"""
import os
import time
import requests
from typing import List, Dict, Any, Optional


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
            resp = requests.post(
                f"{vllm_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=600
            )
            resp.raise_for_status()
            result = resp.json()
            content = result["choices"][0]["message"]["content"]
            responses.append(content)
        except Exception as e:
            print(f"Error calling vLLM: {e}")
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
