"""
Run GRID two-step pipeline on Google Colab with a local vLLM server.

Phạm vi (theo yêu cầu A1-A4):
  A1  Chẩn đoán: probe parser + đọc _TemplateDebug/*.jsonl, lưu prompt/output thô,
      ghi out/grid_raw/diagnosis.md. Chạy TRƯỚC khi sửa/gọi model.
  A2  Checkpoint: in bảng kích thước các checkpoint, KHÔNG tải gì ngoài base model
      trừ khi đổi USE_BASE_MODEL = False.
  A3  Chạy riêng cho TỪNG procedure không rỗng, bỏ dòng tiêu đề "[Chunk n] Tactic - Txxxx",
      temperature = 0, retry tối đa 2 lần nếu rỗng và ghi log.
  A4  Xuất out/grid_raw/<run>/: input.txt, prompt_*.json, step1_raw.txt, step2_raw.txt,
      raw_output.txt, entities.json, relation.json, attempts.json
      + out/grid_raw/procedure_map.json + run.log + manifest.json

Usage on Colab:
    !git clone https://github.com/cudhna/Grid.git
    %cd Grid
    !python out/run_grid_colab.py

Lưu ý thư mục: sau `%cd Grid` KHÔNG được `%cd Grid` lần nữa (tạo /content/Grid/Grid).
"""

import os
import sys
import json
import re
import time
import signal
import subprocess
from pathlib import Path

try:    # console Windows mặc định là cp1252, không in được tiếng Việt
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# ===========================================================================
# Cấu hình
# ===========================================================================
MODEL_NAME = "Qwen/Qwen3-4B-Instruct-2507"   # tên ngắn, dùng làm served-model-name
USE_BASE_MODEL = True  # False -> tải anonymousauthorname/ProjectGRID/task_bank_reward (8.82 GB)

# A2: các checkpoint trong repo chỉ có link, KHÔNG có trọng số.
# Kích thước thật đo từ HuggingFace API (out/report.md mục A2).
CHECKPOINTS = {
    "base":   ("Qwen/Qwen3-4B-Instruct-2507",                     "8.05 GB", "đang dùng"),
    "task_bank_reward": ("anonymousauthorname/ProjectGRID/task_bank_reward",
                         "8.82 GB", "model chính của paper (RQ1: 84.62% precision)"),
    "gptoss120b_generator_sft": ("anonymousauthorname/ProjectGRID/gptoss120b_generator_sft",
                                 "17.65 GB", "SFT trên data GPT-OSS-120B - gấp đôi dung lượng"),
    "end2end_reward": ("anonymousauthorname/ProjectGRID/end2end_reward",
                       "8.82 GB", "biến thể ablation"),
    "choice_only_reward": ("anonymousauthorname/ProjectGRID/choice_only_reward",
                           "8.82 GB", "biến thể ablation"),
    "end2end_sft_without_rl": ("anonymousauthorname/ProjectGRID/end2end_sft_without_rl",
                               "8.82 GB", "biến thể ablation"),
}
# Không tải `llama31_8b_task_bank_reward` (~16 GB): T4 chỉ có 16 GB VRAM.

VLLM_PORT = 8000
VLLM_HOST = "0.0.0.0"

# T4 chỉ có 16GB: model fp16 chiếm ~8GB, còn ~5GB cho KV cache.
# Input của GRID rất nhỏ: prompt Step 1 đo được ~9.6K ký tự (~2.7K token) + input
# 1.6K ký tự (~445 token) → 16384 là rất dư.
MAX_MODEL_LEN = 16384
GPU_MEMORY_UTILIZATION = 0.92

# T4 (Turing/sm_75) KHÔNG có BF16 tensor core → bf16 bị mô phỏng bằng phần mềm,
# sinh token cực chậm (thường timeout). FP16 dùng được tensor core của T4.
DTYPE = "float16"

SERVED_MODEL_NAME = MODEL_NAME.split("/")[-1]

# --- A3 -------------------------------------------------------------------
GRID_TEMP = 0.0            # yêu cầu: temperature 0
MAX_RETRIES = 2            # yêu cầu: rỗng thì thử lại tối đa 2 lần
RUN_AGGREGATE = True       # chạy thêm 1 lần với cả 7 procedure (để so sánh lần cũ)
RUN_PER_PROCEDURE = True   # chạy riêng từng procedure
INCLUDE_TECHNIQUE_HEADER = False   # bỏ dòng "[Chunk n] Tactic - Txxxx" khỏi input gửi model

# max_tokens phải nhỏ hơn max_model_len, nếu không vLLM trả lỗi 400
MAX_NEW_TOKENS = min(64 * 1024, MAX_MODEL_LEN // 2)   # = 8192

OUT_DIR = Path(__file__).resolve().parent
REPO_ROOT = OUT_DIR.parent
sys.path.insert(0, str(OUT_DIR))
sys.path.insert(0, str(REPO_ROOT / "src" / "grid"))

# tools.py mặc định được nạp từ ~/Dropbox (không tồn tại trên Colab) -> trỏ sang out/
os.environ.setdefault("GRID_TOOLS_FILE", str(OUT_DIR / "tools.py"))

GRID_RAW_DIR = OUT_DIR / "grid_raw"          # A4
TEMPLATE_DEBUG_DIR = REPO_ROOT / "src" / "GeneratedKGContent" / "_TemplateDebug"

# report_1.json: sau khi `git pull` mới có. Thử nhiều vị trí, không tự tạo file.
REPORT_CANDIDATES = [
    REPO_ROOT / "report_1.json",
    REPO_ROOT / "phuong_phap_2" / "report_1.json",
    OUT_DIR / "report_1.json",
]


# ===========================================================================
# A2 - bảng checkpoint
# ===========================================================================
def print_checkpoint_table() -> str:
    """In bảng checkpoint + quyết định model sẽ dùng. Trả về model_id."""
    print("=" * 68)
    print("A2. Checkpoint sẽ dùng")
    print("=" * 68)
    print("Thư mục models/*/ trong repo CHỈ CÓ FILE LINK, không có trọng số.")
    print("Muốn dùng checkpoint hậu huấn luyện thì phải tải từ HuggingFace.\n")
    width = max(len(k) for k in CHECKPOINTS)
    for key, (repo, size, note) in CHECKPOINTS.items():
        mark = "  <-- ĐANG DÙNG" if (USE_BASE_MODEL and key == "base") else ""
        print(f"  {key:<{width}}  {size:>9}  {note}{mark}")
    print("\n  llama31_8b_task_bank_reward (~16 GB): KHÔNG tải - T4 chỉ có 16 GB VRAM.")

    if USE_BASE_MODEL:
        model_id = CHECKPOINTS["base"][0]
        print(f"\n-> Dùng base model: {model_id} (không tải gì thêm).")
    else:
        model_id = CHECKPOINTS["task_bank_reward"][0]
        print(f"\n-> CẢNH BÁO: sẽ tải {CHECKPOINTS['task_bank_reward'][1]} "
              f"từ {model_id}. Đổi USE_BASE_MODEL = False trong file này để tải.")
    return model_id


# ===========================================================================
# Cài đặt / server
# ===========================================================================
def install_dependencies():
    print("=" * 60)
    print("Step 1: Installing dependencies...")
    print("=" * 60)

    packages = [
        "openai>=1.30.0",
        "pandas>=2.0.0",
        "pyarrow>=14.0.0",
        # BẮT BUỘC: article_io_cache_parser._robust_json_parse() gọi
        # `import json_repair` để đọc #Entity_List_Start# / #Relationship_List_Start#.
        # Thiếu package này -> ImportError bị nuốt bởi `except Exception: pass`
        # -> entities/relations = [] dù model đã trả kết quả đúng.
        # ĐÃ ĐO (out/grid_diagnose.py): thiếu json_repair thì cả 6 mẫu chuẩn đều ra 0.
        "json-repair>=0.30.0",
        "requests>=2.31.0",
        # Colab dùng Python 3.13 -> cần vLLM >= 0.11. Pin 0.11.0: hỗ trợ
        # Python 3.13 + sm_75 (T4) + torch 2.8/cu128, chạy ổn định trên Colab free.
        "vllm==0.11.0",
        # transformers 5.x đã bỏ `all_special_tokens_extended` mà vLLM 0.11.0
        # dùng -> AttributeError lúc khởi động. Giới hạn <5 (>=4.55.2 theo yêu cầu vLLM).
        "transformers>=4.55.2,<5.0.0",
        "accelerate>=0.34.0",
        "safetensors>=0.4.3",
    ]

    for pkg in packages:
        print(f"Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

    verify_dependencies()
    print("Dependencies installed!")


def verify_dependencies():
    """Fail fast nếu thiếu package mà code repo dùng (import bị nuốt trong try/except)."""
    missing = []
    for module in ("json_repair", "requests", "openai", "pandas", "pyarrow"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        raise RuntimeError(
            f"Thiếu package: {missing}. "
            "json_repair đặc biệt quan trọng - parser sẽ trả về danh sách rỗng."
        )
    print("Dependency check: OK")


def download_model(model_id: str) -> str:
    print("=" * 60)
    print("Step 2: Downloading model...")
    print("=" * 60)
    from huggingface_hub import snapshot_download
    print(f"Downloading {model_id}...")
    local_path = snapshot_download(repo_id=model_id)
    print(f"Model downloaded to: {local_path}")
    return local_path


def start_vllm_server(model_path: str):
    print("=" * 60)
    print("Step 3: Starting vLLM server...")
    print("=" * 60)
    cmd = [
        "vllm", "serve", model_path,
        "--host", VLLM_HOST,
        "--port", str(VLLM_PORT),
        "--trust-remote-code",
        "--dtype", DTYPE,
        "--max-model-len", str(MAX_MODEL_LEN),
        "--gpu-memory-utilization", str(GPU_MEMORY_UTILIZATION),
        "--served-model-name", SERVED_MODEL_NAME,
    ]
    print(f"Starting vLLM: {' '.join(cmd)}")
    log_file = open(OUT_DIR / "vllm_server.log", "w")
    process = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid if os.name != "nt" else None,
    )
    print(f"vLLM server started (PID: {process.pid})")
    print(f"Logs: {OUT_DIR / 'vllm_server.log'}")
    return process


def print_log_tail(lines: int = 20):
    log_path = OUT_DIR / "vllm_server.log"
    if not log_path.exists():
        print(f"(log file not found: {log_path})")
        return
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.readlines()
    except Exception as e:
        print(f"Could not read log: {e}")
        return

    fatal = re.compile(
        r"(fatal error|Error:|ValueError|RuntimeError|AssertionError|"
        r"NotImplementedError|ImportError|ModuleNotFoundError|KeyError|"
        r"TypeError|OSError|out of memory|no kernel image|"
        r"EngineCore.*(failed|error))",
        re.IGNORECASE,
    )
    traceback_end = next(
        (i for i, ln in enumerate(content) if "api_server.py" in ln and "build_async" in ln),
        len(content),
    )
    hit = next((i for i, ln in enumerate(content[:traceback_end]) if fatal.search(ln)), None)

    if hit is not None:
        lo, hi = max(0, hit - 8), min(len(content), hit + 15)
        print(f"----- vLLM log: lỗi gốc (dòng {hit + 1}/{len(content)}) -----")
        print("".join(content[lo:hi]))
    else:
        print("----- (không tìm thấy lỗi gốc trong log) -----")

    print(f"----- vLLM log: {lines} dòng cuối -----")
    print("".join(content[-lines:]))
    print("----- end of log -----")


def check_gpu():
    print("=" * 60)
    print("Step 0: Checking GPU...")
    print("=" * 60)
    try:
        import torch
        if torch.cuda.is_available():
            print(f"GPU detected: {torch.cuda.get_device_name(0)}")
            print(f"CUDA version: {torch.version.cuda}")
        else:
            print("WARNING: No GPU detected!")
            print("On Colab, enable GPU first: Runtime -> Change runtime type -> GPU")
    except Exception:
        subprocess.call(["nvidia-smi"])


def ensure_dropbox_tools():
    """
    Nhiều module trong repo nạp tools.py từ ~/Dropbox (có sẵn trên máy local nhưng
    không có trên Colab). Tạo symlink trỏ tới bản mock trong out/ để không phải sửa
    từng module.
    """
    dropbox_dir = Path(os.path.expanduser("~/Dropbox"))
    dropbox_dir.mkdir(parents=True, exist_ok=True)
    dropbox_tools = dropbox_dir / "tools.py"
    if dropbox_tools.exists():
        return
    try:
        dropbox_tools.symlink_to(OUT_DIR / "tools.py")
        print(f"Linked {dropbox_tools} -> {OUT_DIR / 'tools.py'}")
    except (OSError, NotImplementedError) as e:
        import shutil
        shutil.copyfile(OUT_DIR / "tools.py", dropbox_tools)
        print(f"Copied {OUT_DIR / 'tools.py'} -> {dropbox_tools} ({e})")


def wait_for_vllm_ready(process, timeout: int = 600):
    print("=" * 60)
    print("Step 4: Waiting for vLLM server...")
    print("=" * 60)
    import requests

    start_time = time.time()
    while time.time() - start_time < timeout:
        if process.poll() is not None:
            print(f"vLLM process exited early (exit code {process.returncode})")
            print_log_tail()
            return False
        try:
            resp = requests.get(f"http://localhost:{VLLM_PORT}/v1/models", timeout=5)
            if resp.status_code == 200:
                print(f"vLLM server ready! (took {time.time() - start_time:.1f}s)")
                return True
        except Exception:
            pass
        print(f"Waiting... ({time.time() - start_time:.0f}s)")
        time.sleep(5)

    print(f"Timeout after {timeout}s")
    print_log_tail()
    return False


# ===========================================================================
# A3 - chuẩn bị input
# ===========================================================================
def find_report_path() -> Path:
    for p in REPORT_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError(
        "Không tìm thấy report_1.json. Đã thử: "
        + ", ".join(str(p) for p in REPORT_CANDIDATES)
        + "\nTrên Colab phải `git pull` trước (file này nằm trong thư mục "
          "phuong_phap_2/ chứ không nằm ở thư mục gốc của repo trên GitHub)."
    )


def build_procedures(report_path: Path) -> list:
    """Lấy procedure không rỗng, kèm chunk/tactic/technique để ghi procedure_map.json."""
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    procedures = []
    for chunk_idx, chunk in enumerate(report):
        if not chunk:
            continue
        for tactic in chunk:
            for tech in tactic.get("techniques", []):
                proc = (tech.get("procedure") or "").strip()
                if proc:
                    procedures.append({
                        "procedure_id": f"proc_{len(procedures) + 1:02d}",
                        "chunk": chunk_idx,
                        "tactic": tactic.get("name", ""),
                        "technique_id": tech.get("id", ""),
                        "technique_name": tech.get("name", ""),
                        "procedure": proc,
                    })
    return procedures


def write_procedure_map(procedures: list) -> Path:
    """A4: procedure_map.json - ánh xạ procedure -> chunk/technique/tactic."""
    GRID_RAW_DIR.mkdir(parents=True, exist_ok=True)
    path = GRID_RAW_DIR / "procedure_map.json"
    payload = {
        "source_report": str(find_report_path().name),
        "note": (
            "Mỗi procedure được GRID chạy RIENG. `grid_dir` trỏ tới thư mục trong "
            "out/grid_raw/ chứa input + output thô + entities/relations của lần chạy đó."
        ),
        "technique_header_included": INCLUDE_TECHNIQUE_HEADER,
        "count": len(procedures),
        "procedures": [
            {
                **p,
                "procedure_chars": len(p["procedure"]),
                "technique_codes_in_text": sorted(set(
                    re.findall(r"\bT\d{4}(?:\.\d{3})?\b", p["procedure"])
                )),
                "grid_dir": None,      # điền sau khi chạy
            }
            for p in procedures
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"procedure_map.json -> {path}")
    return path


def build_input_text(proc: dict) -> str:
    """
    A3: dòng tiêu đề "[Chunk n] Tactic - Txxxx" bị BỎ khỏi text gửi model.
    Thông tin chunk/technique vẫn nằm trong procedure_map.json và trong file
    input.txt của từng lần chạy, nên không mất dấu vết.
    """
    if not INCLUDE_TECHNIQUE_HEADER:
        return proc["procedure"]
    return (f"[Chunk {proc['chunk']}] {proc['tactic']} - "
            f"{proc['technique_id']} {proc['technique_name']}\n"
            f"Procedure: {proc['procedure']}")


def build_aggregate_text(procedures: list) -> str:
    """Gộp procedure, cũng bỏ dòng tiêu đề (A3)."""
    return "\n\n".join(build_input_text(p) for p in procedures)


# ===========================================================================
# A3/A4 - chạy GRID
# ===========================================================================
def make_method():
    """Tạo GRIDOursMethod với temperature 0 (A3) và dùng chính server đã bật."""
    os.environ["VLLM_URL"] = f"http://localhost:{VLLM_PORT}/v1"
    os.environ["VLLM_API_KEY"] = "EMPTY"
    os.environ["VLLM_MODEL_NAME"] = SERVED_MODEL_NAME

    from GRID_Ours import GRIDOursMethod
    from shared_eval_backend import build_default_shared_backend

    # Dùng chính server vLLM đã khởi động ở Step 3. Phải bật enabled=True để
    # VLLMServerMethod không tự deploy thêm một server riêng
    # (xem single_pass_template.py: _shared_backend_enabled).
    shared_backend = build_default_shared_backend(
        model_path=SERVED_MODEL_NAME,
        servers=("local",),
    )
    return GRIDOursMethod(
        llm_backend="shared_vllm",
        model="local",
        shared_llm_backend=shared_backend,
        token=MAX_NEW_TOKENS,
        temp=GRID_TEMP,
        think=2,
        check_cache=False,
    )


def _dump_prompt(out_dir: Path, method, text: str, entities: list | None) -> None:
    """
    Lưu prompt của từng step để kiểm chứng định dạng.
    Cả hai hàm trả về list[{"role":..., "content":...}] nên phải json.dumps.
    """
    try:
        p1 = method._create_entity_step_prompt(text)
        (out_dir / "prompt_step1.json").write_text(
            json.dumps(p1, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        (out_dir / "prompt_step1.json").write_text(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False, indent=2),
            encoding="utf-8")
    try:
        p2 = method._create_relation_step_prompt(text, candidate_entities=entities or [])
        (out_dir / "prompt_step2.json").write_text(
            json.dumps(p2, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        (out_dir / "prompt_step2.json").write_text(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False, indent=2),
            encoding="utf-8")


def _rel_to_out(path: Path) -> str:
    """Đường dẫn tương đối so với out/ (đọc được trong manifest.json)."""
    try:
        return str(Path(path).relative_to(OUT_DIR)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _classify(result: dict) -> dict:
    """Chấm điểm output thô bằng bộ phân loại của A1 (không cần model)."""
    from grid_diagnose import classify_output
    return {
        "step1": classify_output(result.get("step1_raw_output") or ""),
        "step2": classify_output(result.get("step2_raw_output") or ""),
    }


def run_one(method, label: str, text: str, out_dir: Path,
            max_retries: int = MAX_RETRIES) -> dict:
    """
    Chạy GRID một lần cho `text`, lưu đầy đủ ra out_dir (A4).
    Nếu entities và relations đều rỗng thì thử lại tối đa `max_retries` lần.

    Lưu ý về temperature: yêu cầu là temperature 0, nên các lần thử lại gần như
    cho kết quả giống nhau. Phần khác biệt đến từ tính không tất định của batching
    trong vLLM. Vì vậy log ghi rõ từng lần để không nhầm là lỗi mạng.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "input.txt").write_text(text, encoding="utf-8")

    attempts = []
    result = {}
    for attempt in range(1, max_retries + 2):
        t0 = time.time()
        try:
            result = method.generate(text)
        except Exception as exc:
            attempts.append({
                "attempt": attempt, "error": f"{type(exc).__name__}: {exc}",
                "seconds": round(time.time() - t0, 1),
            })
            print(f"    [{label}] attempt {attempt}: EXCEPTION {type(exc).__name__}: {exc}")
            continue

        n_e = len(result.get("entities") or [])
        n_r = len(result.get("relations") or [])
        info = _classify(result)
        attempts.append({
            "attempt": attempt,
            "entities": n_e,
            "relations": n_r,
            "seconds": round(time.time() - t0, 1),
            "step1_chars": info["step1"]["chars"],
            "step2_chars": info["step2"]["chars"],
            "step1_verdict": info["step1"]["verdict"],
            "step2_verdict": info["step2"]["verdict"],
        })
        print(f"    [{label}] attempt {attempt}/{max_retries + 1}: "
              f"{n_e} entities, {n_r} relations, {attempts[-1]['seconds']}s")

        if n_e or n_r:
            break
        if attempt <= max_retries:
            print(f"    [{label}] rỗng -> thử lại (temperature vẫn = {GRID_TEMP})")

    # --- ghi kết quả (A4) ---
    entities = result.get("entities") or []
    relations = result.get("relations") or []
    (out_dir / "entities.json").write_text(
        json.dumps(entities, ensure_ascii=False, indent=2), encoding="utf-8")
    # GRID gọi khoá là "relations"; A4 yêu cầu tên relation.json
    (out_dir / "relation.json").write_text(
        json.dumps(relations, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "step1_raw.txt").write_text(
        result.get("step1_raw_output") or "", encoding="utf-8")
    (out_dir / "step2_raw.txt").write_text(
        result.get("step2_raw_output") or "", encoding="utf-8")
    # raw_output.txt là output ĐÃ DỰNG LẠI từ kết quả parse
    # (GRID_backbone._build_final_split_output), KHÔNG phải output thô của model.
    (out_dir / "raw_output.txt").write_text(
        result.get("raw_output") or "", encoding="utf-8")
    (out_dir / "raw_output.NOTE.txt").write_text(
        "raw_output.txt do GRID_backbone._build_final_split_output() dựng lại từ\n"
        "entities/relations ĐÃ PARSE, không phải output thô của model.\n"
        "Output thô thật nằm ở step1_raw.txt và step2_raw.txt.\n",
        encoding="utf-8")
    (out_dir / "attempts.json").write_text(
        json.dumps({
            "label": label,
            "temperature": GRID_TEMP,
            "max_retries": max_retries,
            "retry_note": (
                "temperature = 0 nên các lần thử lại gần như tất định; khác biệt "
                "(nếu có) đến từ batching không tất định của vLLM, không phải từ nhiệt độ."
            ),
            "attempts": attempts,
            "final": {"entities": len(entities), "relations": len(relations)},
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    _dump_prompt(out_dir, method, text, entities)

    summary = {
        "label": label,
        "dir": _rel_to_out(out_dir),
        "input_chars": len(text),
        "entities": len(entities),
        "relations": len(relations),
        "attempts": len(attempts),
    }
    return summary


def log(msg: str) -> None:
    print(msg, flush=True)
    with open(GRID_RAW_DIR / "run.log", "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")


# ===========================================================================
# A1 - chẩn đoán (không cần model)
# ===========================================================================
def run_diagnosis(extra: dict | None = None) -> Path:
    """Probe parser + đọc _TemplateDebug/*.jsonl, ghi out/grid_raw/diagnosis.md."""
    import datetime
    import grid_diagnose as gd

    probe = gd.probe_parser(verbose=True)
    findings = gd.inspect_debug_jsonl(TEMPLATE_DEBUG_DIR, copy_to=GRID_RAW_DIR)
    existing = gd.inspect_existing_outputs(OUT_DIR / "grid_output")
    calls = gd.inspect_call_log(GRID_RAW_DIR)
    info = {"generated_at": datetime.datetime.now().isoformat(timespec="seconds")}
    info.update(extra or {})
    path = gd.write_report(GRID_RAW_DIR / "diagnosis.md", probe, findings, existing,
                           extra=info, calls=calls)
    log(f"A1 diagnosis -> {path} (probe={probe.get('verdict')}, "
        f"model_calls={len(findings)})")
    return path


# ===========================================================================
def main():
    log("#" * 68)
    log("GRID pipeline start")
    print("=" * 60)
    print("GRID Pipeline on Google Colab")
    print("=" * 60)

    GRID_RAW_DIR.mkdir(parents=True, exist_ok=True)

    # ---- A2: chọn checkpoint (không tải gì ngoài base trừ khi đổi cờ) ----
    model_id = print_checkpoint_table()

    # ---- A1: probe parser TRƯỚC khi tải model / gọi model ----
    print("=" * 60)
    print("A1. Chẩn đoán parser (không cần model, chạy trước để biết nguyên nhân)")
    print("=" * 60)
    early = run_diagnosis({"stage": "trước khi chạy model"})

    # Step 0: GPU + tools.py
    check_gpu()
    ensure_dropbox_tools()

    # Step 1: dependencies
    install_dependencies()

    # Step 2: model
    model_path = download_model(model_id)

    # Step 3-4: vLLM
    vllm_process = start_vllm_server(model_path)
    manifest = {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model_id": model_id,
        "served_model_name": SERVED_MODEL_NAME,
        "dtype": DTYPE,
        "max_model_len": MAX_MODEL_LEN,
        "gpu_memory_utilization": GPU_MEMORY_UTILIZATION,
        "max_new_tokens": MAX_NEW_TOKENS,
        "temperature": GRID_TEMP,
        "max_retries": MAX_RETRIES,
        "technique_header_included": INCLUDE_TECHNIQUE_HEADER,
        "runs": [],
    }

    try:
        if not wait_for_vllm_ready(vllm_process, timeout=600):
            log("ERROR: vLLM server failed to start")
            print("ERROR: vLLM server failed to start")
            return

        # ---- A3: chuẩn bị input ----
        report_path = find_report_path()
        procedures = build_procedures(report_path)
        log(f"A3: {len(procedures)} procedure khong rong tu {report_path}")
        map_path = write_procedure_map(procedures)

        method = make_method()

        # ---- A3: chạy gộp (để so sánh với lần chạy cũ) ----
        if RUN_AGGREGATE:
            log("A3: chay GRID gop tat ca procedure")
            agg_text = build_aggregate_text(procedures)
            s = run_one(method, "aggregate", agg_text, GRID_RAW_DIR / "aggregate")
            s["kind"] = "aggregate"
            s["procedure_ids"] = [p["procedure_id"] for p in procedures]
            manifest["runs"].append(s)
            # giữ bản tương thích với out/grid_output/ của lần chạy cũ
            legacy = OUT_DIR / "grid_output"
            legacy.mkdir(exist_ok=True)
            for fname, src in (("raw_output.txt", "raw_output.txt"),
                               ("step1_raw.txt", "step1_raw.txt"),
                               ("step2_raw.txt", "step2_raw.txt"),
                               ("entities.json", "entities.json"),
                               ("relations.json", "relation.json")):
                (legacy / fname).write_text(
                    (GRID_RAW_DIR / "aggregate" / src).read_text(encoding="utf-8"),
                    encoding="utf-8")

        # ---- A3: chạy riêng từng procedure ----
        if RUN_PER_PROCEDURE:
            log(f"A3: chay GRID rieng cho tung procedure ({len(procedures)} procedure)")
            for p in procedures:
                text = build_input_text(p)
                name = f"{p['procedure_id']}_{p['technique_id'] or 'NA'}"
                s = run_one(method, name, text, GRID_RAW_DIR / name)
                s["kind"] = "procedure"
                s["procedure_id"] = p["procedure_id"]
                s["technique_id"] = p["technique_id"]
                s["technique_name"] = p["technique_name"]
                s["chunk"] = p["chunk"]
                manifest["runs"].append(s)

        # ---- A4: cập nhật procedure_map.json với grid_dir ----
        pm = json.loads(map_path.read_text(encoding="utf-8"))
        by_label = {r["label"]: r for r in manifest["runs"]}
        for item in pm["procedures"]:
            s = by_label.get(item["procedure_id"])
            if s:
                item["grid_dir"] = s["dir"]
                item["entities"] = s["entities"]
                item["relations"] = s["relations"]
        map_path.write_text(json.dumps(pm, ensure_ascii=False, indent=2), encoding="utf-8")

        manifest["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        manifest["totals"] = {
            "runs": len(manifest["runs"]),
            "entities": sum(r["entities"] for r in manifest["runs"]),
            "relations": sum(r["relations"] for r in manifest["runs"]),
            "empty_runs": [r["label"] for r in manifest["runs"]
                           if not r["entities"] and not r["relations"]],
        }
        (GRID_RAW_DIR / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"A4: manifest -> {GRID_RAW_DIR / 'manifest.json'}")

        # ---- A1: chẩn đoán lại SAU khi chạy (jsonl đã có dữ liệu) ----
        run_diagnosis({"stage": "sau khi chạy xong",
                       "empty_runs": manifest["totals"]["empty_runs"]})
        log(f"A1: chay chuan doan som truoc khi goi model -> {early}")

        print("=" * 60)
        print("Pipeline completed!")
        print(f"Kết quả: {GRID_RAW_DIR}")
        print(f"Chẩn đoán: {GRID_RAW_DIR / 'diagnosis.md'}")
        print("=" * 60)
        log("DONE")

    finally:
        print("Stopping vLLM server...")
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(vllm_process.pid), signal.SIGTERM)
            else:
                vllm_process.terminate()
            vllm_process.wait()
        except (ProcessLookupError, OSError):
            print("vLLM process already stopped.")
        print("vLLM server stopped.")


if __name__ == "__main__":
    main()
