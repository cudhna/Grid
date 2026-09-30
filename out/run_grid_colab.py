"""
Run GRID pipeline on Google Colab with local vLLM.
This script:
1. Installs dependencies
2. Downloads model from HuggingFace
3. Starts vLLM server
4. Runs GRID_Ours with vLLM backend
5. Saves results

Usage on Colab:
    !git clone https://github.com/your-repo/ProjectGRID.git
    %cd ProjectGRID
    !python out/run_grid_colab.py
"""

import os
import sys
import json
import re
import time
import subprocess
import signal
from pathlib import Path

# Configuration
MODEL_NAME = "Qwen/Qwen3-4B-Instruct-2507"  # or "anonymousauthorname/ProjectGRID/task_bank_reward"
USE_BASE_MODEL = True  # Set to False to use task_bank_reward
VLLM_PORT = 8000
VLLM_HOST = "0.0.0.0"

# T4 chỉ có 16GB: model bf16 chiếm ~8GB, còn ~4GB cho KV cache.
# 32768 token cần 4.5GB KV → không đủ ("EngineCore failed to start").
# Input của GRID rất nhỏ (~9KB ≈ 2.5K token) nên 16384 là rất dư.
MAX_MODEL_LEN = 16384
GPU_MEMORY_UTILIZATION = 0.92

# Add out directory to path for tools.py
OUT_DIR = Path(__file__).parent
sys.path.insert(0, str(OUT_DIR))

# Add src/grid to path
REPO_ROOT = OUT_DIR.parent
sys.path.insert(0, str(REPO_ROOT / "src" / "grid"))

# tools.py mặc định được nạp từ ~/Dropbox (không tồn tại trên Colab)
# → trỏ sang bản mock trong out/
os.environ.setdefault("GRID_TOOLS_FILE", str(OUT_DIR / "tools.py"))


def install_dependencies():
    """Install required packages."""
    print("=" * 60)
    print("Step 1: Installing dependencies...")
    print("=" * 60)
    
    packages = [
        "openai>=1.30.0",
        "pandas>=2.0.0",
        "pyarrow>=14.0.0",
        # Colab dùng Python 3.13 → cần vLLM >= 0.11. Pin 0.11.0: hỗ trợ
        # Python 3.13 + sm_75 (T4) + torch 2.8/cu128, chạy ổn định trên Colab free.
        # (0.8.x-0.10.x không cài được trên Python 3.13; 0.30.x dùng torch 2.13/cu130
        #  không chạy được trên T4)
        "vllm==0.11.0",
        # transformers 5.x đã bỏ `all_special_tokens_extended` mà vLLM 0.11.0
        # dùng → AttributeError lúc khởi động. Giới hạn <5 (>=4.55.2 theo yêu cầu vLLM).
        "transformers>=4.55.2,<5.0.0",
        "accelerate>=0.34.0",
        "safetensors>=0.4.3",
    ]
    
    for pkg in packages:
        print(f"Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])
    
    print("Dependencies installed!")


def download_model():
    """Download model from HuggingFace."""
    print("=" * 60)
    print("Step 2: Downloading model...")
    print("=" * 60)
    
    from huggingface_hub import snapshot_download
    
    if USE_BASE_MODEL:
        model_id = "Qwen/Qwen3-4B-Instruct-2507"
    else:
        model_id = "anonymousauthorname/ProjectGRID/task_bank_reward"
    
    print(f"Downloading {model_id}...")
    local_path = snapshot_download(repo_id=model_id)
    print(f"Model downloaded to: {local_path}")
    return local_path


def start_vllm_server(model_path: str):
    """Start vLLM server in background."""
    print("=" * 60)
    print("Step 3: Starting vLLM server...")
    print("=" * 60)
    
    cmd = [
        "vllm", "serve", model_path,
        "--host", VLLM_HOST,
        "--port", str(VLLM_PORT),
        "--trust-remote-code",
        "--dtype", "auto",
        "--max-model-len", str(MAX_MODEL_LEN),
        "--gpu-memory-utilization", str(GPU_MEMORY_UTILIZATION),
    ]
    
    print(f"Starting vLLM: {' '.join(cmd)}")
    
    # Start in background
    log_file = open(OUT_DIR / "vllm_server.log", "w")
    process = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid if os.name != "nt" else None
    )
    
    print(f"vLLM server started (PID: {process.pid})")
    print(f"Logs: {OUT_DIR / 'vllm_server.log'}")
    
    return process


def print_log_tail(lines: int = 20):
    """In log vLLM: quanh lỗi gốc (root cause) + phần cuối file."""
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

    # Lỗi gốc nằm TRƯỚC traceback cuối của API server, nên tìm dòng lỗi đầu tiên
    fatal = re.compile(
        r"(fatal error|Error:|ValueError|RuntimeError|AssertionError|"
        r"NotImplementedError|ImportError|ModuleNotFoundError|KeyError|"
        r"TypeError|OSError|out of memory|no kernel image|"
        r"EngineCore.*(failed|error))",
        re.IGNORECASE,
    )
    # Bỏ qua dòng nằm trong traceback của chính API server
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
    """Kiểm tra GPU (trên Colab: Runtime -> Change runtime type -> GPU)."""
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
            print("On Colab, enable GPU first: Runtime -> Change runtime type -> Hardware accelerator -> GPU")
    except Exception:
        subprocess.call(["nvidia-smi"])


def wait_for_vllm_ready(process, timeout: int = 600):
    """Wait for vLLM server to be ready."""
    print("=" * 60)
    print("Step 4: Waiting for vLLM server...")
    print("=" * 60)

    import requests

    start_time = time.time()
    while time.time() - start_time < timeout:
        # Process đã chết sớm → dừng ngay và in log thay vì chờ hết timeout
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

        elapsed = time.time() - start_time
        print(f"Waiting... ({elapsed:.0f}s)")
        time.sleep(5)

    print(f"Timeout after {timeout}s")
    print_log_tail()
    return False


def prepare_input_text(report_path: str) -> str:
    """Prepare input text from report_1.json."""
    print("=" * 60)
    print("Step 5: Preparing input text...")
    print("=" * 60)
    
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    
    # Extract non-empty procedures
    procedures = []
    for chunk_idx, chunk in enumerate(report):
        if not chunk:
            continue
        for tactic in chunk:
            for tech in tactic.get("techniques", []):
                proc = tech.get("procedure", "").strip()
                if proc:
                    procedures.append({
                        "chunk": chunk_idx,
                        "tactic": tactic.get("name", ""),
                        "technique_id": tech.get("id", ""),
                        "technique_name": tech.get("name", ""),
                        "procedure": proc
                    })
    
    print(f"Found {len(procedures)} non-empty procedures")
    
    # Build input text
    text_parts = []
    for p in procedures:
        text_parts.append(
            f"[Chunk {p['chunk']}] {p['tactic']} - {p['technique_id']} {p['technique_name']}\n"
            f"Procedure: {p['procedure']}"
        )
    
    input_text = "\n\n".join(text_parts)
    
    # Save input text
    input_path = OUT_DIR / "input_text.txt"
    with open(input_path, "w", encoding="utf-8") as f:
        f.write(input_text)
    
    print(f"Input text saved to: {input_path}")
    print(f"Input length: {len(input_text)} chars")
    
    return input_text


def run_grid(input_text: str):
    """Run GRID_Ours with vLLM backend."""
    print("=" * 60)
    print("Step 6: Running GRID_Ours...")
    print("=" * 60)
    
    # Set environment variables for tools.py
    os.environ["VLLM_URL"] = f"http://localhost:{VLLM_PORT}/v1"
    os.environ["VLLM_API_KEY"] = "EMPTY"
    os.environ["VLLM_MODEL_NAME"] = MODEL_NAME.split("/")[-1]
    
    # Import GRID
    from GRID_Ours import GRIDOursMethod
    
    # Initialize method
    method = GRIDOursMethod(
        llm_backend="dedicated_vllm",
        model="local",
        model_path=MODEL_NAME,
        token=64 * 1024,
        temp=0.7,
        think=2,
        check_cache=False,
    )
    
    # Run generation
    print("Running GRID (this may take a while)...")
    result = method.generate(input_text)
    
    return result


def save_results(result: dict):
    """Save results to output files."""
    print("=" * 60)
    print("Step 7: Saving results...")
    print("=" * 60)
    
    output_dir = OUT_DIR / "grid_output"
    output_dir.mkdir(exist_ok=True)
    
    # Save raw output
    raw_path = output_dir / "raw_output.txt"
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(result.get("raw_output", ""))
    print(f"Raw output saved to: {raw_path}")
    
    # Save entities
    entities_path = output_dir / "entities.json"
    with open(entities_path, "w", encoding="utf-8") as f:
        json.dump(result.get("entities", []), f, ensure_ascii=False, indent=2)
    print(f"Entities saved to: {entities_path}")
    
    # Save relations
    relations_path = output_dir / "relations.json"
    with open(relations_path, "w", encoding="utf-8") as f:
        json.dump(result.get("relations", []), f, ensure_ascii=False, indent=2)
    print(f"Relations saved to: {relations_path}")
    
    # Save step1 raw output
    step1_path = output_dir / "step1_raw.txt"
    with open(step1_path, "w", encoding="utf-8") as f:
        f.write(result.get("step1_raw_output", ""))
    print(f"Step1 raw output saved to: {step1_path}")
    
    # Save step2 raw output
    step2_path = output_dir / "step2_raw.txt"
    with open(step2_path, "w", encoding="utf-8") as f:
        f.write(result.get("step2_raw_output", ""))
    print(f"Step2 raw output saved to: {step2_path}")
    
    return output_dir


def main():
    """Main pipeline."""
    print("=" * 60)
    print("GRID Pipeline on Google Colab")
    print("=" * 60)
    
    # Step 0: Check GPU
    check_gpu()

    # Step 1: Install dependencies
    install_dependencies()
    
    # Step 2: Download model
    model_path = download_model()
    
    # Step 3: Start vLLM server
    vllm_process = start_vllm_server(model_path)
    
    try:
        # Step 4: Wait for vLLM ready
        if not wait_for_vllm_ready(vllm_process, timeout=600):
            print("ERROR: vLLM server failed to start")
            return
        
        # Step 5: Prepare input text
        report_path = REPO_ROOT / "report_1.json"
        input_text = prepare_input_text(str(report_path))
        
        # Step 6: Run GRID
        result = run_grid(input_text)
        
        # Step 7: Save results
        output_dir = save_results(result)
        
        print("=" * 60)
        print("Pipeline completed successfully!")
        print(f"Results saved to: {output_dir}")
        print("=" * 60)
        
    finally:
        # Cleanup
        print("Stopping vLLM server...")
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(vllm_process.pid), signal.SIGTERM)
            else:
                vllm_process.terminate()
            vllm_process.wait()
        except (ProcessLookupError, OSError):
            # Server đã tự chết trước đó
            print("vLLM process already stopped.")
        print("vLLM server stopped.")


if __name__ == "__main__":
    main()
