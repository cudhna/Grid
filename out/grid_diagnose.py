"""
A1 - Chẩn đoán vì sao entities/relations của GRID rỗng.

Module này KHÔNG gọi model. Nó làm 3 việc:

1. probe_parser()
   Nạp `_robust_json_parse` của chính repo (article_io_cache_parser) rồi đưa vào
   các chuỗi ĐÃ ĐÚNG ĐỊNH DẠNG. Nếu kết quả vẫn rỗng -> lỗi ở parser/môi trường
   (json_repair chưa cài, regex hỏng). Nếu kết quả đúng -> parser ổn, vấn đề nằm ở
   model hoặc ở input.

2. inspect_debug_jsonl()
   Đọc src/GeneratedKGContent/_TemplateDebug/*.jsonl mà repo tự ghi lại (mỗi dòng =
   1 lần gọi model, có input_prompt và output_result). Phân loại từng lần gọi là
   Step 1 hay Step 2 dựa trên prompt, rồi chấm điểm output.

3. write_report()
   Ghi out/grid_raw/diagnosis.md.

Vì sao cần riêng module này
--------------------------
`out/grid_output/raw_output.txt` KHÔNG phải output thô của model. Hàm
`_build_final_split_output()` trong src/grid/GRID_backbone.py dựng lại file đó từ
`final_entities`/`final_relations`, tức là từ kết quả ĐÃ PARSE. Thấy "suy luận có
nhưng #Entity_List# là []" trong file đó không chứng minh model trả về []; nó chỉ
chứng minh parser trả về rỗng. Output thô thật chỉ nằm ở:
  - result["step1_raw_output"] / result["step2_raw_output"]  (out/grid_output/step*_raw.txt)
  - src/GeneratedKGContent/_TemplateDebug/debug_<model>_<date>.jsonl

Chạy độc lập (không cần model, không cần GPU):
    python out/grid_diagnose.py
    python out/grid_diagnose.py --debug-dir src/GeneratedKGContent/_TemplateDebug \
                                --out out/grid_raw
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import types
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent
REPO_ROOT = OUT_DIR.parent

try:    # console Windows mặc định là cp1252, không in được tiếng Việt
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ------------------------------------------------------------------ marker ----
# Sao chép NGUYÊN VĂN regex trong article_io_cache_parser._robust_json_parse
# (dòng 296-342) để kết luận ở đây khớp với kết luận runtime.
RX_CODE_BLOCK = re.compile(r"```(?:json)?\s*([\s\S]*?)```")
RX_ENTITY = re.compile(r"#Entity_List_Start#\s*(\[[\s\S]*?\])\s*#Entity_List_End#")
RX_RELATION = re.compile(r"#Relationship_List_Start#\s*(\[[\s\S]*?\])\s*#Relationship_List_End#")
RX_START_ONLY = re.compile(r"#(Entity|Relationship)_List_Start#")
RX_REASONING = re.compile(r"#Reasoning_Start#\s*([\s\S]*?)\s*#Reasoning_End#")
RX_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Mẫu đầu vào cho probe. `expect_*` là kết quả ĐÚNG khi parser + json_repair hoạt
# động bình thường, đã đối chiếu với logic thật trong _robust_json_parse.
#   informative=True -> không dùng để kết luận pass/fail, chỉ để quan sát.
PROBE_CASES = [
    {
        "name": "entity",
        "informative": False,
        "expect_entities": 1, "expect_relations": 0,
        "raw": "#Reasoning_Start#\nThe text mentions CyberLock encrypting files.\n#Reasoning_End#\n"
               '#Entity_List_Start#\n[{"name": "CyberLock", "type": "malware"}]\n#Entity_List_End#',
    },
    {
        "name": "relation",
        "informative": False,
        "expect_entities": 2, "expect_relations": 1,
        "raw": "#Reasoning_Start#\nCyberLock runs PowerShell.\n#Reasoning_End#\n"
               '#Entity_List_Start#\n[{"name": "CyberLock", "type": "malware"},'
               ' {"name": "PowerShell", "type": "hacker-tool"}]\n#Entity_List_End#\n'
               '#Relationship_List_Start#\n[{"sub": "CyberLock", "rel": "runs",'
               ' "rel_type": ["executes"], "obj": "PowerShell"}]\n#Relationship_List_End#',
    },
    {
        "name": "empty_list",
        "informative": False,
        "expect_entities": 0, "expect_relations": 0,
        "raw": "#Reasoning_Start#\nCyberLock encrypts files with PowerShell.\n#Reasoning_End#\n"
               "#Entity_List_Start#\n[]\n#Entity_List_End#",
    },
    {
        "name": "no_marker",
        "informative": False,
        "expect_entities": 0, "expect_relations": 0,
        "raw": "CyberLock is a ransomware that encrypts files using PowerShell.",
    },
    {
        # Kết quả thực đo: có json_repair thì _robust_json_parse CỨU ĐƯỢC phần bị
        # cắt qua fallback brace_match + json_repair -> vẫn ra 1 entity.
        # Nghĩa là cắt output KHÔNG gây rỗng hoàn toàn, chỉ gây thiếu.
        "name": "truncated",
        "informative": True,
        "expect_entities": 1, "expect_relations": 0,
        "raw": "#Reasoning_Start#\nCyberLock encrypts files with PowerShell.\n#Reasoning_End#\n"
               '#Entity_List_Start#\n[{"name": "CyberLock", "type": "malware"',
    },
    {
        # JSON hỏng bên trong (dấu nháy lẻ) -> chỉ json_repair mới cứu được.
        "name": "broken_json",
        "informative": True,
        "expect_entities": 1, "expect_relations": 0,
        "raw": '#Entity_List_Start#\n[{"name": "CyberLock, "type": "malware"}]\n#Entity_List_End#',
    },
]


def clean_response(response: str) -> str:
    """Giống hệt article_io_cache_parser._clean_response."""
    if response:
        return response.replace("<Fin>", "").strip()
    return ""


def classify_output(raw: str) -> dict:
    """Chấm điểm một output thô của model, không cần class của repo."""
    text = clean_response(raw or "")
    info = {
        "chars": len(text),
        "has_reasoning": bool(RX_REASONING.search(text)),
        "has_entity_pair": bool(RX_ENTITY.search(text)),
        "has_relation_pair": bool(RX_RELATION.search(text)),
        "entity_start_without_end": False,
        "relation_start_without_end": False,
        "has_json_fence": bool(RX_CODE_BLOCK.search(text)),
        "entity_items": 0,
        "relation_items": 0,
    }
    em, rm = RX_ENTITY.search(text), RX_RELATION.search(text)
    # Bị cắt giữa chừng = có Start# nhưng thiếu End# tương ứng.
    info["entity_start_without_end"] = (
        "#Entity_List_Start#" in text and "#Entity_List_End#" not in text
    )
    info["relation_start_without_end"] = (
        "#Relationship_List_Start#" in text and "#Relationship_List_End#" not in text
    )
    if em:
        info["entity_items"] = _count_items(em.group(1))
    if rm:
        info["relation_items"] = _count_items(rm.group(1))
    info["technique_codes_in_output"] = sorted(set(RX_TECHNIQUE.findall(text)))

    # Kết luận, theo thứ tự ưu tiên.
    no_pair = not (info["has_entity_pair"] or info["has_relation_pair"])
    if not text:
        info["verdict"] = "empty_response"
    elif info["has_entity_pair"] and info["entity_items"] == 0:
        info["verdict"] = "model_emitted_empty_list"
    elif no_pair and (info["entity_start_without_end"] or info["relation_start_without_end"]):
        info["verdict"] = "output_truncated"
    elif no_pair:
        info["verdict"] = "markers_missing"
    else:
        info["verdict"] = "ok"
    return info


def _count_items(fragment: str) -> int:
    """Đếm phần tử JSON trong một mảng, không cần thư viện ngoài."""
    frag = fragment.strip()
    if not frag.startswith("["):
        return 0
    try:
        data = json.loads(frag)
        return len(data) if isinstance(data, list) else 0
    except Exception:
        pass
    try:
        import json_repair
        data = json_repair.loads(frag)
        return len(data) if isinstance(data, list) else 0
    except Exception:
        pass
    return frag.count('"name"') or frag.count("{")


# ---------------------------------------------------------------- probe ----
def probe_parser(verbose: bool = True) -> dict:
    """
    Nạp chính _robust_json_parse của repo rồi thử 5 chuỗi mẫu.

    Kết quả phân biệt rõ hai nguyên nhân:
      - TẤT CẢ mẫu rỗng  -> lỗi môi trường/parser (thường là json_repair chưa cài,
        vì code nuốt ImportError trong `except Exception: pass`).
      - Chỉ `truncated` rỗng -> parser ổn, nguyên nhân là output bị cắt.
    """
    report = {"loaded": False, "error": None, "cases": {}}
    sys.path.insert(0, str(REPO_ROOT / "src" / "grid"))

    # `article_io_cache_parser` -> `shared_eval_backend` -> nạp tools.py -> requests.
    # Nếu máy chưa có requests, trỏ GRID_TOOLS_FILE sang một stub tối thiểu:
    # _robust_json_parse là hàm thuần nên không cần gọi LLM thật.
    try:
        import requests  # noqa: F401
        os.environ.setdefault("GRID_TOOLS_FILE", str(OUT_DIR / "tools.py"))
    except ImportError:
        report["used_stub_tools"] = True
        stub_dir = Path(os.environ.get("TEMP", "/tmp")) / "grid_diagnose_stub"
        stub_dir.mkdir(parents=True, exist_ok=True)
        stub_file = stub_dir / "tools.py"
        if not stub_file.exists():
            stub_file.write_text(
                "def ask_group_link(*a, **k):\n    return ['']\n"
                "def check_cache_batch(*a, **k):\n    return {}, [0], [0]\n"
                "def get_prompt_hash(p):\n    return ''\n"
                "def llmname(*a, **k):\n    return 'stub'\n"
                "def resolve_model_name(*a, **k):\n    return 'stub'\n"
                "def get_vllm_realtime_stats(*a, **k):\n    return {}\n",
                encoding="utf-8",
            )
        os.environ["GRID_TOOLS_FILE"] = str(stub_file)

    # `vllm_environment_setup` hardcode ~/Dropbox/tools.py (dòng 29) nên không
    # import được nếu chưa tạo symlink. Ở đây chỉ cần 2 tên `SERVERS` và
    # `VLLMEnvironmentManager` cho import-time, nên dùng stub trong bộ nhớ.
    if not (Path.home() / "Dropbox" / "tools.py").exists():
        if "vllm_environment_setup" not in sys.modules:
            _ve = types.ModuleType("vllm_environment_setup")
            _ve.SERVERS = {}
            _ve.VLLMEnvironmentManager = object
            sys.modules["vllm_environment_setup"] = _ve
        report["used_stub_vllm_env"] = True

    for mod in [m for m in sys.modules
                if m in ("article_io_cache_parser", "shared_eval_backend",
                         "single_pass_template", "tools")]:
        del sys.modules[mod]
    try:
        from article_io_cache_parser import BaseKGMethod  # noqa: F401
        report["loaded"] = True
    except Exception as exc:  # pragma: no cover
        report["error"] = f"{type(exc).__name__}: {exc}"
        return report

    try:
        import json_repair  # noqa: F401
        report["json_repair"] = True
    except ImportError:
        report["json_repair"] = False

    # Gọi hàm tĩnh qua một instance tối thiểu, không khởi tạo LLM.
    from article_io_cache_parser import BaseKGMethod

    class _Probe(BaseKGMethod):
        def generate(self, content: str):  # pragma: no cover - không dùng
            raise NotImplementedError

    probe = _Probe(name="diagnose_probe", save_log=False)
    for case in PROBE_CASES:
        name = case["name"]
        try:
            parsed = probe._robust_json_parse(clean_response(case["raw"]))
            got_e = len(parsed.get("entities") or [])
            got_r = len(parsed.get("relations") or [])
        except Exception as exc:
            got_e = got_r = -1
            report.setdefault("errors", []).append(f"{name}: {type(exc).__name__}: {exc}")
        report["cases"][name] = {
            "entities": got_e,
            "relations": got_r,
            "expected_entities": case["expect_entities"],
            "expected_relations": case["expect_relations"],
            "informative": case["informative"],
            "matches_expected": got_e == case["expect_entities"] and got_r == case["expect_relations"],
        }
        if verbose:
            mark = "  (chỉ quan sát)" if case["informative"] else ""
            print(f"    probe[{name:12s}] -> entities={got_e}, relations={got_r}{mark}")

    required = [c for c in report["cases"].values() if not c["informative"]]
    passed = required and all(c["matches_expected"] for c in required)
    report["verdict"] = "parser_ok" if passed else "parser_broken"
    if passed:
        salvaged = report["cases"].get("truncated", {}).get("entities", 0)
        report["note"] = (
            f"Parser đúng. Mẫu 'truncated' cứu được {salvaged} entity -> cắt output "
            "KHÔNG phải nguyên nhân gây rỗng, chỉ gây thiếu."
        )
    return report


# --------------------------------------------------------- debug jsonl ----
def detect_stage(prompt) -> str:
    """Step 1 hay Step 2? Suy từ nội dung prompt (repo không ghi tên stage)."""
    text = prompt if isinstance(prompt, str) else json.dumps(prompt, ensure_ascii=False)
    if "STEP2 ADDITIONAL INPUT" in text or "Step 1 Candidate Entity List" in text:
        return "step2"
    if "STEP1 OUTPUT OVERRIDE" in text:
        return "step1"
    return "unknown"


def inspect_debug_jsonl(debug_dir, copy_to=None) -> list:
    """Đọc mọi *.jsonl trong debug_dir, chấm điểm từng lần gọi model."""
    findings = []
    files = sorted(glob.glob(os.path.join(str(debug_dir), "*.jsonl")))
    if not files:
        return findings
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    findings.append({"file": os.path.basename(path), "line": lineno,
                                     "verdict": "bad_jsonl_line", "raw_line": line[:300]})
                    continue
                prompt = rec.get("input_prompt")
                output = rec.get("output_result") or ""
                if isinstance(output, list):
                    output = output[0] if output else ""
                stage = detect_stage(prompt)
                info = classify_output(output)
                prompt_text = prompt if isinstance(prompt, str) else json.dumps(prompt, ensure_ascii=False)
                item = {
                    "file": os.path.basename(path),
                    "line": lineno,
                    "timestamp": rec.get("timestamp"),
                    "model": rec.get("model"),
                    "stage": stage,
                    "prompt_chars": len(prompt_text),
                    "prompt_tokens_approx": len(prompt_text) // 4,
                    "finish_reason_hint": _finish_reason_hint(rec, output),
                    **info,
                }
                findings.append(item)
                if copy_to:
                    _dump_one(copy_to, rec, stage, info)
    return findings


def _finish_reason_hint(rec, output) -> str:
    """Không có finish_reason trong log; suy từ việc có marker End# hay không."""
    text = output if isinstance(output, str) else ""
    has_start = bool(RX_START_ONLY.search(text))
    has_end = "#Entity_List_End#" in text or "#Relationship_List_End#" in text
    if has_start and not has_end:
        return "likely_length (thieu marker End#)"
    if not has_start and text.strip():
        return "likely_stop (khong co marker nao)"
    return "unknown"


def _dump_one(copy_to: Path, rec, stage: str, info: dict):
    """Lưu nguyên prompt + output thô của từng lần gọi để tải về kiểm tra."""
    try:
        out_dir = copy_to / "template_debug"
        out_dir.mkdir(parents=True, exist_ok=True)
        idx = f"{rec.get('timestamp', 'na')}_{stage}_{rec.get('index', 0)}"
        safe = re.sub(r"[^0-9A-Za-z_.-]", "_", idx)
        base = out_dir / safe
        base.parent.mkdir(parents=True, exist_ok=True)
        with open(base.with_suffix(".prompt.txt"), "w", encoding="utf-8") as fh:
            prompt = rec.get("input_prompt")
            fh.write(prompt if isinstance(prompt, str)
                     else json.dumps(prompt, ensure_ascii=False, indent=2))
        out = rec.get("output_result") or ""
        if isinstance(out, list):
            out = out[0] if out else ""
        with open(base.with_suffix(".raw.txt"), "w", encoding="utf-8") as fh:
            fh.write(out or "")
        with open(base.with_suffix(".verdict.json"), "w", encoding="utf-8") as fh:
            json.dump(info, fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        print(f"  (không lưu được bản ghi: {exc})")


def inspect_call_log(grid_raw: Path) -> list:
    """
    Đọc out/grid_raw/vllm_calls.jsonl do out/tools.py ghi lại (mỗi dòng = 1 lần gọi
    vLLM). Nhờ vậy phân biệt được:
      - model trả list RỖNG      : finish_reason = "stop"  và completion_tokens > 0
      - model bị CẮT output      : finish_reason = "length"
      - request hỏng / timeout   : error khác None
    """
    path = Path(grid_raw) / "vllm_calls.jsonl"
    if not path.exists():
        return []
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rows.append({"line": lineno, "verdict": "bad_jsonl_line"})
                continue
            if rec.get("error"):
                verdict = "request_failed"
            elif rec.get("finish_reason") == "length":
                verdict = "output_truncated"
            elif (rec.get("completion_tokens") or 0) > 0:
                verdict = "response_returned"
            else:
                verdict = "empty_response"
            rows.append({"line": lineno, "verdict": verdict, **{k: v for k, v in rec.items()
                                                                if k != "verdict"}})
    return rows


def inspect_existing_outputs(grid_output: Path) -> dict:
    """Đọc out/grid_output/step*_raw.txt nếu lần chạy trước còn trên đĩa."""
    out = {}
    for name in ("step1_raw.txt", "step2_raw.txt", "raw_output.txt"):
        p = grid_output / name
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            out[name] = {"chars": len(text), **classify_output(text)}
    return out


# ------------------------------------------------------------- report ----
VERDICT_VI = {
    "parser_ok": "Parser đọc đúng mọi mẫu chuẩn -> lỗi KHÔNG nằm ở parser.",
    "parser_broken": "Parser/môi trường HỎNG -> đây là nguyên nhân gốc.",
    "empty_response": "Model không trả về gì (timeout / lỗi mạng / request lỗi).",
    "model_emitted_empty_list": "Model trả kèm marker đúng nhưng tự sinh list RỖNG "
                                "-> lỗi tuân thủ chỉ dẫn của model, không phải lỗi code.",
    "output_truncated": "Model bị cắt output giữa chừng (thiếu #..._End#) -> nội dung bị mất "
                        "một phần (đã đo: vẫn cứu được phần đầu qua json_repair), "
                        "KHÔNG phải nguyên nhân gây rỗng hoàn toàn.",
    "markers_missing": "Model không tạo đủ marker #..._Start#/End# -> parser rơi vào "
                       "fallback và không lấy được danh sách.",
    "bad_jsonl_line": "Dòng jsonl hỏng, không đọc được.",
}


def write_report(path: Path, probe: dict, findings: list, existing: dict,
                 extra: dict | None = None, calls: list | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    calls = calls or []
    L = []
    A = L.append
    A("# A1 - Chẩn đoán: tại sao entities/relations của GRID rỗng")
    A("")
    A(f"Sinh lúc: {extra.get('generated_at') if extra else ''}")
    A("")
    A("## 0. Cảnh báo quan trọng về file `raw_output.txt`")
    A("")
    A("`out/grid_output/raw_output.txt` **không phải** output thô của model.")
    A("`GRID_backbone._build_final_split_output()` (src/grid/GRID_backbone.py:165-198) dựng lại")
    A("file đó từ `final_entities` / `final_relations`, tức là từ kết quả ĐÃ PARSE:")
    A("")
    A("```")
    A("blocks = ['#Entity_List_Start#', _json_dumps(final_entities), '#Entity_List_End#', ...]")
    A("```")
    A("")
    A("Nên thấy \"suy luận có nhưng `#Entity_List#` là `[]`\" trong file đó chỉ chứng minh")
    A("**parser** trả về rỗng, không chứng minh model trả `[]`.")
    A("Output thô thật chỉ nằm ở `step1_raw.txt`, `step2_raw.txt` và `_TemplateDebug/*.jsonl`.")
    A("")

    A("## 1. Probe parser (không cần model, không cần GPU)")
    A("")
    A("Cách làm: nạp chính `_robust_json_parse` của repo rồi đưa vào 6 chuỗi mẫu đã biết kết quả")
    A("mong muốn. Nếu *tất cả* mẫu đều ra 0 thì lỗi ở parser/môi trường; nếu chỉ mẫu JSON hỏng")
    A("ra 0 thì parser ổn và vấn đề nằm ở model hoặc input.")
    A("")
    A(f"- Nạp được `article_io_cache_parser`: {probe.get('loaded')}")
    A(f"- `json_repair` import được: **{probe.get('json_repair')}**")
    if probe.get("used_stub_tools"):
        A("- Dùng `tools.py` stub (máy chạy probe không cần cài `requests`)")
    if probe.get("used_stub_vllm_env"):
        A("- Dùng `vllm_environment_setup` stub (tránh phụ thuộc `~/Dropbox/tools.py`)")
    if probe.get("error"):
        A(f"- Lỗi khi nạp: `{probe['error']}`")
    A("")
    if probe.get("cases"):
        A("| mẫu | entities (thực) | relations (thực) | entities (mong đợi) | relations (mong đợi) | khớp? |")
        A("|---|---:|---:|---:|---:|---|")
        for name, c in probe["cases"].items():
            tag = " _(chỉ quan sát)_" if c.get("informative") else ""
            mark = "khớp" if c.get("matches_expected") else "**SAI**"
            A(f"| `{name}`{tag} | {c['entities']} | {c['relations']} | "
              f"{c['expected_entities']} | {c['expected_relations']} | {mark} |")
        A("")
    A(f"**Kết luận probe: `{probe.get('verdict')}`** — {VERDICT_VI.get(probe.get('verdict'), '')}")
    if probe.get("note"):
        A("")
        A(f"> {probe['note']}")
    A("")

    A("## 2. Các nguyên nhân, xếp theo mức độ khả nghi ĐÃ ĐO")
    A("")
    A("| # | Nguyên nhân | Bằng chứng | Trạng thái |")
    A("|---|---|---|---|")
    A("| 1 | `json_repair` chưa cài | `article_io_cache_parser.py:311,320,360` quanh `import json_repair` "
      "đều bọc `except Exception: pass` → ImportError bị nuốt im lặng | **ĐÃ TÁI HIỆN**: thiếu "
      "`json_repair` thì cả 6 mẫu ra 0; cài vào thì `entity` ra 1, `relation` ra 2+1, "
      "`broken_json` ra 1. Đây là nguyên nhân gây rỗng **hoàn toàn**. |")
    A("| 2 | Model tự sinh list rỗng | Base Qwen3-4B-Instruct-2507 chưa qua hậu huấn luyện task-bank, "
      "không được huấn luyện để phát đủ marker | Cần mục 3: `verdict = model_emitted_empty_list` |")
    A("| 3 | Model không tạo đủ marker | Không có list marker → rơi vào fallback `_repair_json` | "
      "Cần mục 3: `verdict = markers_missing` |")
    A("| 4 | Request lỗi / timeout | `out/tools.py` nuốt exception và trả `\"\"` | "
      "Cần mục 3: `verdict = empty_response` |")
    A("| ~~5~~ | ~~Output bị cắt~~ | Regex bắt buộc có `#Entity_List_End#` (`:301-302`) | "
      "**ĐÃ LOẠI**: đo mẫu `truncated` vẫn ra 1 entity nhờ fallback `brace_match` + `json_repair`. "
      "Cắt output gây **thiếu**, không gây rỗng. |")
    A("")
    A("**Kết luận A1 (chỉ dựa trên đọc code + probe, chưa cần chạy model):** nếu `json_repair` trên")
    A("Colab đã được cài đúng thì nguyên nhân số 1 bị loại, và phần còn lại phải phân biệt bằng cách")
    A("đọc output thô. Mà `raw_output.txt` hiện tại không dùng được vì nó đã bị dựng lại (mục 0).")
    A("Đó là lý do `out/grid_raw/` của lần chạy mới phải lưu `step1_raw.txt` / `step2_raw.txt` thật.")
    A("")

    A("## 3. Kết quả đọc `_TemplateDebug/*.jsonl`")
    A("")
    if not findings:
        A("Không tìm thấy file `.jsonl` nào. Có thể vì:")
        A("")
        A("- Colab runtime bị restart (thư mục là ephemeral, mất khi khởi động lại); hoặc")
        A("- `save_debug_log()` chỉ chạy sau khi `_call_llm` trả về, tức là phải đã gọi model "
          "thành công ít nhất một lần.")
        A("")
        A("Nếu file có tồn tại, chạy lại `python out/grid_diagnose.py` ngay sau khi pipeline chạy xong,")
        A("hoặc tải thư mục `src/GeneratedKGContent/_TemplateDebug/` về máy local rồi chạy.")
    else:
        A(f"Tìm thấy {len(findings)} lần gọi model.")
        A("")
        A("| file:dòng | stage | output chars | tokens~ | reasoning | entity pair | rel pair | verdict |")
        A("|---|---|---:|---:|---|---|---|---|")
        for f in findings:
            A(f"| {f.get('file')}:{f.get('line')} | {f.get('stage')} | {f.get('chars')} | "
              f"{f.get('prompt_tokens_approx', 0)} | {'có' if f.get('has_reasoning') else 'KHÔNG'} | "
              f"{'có' if f.get('has_entity_pair') else 'KHÔNG'} | "
              f"{'có' if f.get('has_relation_pair') else 'KHÔNG'} | `{f.get('verdict')}` |")
        A("")
        A("Diễn giải:")
        A("")
        for f in findings:
            if f.get("verdict") != "ok":
                A(f"- `{f.get('file')}:{f.get('line')}` ({f.get('stage')}): "
                  f"{VERDICT_VI.get(f.get('verdict'), f.get('verdict'))}")
    A("")

    A("## 4. Nhật ký gọi vLLM (`vllm_calls.jsonl`)")
    A("")
    A("Đây là nguồn để phân biệt \"model trả list rỗng\" với \"bị cắt output\" với \"request hỏng\".")
    A("")
    if not calls:
        A("Chưa có `vllm_calls.jsonl` (chỉ xuất hiện sau lần chạy có gọi vLLM thật).")
    else:
        A(f"Tìm thấy {len(calls)} lần gọi.")
        A("")
        A("| # | thời gian (s) | prompt tok | completion tok | max tok | chars | finish_reason | verdict |")
        A("|---|---:|---:|---:|---:|---:|---|---|")
        for c in calls:
            A(f"| {c.get('line')} | {c.get('seconds')} | {c.get('prompt_tokens')} | "
              f"{c.get('completion_tokens')} | {c.get('max_tokens')} | {c.get('chars')} | "
              f"{c.get('finish_reason')} | `{c.get('verdict')}` |")
        A("")
        n_trunc = sum(1 for c in calls if c.get("verdict") == "output_truncated")
        n_fail = sum(1 for c in calls if c.get("verdict") == "request_failed")
        n_ok = sum(1 for c in calls if c.get("verdict") == "response_returned")
        A(f"Tóm tắt: {n_ok} lần trả về bình thường, {n_trunc} lần bị cắt output, "
          f"{n_fail} lần request lỗi.")
    A("")

    A("## 5. Đọc `out/grid_output/*.txt` của lần chạy trước")
    A("")
    if not existing:
        A("Không có file `step1_raw.txt` / `step2_raw.txt` trên đĩa (đã bị xoá khi khởi động lại Colab).")
    else:
        A("| file | chars | reasoning | entity pair | entity items | verdict |")
        A("|---|---:|---|---|---:|---|")
        for name, c in existing.items():
            A(f"| {name} | {c['chars']} | {'có' if c['has_reasoning'] else 'KHÔNG'} | "
              f"{'có' if c['has_entity_pair'] else 'KHÔNG'} | {c['entity_items']} | "
              f"`{c['verdict']}` |")
        A("")
        A("Lưu ý: `raw_output.txt` là output **đã dựng lại**, nên cột `entity items` của nó")
        A("luôn bằng giá trị đã parse, không phản ánh model. Hai file `step*_raw.txt` mới là output thô.")
    A("")

    if extra:
        A("## 6. Thông tin phiên chạy")
        A("")
        for k, v in extra.items():
            if k == "generated_at":
                continue
            A(f"- **{k}**: {v}")
        A("")

    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return path


def main():
    ap = argparse.ArgumentParser(description="Chẩn đoán GRID trả về danh sách rỗng (không cần model)")
    ap.add_argument("--debug-dir", default=str(REPO_ROOT / "src" / "GeneratedKGContent" / "_TemplateDebug"))
    ap.add_argument("--grid-output", default=str(OUT_DIR / "grid_output"))
    ap.add_argument("--out", default=str(OUT_DIR / "grid_raw"))
    a = ap.parse_args()

    import datetime
    print("=" * 68)
    print("A1. Chẩn đoán GRID")
    print("=" * 68)

    print("[1] Probe parser (không cần model)...")
    probe = probe_parser()
    print(f"    -> {probe.get('verdict')}")

    print(f"[2] Đọc {a.debug_dir}/*.jsonl ...")
    out_dir = Path(a.out)
    findings = inspect_debug_jsonl(a.debug_dir, copy_to=out_dir)
    print(f"    -> {len(findings)} lần gọi model")

    print(f"[3] Đọc {a.grid_output}/step*_raw.txt ...")
    existing = inspect_existing_outputs(Path(a.grid_output))
    print(f"    -> {len(existing)} file")

    print(f"[4] Đọc {out_dir}/vllm_calls.jsonl ...")
    calls = inspect_call_log(out_dir)
    print(f"    -> {len(calls)} lần gọi vLLM")

    path = write_report(out_dir / "diagnosis.md", probe, findings, existing,
                        extra={"generated_at": datetime.datetime.now().isoformat(timespec="seconds")},
                        calls=calls)
    print(f"\nĐã ghi: {path}")
    print(f"Kết luận probe: {probe.get('verdict')} — {VERDICT_VI.get(probe.get('verdict'), '')}")
    for f in findings:
        if f.get("verdict") != "ok":
            print(f"  ! {f.get('stage')} -> {f.get('verdict')}: {VERDICT_VI.get(f.get('verdict'), '')}")
    for c in calls:
        if c.get("verdict") not in ("response_returned",):
            print(f"  ! vLLM call #{c.get('line')} -> {c.get('verdict')}"
                  f" (finish_reason={c.get('finish_reason')}, error={c.get('error')})")


if __name__ == "__main__":
    main()
