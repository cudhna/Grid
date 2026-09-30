# KG 3 tầng: ATT&CK + technique từ báo cáo + triple GRID

Sinh lúc: 2026-09-30T17:14:34

> **Lưu ý về số liệu:** mọi con số dưới đây lấy từ lần chạy thật trên máy này.
> Những phần phụ thuộc kết quả GRID sẽ ghi rõ là **CHƯA CHẠY** nếu `out/grid_raw/`
> chưa có — không có số nào được ước lượng.

## A2. Checkpoint

Kích thước đo từ HuggingFace API (repo `anonymousauthorname/ProjectGRID`):

| checkpoint | kích thước | ghi chú |
|---|---:|---|
| `base_model` | 8.05 GB | Qwen3-4B-Instruct-2507 — **đang dùng** |
| `task_bank_reward` | 8.82 GB | model chính của paper (RQ1: 84.62% precision) |
| `gptoss120b_generator_sft` | 17.65 GB | SFT trên data GPT-OSS-120B |
| `end2end_reward` / `choice_only_reward` / `end2end_sft_without_rl` | 8.82 GB | biến thể ablation |
| `llama31_8b_task_bank_reward` | ~16 GB | **không vừa T4** (16 GB VRAM) |

Thư mục `models/*/` trong repo **chỉ có file link, không có trọng số**.
Quyết định hiện tại: giữ base model, chạy chẩn đoán A1 trước, **không tải thêm**.

## A1. Chẩn đoán GRID trả danh sách rỗng

Probe parser chạy tại đây: **`parser_ok`** — Parser đọc đúng mọi mẫu chuẩn -> lỗi KHÔNG nằm ở parser. (`json_repair` ĐÃ cài. Nếu probe trên Colab báo `parser_broken` thì chính Colab thiếu package này.)

### Phát hiện quan trọng: `raw_output.txt` không phải output thô

`out/grid_output/raw_output.txt` được `GRID_backbone._build_final_split_output()`
(src/grid/GRID_backbone.py:165-198) dựng lại từ `final_entities` / `final_relations`,
tức là từ kết quả **đã parse**:

```
blocks = ['#Entity_List_Start#', _json_dumps(final_entities), '#Entity_List_End#', ...]
```

Thấy `#Entity_List#` là `[]` trong file đó **chỉ chứng minh parser trả rỗng**,
không chứng minh model trả `[]`. Output thô thật nằm ở `step1_raw.txt`,
`step2_raw.txt` và `src/GeneratedKGContent/_TemplateDebug/*.jsonl` — đó là lý do
`out/run_grid_colab.py` lưu riêng 3 nguồn này cho mỗi lần chạy.

### Xếp hạng nguyên nhân (đã đo, không phải phỏng đoán)

| # | nguyên nhân | trạng thái |
|---|---|---|
| 1 | Thiếu `json_repair` | **ĐÃ TÁI HIỆN hoàn toàn.** `article_io_cache_parser.py:311,320,360` bọc `import json_repair` trong `except Exception: pass` → ImportError bị nuốt im lặng. Đo: thiếu package thì cả 6 mẫu chuẩn đều ra 0; cài vào thì `entity`=1, `relation`=2+1, `broken_json`=1. |
| 2 | Model tự sinh list rỗng | Chưa loại — phải đọc `step1_raw.txt` của lần chạy thật. |
| 3 | Model không phát đủ marker | Chưa loại — cùng nguồn kiểm chứng. |
| 4 | Request lỗi / timeout (`out/tools.py` nuốt exception, trả `""`) | Chưa loại — xem `out/grid_raw/vllm_calls.jsonl`. |
| 5 | Output bị cắt do đuôi `max_tokens` | **ĐÃ LOẠI.** Mẫu `truncated` vẫn cứu được 1 entity nhờ fallback `brace_match` + `json_repair`. Cắt output gây **thiếu**, không gây rỗng. |

Prompt không phải nguyên nhân: `ENTITY_TYPES` 542 ký tự + `REL_TYPES` 601, prompt
Step 1 đầy đủ ~9.619 ký tự (~2.671 token), input 7 procedure ~445 token → tổng ~3.1K
token, `MAX_MODEL_LEN = 16384` rất dư. Không chỗ nào cần context dài hơn.

Chi tiết đầy đủ (bảng từng lần gọi model, prompt/output thô) nằm ở
`out/grid_raw/diagnosis.md` do `out/grid_diagnose.py` sinh ra.

## A3/A4. Kết quả chạy GRID trên Colab

**CHƯA CHẠY.** Không có `out/grid_raw/` trên máy này.

Cần chạy trên Colab (có GPU T4):

```bash
!git clone https://github.com/cudhna/Grid.git
%cd Grid
!git pull
!python out/run_grid_colab.py
```

Script sẽ tự sinh `out/grid_raw/` gồm `procedure_map.json`, `manifest.json`,
`run.log`, `vllm_calls.jsonl`, `diagnosis.md` và một thư mục cho mỗi procedure.

Cấu hình A3 đã đặt trong `out/run_grid_colab.py`:

| tham số | giá trị | lý do |
|---|---|---|
| `GRID_TEMP` | `0.0` | yêu cầu temperature 0 |
| `MAX_RETRIES` | `2` | rỗng thì thử lại tối đa 2 lần, ghi log vào `attempts.json` |
| `INCLUDE_TECHNIQUE_HEADER` | `False` | bỏ dòng tiêu đề `[Chunk n] Tactic - Txxxx` |
| `RUN_AGGREGATE` / `RUN_PER_PROCEDURE` | `True` / `True` | chạy cả gộp lẫn từng procedure |

Lưu ý: vì `temperature = 0`, các lần thử lại gần như tất định; khác biệt (nếu có)
đến từ batching không tất định của vLLM chứ không phải từ nhiệt độ. `attempts.json`
ghi rõ điều này.

## B1. Ánh xạ type GRID → STIX/ATT&CK

Nguồn: `src/grid/GRID_backbone.py (ENTITY_TYPES, REL_TYPES)` — **33 entity type** và
**44 relation type**.

Từ vựng quan hệ đo được trong `enterprise-attack.json` chỉ có 6 giá trị:
`uses`, `mitigates`, `detects`, `subtechnique-of`, `revoked-by`, `attributed-to`.
Mọi `attack_relationship` đều nằm trong 6 giá trị này.

Phân bố trạng thái:

| nhóm | mapped | alias | approximate | unmapped | tổng |
|---|---:|---:|---:|---:|---:|
| entity type | 8 | 2 | 11 | 12 | 33 |
| relation type | 3 | 0 | 6 | 35 | 44 |

**Cần bạn duyệt:** mọi mục `approximate` là tôi đề xuất gần nhất, chưa chắc đúng ngữ nghĩa.
Mọi mục `unmapped` giữ nguyên tên GRID và gắn cờ `unmapped` — **không có gì bị xóa**.

Danh sách cần duyệt (`approximate`):

| GRID type | đề xuất | vì sao |
|---|---|---|
| `general-software` | `tool` | GRID rong hon `tool` (gom ca phan mem thuong); bundle khong co type rieng |
| `vulnerability` | `vulnerability` | STIX 2.1 co `vulnerability`, nhung bundle ATT&CK khong chua loai nay |
| `ipv4-addr` | `ipv4-addr` | SCO cua STIX 2.1; bundle khong chua |
| `ipv6-addr` | `ipv6-addr` | SCO cua STIX 2.1; bundle khong chua |
| `domain-name` | `domain-name` | SCO cua STIX 2.1; bundle khong chua |
| `url` | `url` | SCO cua STIX 2.1; bundle khong chua |
| `network-traffic` | `network-traffic` | SCO cua STIX 2.1; bundle khong chua |
| `infrastructure` | `infrastructure` | SDO cua STIX 2.1; bundle ATT&CK khong chua |
| `x509-certificate` | `x509-certificate` | SCO cua STIX 2.1; bundle khong chua |
| `indicator` | `indicator` | SDO cua STIX 2.1; ATT&CK khong dung loai nay |
| `location` | `location` | SDO cua STIX 2.1; bundle khong chua |
| `exploits` (rel) | `uses` | bundle chi co `uses`; `exploits` cua GRID gan nghia |
| `malicious-investigates-track-detects` (rel) | `detects` | bundle co `detects` (dung cho detection strategy) |
| `executes` (rel) | `uses` | bundle chi co `uses` |
| `authored-by` (rel) | `attributed-to` | bundle chi co `attributed-to` |
| `indicates` (rel) | `detects` | bundle co `detects` |
| `research-describes-analysis-of-characterizes-detects` (rel) | `detects` | bundle co `detects` |

Toàn bộ bảng: `out/type_mapping.json`.

## B2–B5. KG ghép

**CHƯA CHẠY** — cần `out/grid_raw/` (xem mục A3/A4).

Khi có dữ liệu, chạy:

```bash
python out/build_kg_full.py
```

rồi nạp vào Neo4j:

```bash
python phuong_phap_2/attack_kg_neo4j.py \
    --scoped phuong_phap_2/kg_base_scoped.json \
    --kg out/kg_full.json --report-name report_1 --password MAT_KHAU
```

Lớp nền vẫn nạp từ `kg_base_scoped.json` — **không thay đổi**.

`--dry-run` cho biết trước số node/cạnh sẽ nạp, số node theo từng lớp và số cạnh
GRID — để kiểm tra trước khi ghi vào Neo4j.

## Kiểm tra bất biện trước khi nạp (self-check)

```bash
python out/selfcheck_part_b.py
```

Chạy offline, dùng **fixture tổng hợp** trong thư mục tạm — **không phải kết quả GRID**,
và không ghi gì vào `out/kg_full.json`. Nó kiểm tra đúng những lỗi đã phát hiện khi viết
code, để không lặp lại:

- id node không trùng, không cạnh trỏ tới node không tồn tại;
- nhãn node/cạnh hợp lệ cho Cypher;
- mọi giá trị trong `kg_full.json` nạp được vào Neo4j (dict → chuỗi JSON, vì Neo4j
  chỉ nhận primitive hoặc list primitive);
- cạnh `inferred_by="code"` đều là `USES` và không self-loop;
- mọi cạnh `inferred_by="grid"` đều có `evidence_status` (thiếu bằng chứng thì gắn
  cờ, không xóa);
- node khớp ATT&CK thì có `external_id`, node mới thì để trống;
- node đã có trong lớp nền giữ `layer='base'` sau khi nạp.

## Ranh giới đã giữ

- Không sửa file gốc của repo; mọi thứ mới nằm trong `out/`.
- Không thêm kiến thức ngoài văn bản báo cáo: mọi entity/triple GRID đều truy về
  được một câu trong `report_1.json` (cột `evidence`) hoặc bị gắn cờ `evidence_status`.
- Không xóa gì: thiếu ánh xạ type thì giữ type gốc + cờ; thiếu bằng chứng thì
  giữ triple + cờ; khớp mơ hồ thì để trống `external_id`.
- Lớp nền ATT&CK không đổi: vẫn nạp từ `phuong_phap_2/kg_base_scoped.json`.
- Entity ngoài phạm vi loader không bị loại — được đánh dấu `in_loader_scope`
  (giống cách đã xử lý ở tầng technique của báo cáo).

