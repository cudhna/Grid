# Hướng dẫn chạy GRID trên Google Colab (A1 → A4)

Script duy nhất: **`out/run_grid_colab.py`** — tự làm hết A1, A2, A3, A4.
Chạy một lần, xong thì tải thư mục `out/grid_raw/` về máy local để chạy Phần B.

## Yêu cầu
- Tài khoản Google (miễn phí)
- **Runtime → Change runtime type → Hardware accelerator → GPU** (Colab miễn phí cấp T4, 16 GB VRAM)

---

## 1. Clone + lấy code mới nhất

```python
!git clone https://github.com/cudhna/Grid.git
%cd Grid
!git pull          # BẮT BUỘC: lần clone đầu có thể thiếu file của phiên bản mới
```

> ⚠️ **Không `%cd Grid` lần thứ hai** — sẽ tạo `/content/Grid/Grid` và script không tìm thấy repo.
> ⚠️ Thư mục Colab là **ephemeral**: mất sạch khi restart runtime hoặc hết phiên.
> Tải `out/grid_raw/` về **ngay sau khi chạy xong**, không để qua ngày hôm sau.

## 2. Chạy

```python
!python out/run_grid_colab.py
```

Trình tự script tự làm:

| bước | việc | thời gian |
|---|---|---|
| A2 | in bảng kích thước checkpoint, chọn `base_model` (8.05 GB) | vài giây |
| A1 | probe parser `_robust_json_parse` (6 mẫu) → `out/grid_raw/diagnosis.md` | vài giây |
| — | cài dependency, tải model, khởi động vLLM | 5–15 phút |
| A3 | chạy GRID: 1 lần gộp + 7 lần riêng từng procedure, mỗi lần tối đa 3 attempt | 5–20 phút |
| A1 | chẩn đoán lại (lần này có đủ dữ liệu `_TemplateDebug/*.jsonl`) | vài giây |

**Kiểm tra A1 trước khi đọc tiếp:** nếu dòng probe in ra `parser_broken` thì dừng,
chạy `!pip install json-repair` rồi chạy lại script. Nguyên nhân này đã được đo và
tái hiện (thiếu `json_repair` → cả 6 mẫu chuẩn đều ra danh sách rỗng).

## 3. Cấu trúc kết quả `out/grid_raw/`

```
out/grid_raw/
├── procedure_map.json        # procedure -> {chunk, technique_id, tactic, grid_dir}
├── manifest.json             # cấu hình lần chạy + số entity/relation từng lần chạy
├── run.log                   # log toàn bộ
├── vllm_calls.jsonl          # MỖI lần gọi LLM: token, finish_reason, truncated, lỗi
├── diagnosis.md              # báo cáo chẩn đoán A1
├── template_debug/           # prompt + output thô bóc từ _TemplateDebug/*.jsonl
│                              #   mỗi bản ghi: *.prompt.txt, *.raw.txt, *.verdict.json
├── aggregate/                # lần chạy gộp cả 7 procedure
└── proc_01_T1486/ … proc_07_T1036.001/
```

Mỗi thư mục lần chạy có 11 file:

| file | nội dung |
|---|---|
| `input.txt` | đúng văn bản đã gửi model (đã bỏ dòng `[Chunk n] Tactic - Txxxx`) |
| `prompt_step1.json` / `prompt_step2.json` | prompt đầy đủ mà GRID dựng ra |
| `step1_raw.txt` / `step2_raw.txt` | **output thô** của model từng bước |
| `raw_output.txt` | output GRID dựng lại (xem cảnh báo bên dưới) |
| `raw_output.NOTE.txt` | giải thích `raw_output.txt` khác output thô ở đâu |
| `entities.json` / `relation.json` | kết quả đã parse — đây là dữ liệu Phần B dùng |
| `attempts.json` | từng lần thử: số entity/relation, `step1_chars`/`step2_chars`, `step1_verdict`/`step2_verdict`, lỗi nếu có |

> **Cảnh báo quan trọng về `raw_output.txt`:** nó **không phải** output thô của model.
> `GRID_backbone._build_final_split_output()` dựng lại từ `final_entities` / `final_relations`
> sau khi đã parse. Muốn xem model thực sự sinh ra gì thì đọc `step1_raw.txt` / `step2_raw.txt`.

## 4. Tải `out/grid_raw/` về máy local

Thư mục Colab mất khi restart. Tải ngay sau khi chạy xong:

```python
!zip -r grid_raw.zip out/grid_raw
```

Sau đó tải `grid_raw.zip` qua panel Files (bấm phải → Download), giải nén **đè lên**
thư mục `out/grid_raw/` của repo trên máy local.

Cách nhanh hơn nếu repo đã có sẵn trên Drive: chép nguyên thư mục, không cần zip.

## 5. Chạy Phần B trên máy local (không cần GPU)

```powershell
python out\build_kg_full.py
```

- Tạo `out/type_mapping.json` (B1 — duyệt các mục `approximate`)
- Tạo `out/kg_full.json` (B2–B5)
- Cập nhật `out/report.md`

Nạp vào Neo4j:

```powershell
python phuong_phap_2\attack_kg_neo4j.py `
    --scoped phuong_phap_2\kg_base_scoped.json `
    --kg out\kg_full.json --report-name report_1 --password MAT_KHAU --dry-run
```

Bỏ `--dry-run` để nạp thật. Lớp nền **không thay đổi**.

---

## Xử lý lỗi

### `json_repair` / parser trả danh sách rỗng
- `!pip install json-repair` rồi chạy lại script.
- `out/grid_raw/diagnosis.md` mục probe ghi rõ kết luận.
- Nguyên nhân: `article_io_cache_parser._robust_json_parse()` có 3 chỗ
  `except Exception: pass` nuốt luôn `ImportError` của `json_repair` → parse fail âm thầm.

### "CUDA out of memory"
- **Runtime → Restart runtime**, chạy lại script.

### "vLLM server failed to start"
- Log: `!cat out/vllm_server.log`
- Script đã pin `vllm==0.11.0` (hỗ trợ Python 3.13 + T4/CUDA 12) và `transformers<5`
  (transformers 5.x bỏ `all_special_tokens_extended` mà vLLM 0.11.0 dùng → `AttributeError`).
  vLLM 0.8.x–0.10.x không cài được trên Python 3.13; bản mới nhất (0.30.x, torch 2.13/cu130)
  không chạy được trên T4.
- Lỗi `EngineCore failed to start … larger than the available KV cache memory`:
  script đã giải hạn `--max-model-len 16384` và `--gpu-memory-utilization 0.92`.
  (Đo được: prompt Step 1 ~2.671 token + input ~445 token → 16384 rất dư, không cần tăng.)
- T4 không hỗ trợ FlashAttention 2 (cần compute capability ≥ 8) nên vLLM dùng
  **FlexAttention** → khởi động chậm ~2 phút (torch.compile lần đầu). Bình thường, không phải lỗi.
- Script chạy `--dtype float16` (T4 không có BF16 tensor core → bf16 bị mô phỏng, sinh token
  rất chậm, dễ timeout). Trên GPU mới hơn đổi `DTYPE` ở đầu `run_grid_colab.py` thành `"auto"`.
- vLLM cũ treo từ lần chạy trước: `!pkill -f vllm` hoặc **Restart runtime**.

### `FileNotFoundError: Không tìm thấy report_1.json`
Script thử lần lượt `report_1.json` (thư mục gốc repo), `phuong_phap_2/report_1.json`,
`out/report_1.json`. File nằm trong `phuong_phap_2/`, phải `git pull` mới có
(thư mục này chưa nằm trong bản clone cũ).

### Một số lần chạy vẫn ra `entities: 0` dù đã cài `json_repair`
Xem `out/grid_raw/vllm_calls.jsonl` để phân biệt 3 khả năng:

| `finish_reason` | nghĩa là |
|---|---|
| `length` + `truncated: true` | model bị cắt output (`MAX_NEW_TOKENS = 8192`); parser vẫn cứu được phần đầu |
| `stop` nhưng 0 entity | model **tự sinh danh sách rỗng**, hoặc thiếu marker `#Entity_List_Start#` |
| có `error` | request hỏng — xem `out/vllm_server.log` |

Cột `chars` cho biết model sinh ra bao nhiêu ký tự: nếu rất nhỏ thì model không sinh gì.

### "No module named 'xxx'"
`!pip install <package>` rồi **Restart runtime** và chạy lại.

---

## Tùy chọn

### Dùng checkpoint fine-tuned (`task_bank_reward`, 8.82 GB)
Đầu `out/run_grid_colab.py`:
```python
USE_BASE_MODEL = False
```
Không dùng `gptoss120b_generator_sft` (17.65 GB) và `llama31_8b_task_bank_reward` (~16 GB):
T4 chỉ có 16 GB VRAM. Bảng kích thước đo từ HuggingFace API nằm ở `out/report.md` mục A2.

### Chỉ chạy A1 (không cần GPU, không tải model)
```python
!python out/grid_diagnose.py
```
Chạy offline được, đọc `src/GeneratedKGContent/_TemplateDebug/*.jsonl` và `out/grid_output/`.

### Tăng `max_tokens`
```python
MAX_NEW_TOKENS = 8192   # = min(64*1024, MAX_MODEL_LEN // 2); phải < max_model_len
```

### Bỏ lần chạy gộp / chạy nhiều báo cáo
Đầu `out/run_grid_colab.py`:
```python
RUN_AGGREGATE = True       # False = chỉ chạy riêng từng procedure
RUN_PER_PROCEDURE = True   # False = chỉ chạy gộp
```
Nhiều báo cáo: sửa `REPORT_CANDIDATES` / `find_report_path()`.
Lưu ý Phần B mặc định **bỏ qua** thư mục `aggregate/` (tránh trùng entity);
dùng `--include-aggregate` nếu thật sự muốn gộp.
