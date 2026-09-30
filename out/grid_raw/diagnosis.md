# A1 - Chẩn đoán: tại sao entities/relations của GRID rỗng

Sinh lúc: 2026-09-30T17:12:31

## 0. Cảnh báo quan trọng về file `raw_output.txt`

`out/grid_output/raw_output.txt` **không phải** output thô của model.
`GRID_backbone._build_final_split_output()` (src/grid/GRID_backbone.py:165-198) dựng lại
file đó từ `final_entities` / `final_relations`, tức là từ kết quả ĐÃ PARSE:

```
blocks = ['#Entity_List_Start#', _json_dumps(final_entities), '#Entity_List_End#', ...]
```

Nên thấy "suy luận có nhưng `#Entity_List#` là `[]`" trong file đó chỉ chứng minh
**parser** trả về rỗng, không chứng minh model trả `[]`.
Output thô thật chỉ nằm ở `step1_raw.txt`, `step2_raw.txt` và `_TemplateDebug/*.jsonl`.

## 1. Probe parser (không cần model, không cần GPU)

Cách làm: nạp chính `_robust_json_parse` của repo rồi đưa vào 6 chuỗi mẫu đã biết kết quả
mong muốn. Nếu *tất cả* mẫu đều ra 0 thì lỗi ở parser/môi trường; nếu chỉ mẫu JSON hỏng
ra 0 thì parser ổn và vấn đề nằm ở model hoặc input.

- Nạp được `article_io_cache_parser`: True
- `json_repair` import được: **True**
- Dùng `tools.py` stub (máy chạy probe không cần cài `requests`)
- Dùng `vllm_environment_setup` stub (tránh phụ thuộc `~/Dropbox/tools.py`)

| mẫu | entities (thực) | relations (thực) | entities (mong đợi) | relations (mong đợi) | khớp? |
|---|---:|---:|---:|---:|---|
| `entity` | 1 | 0 | 1 | 0 | khớp |
| `relation` | 2 | 1 | 2 | 1 | khớp |
| `empty_list` | 0 | 0 | 0 | 0 | khớp |
| `no_marker` | 0 | 0 | 0 | 0 | khớp |
| `truncated` _(chỉ quan sát)_ | 1 | 0 | 1 | 0 | khớp |
| `broken_json` _(chỉ quan sát)_ | 1 | 0 | 1 | 0 | khớp |

**Kết luận probe: `parser_ok`** — Parser đọc đúng mọi mẫu chuẩn -> lỗi KHÔNG nằm ở parser.

> Parser đúng. Mẫu 'truncated' cứu được 1 entity -> cắt output KHÔNG phải nguyên nhân gây rỗng, chỉ gây thiếu.

## 2. Các nguyên nhân, xếp theo mức độ khả nghi ĐÃ ĐO

| # | Nguyên nhân | Bằng chứng | Trạng thái |
|---|---|---|---|
| 1 | `json_repair` chưa cài | `article_io_cache_parser.py:311,320,360` quanh `import json_repair` đều bọc `except Exception: pass` → ImportError bị nuốt im lặng | **ĐÃ TÁI HIỆN**: thiếu `json_repair` thì cả 6 mẫu ra 0; cài vào thì `entity` ra 1, `relation` ra 2+1, `broken_json` ra 1. Đây là nguyên nhân gây rỗng **hoàn toàn**. |
| 2 | Model tự sinh list rỗng | Base Qwen3-4B-Instruct-2507 chưa qua hậu huấn luyện task-bank, không được huấn luyện để phát đủ marker | Cần mục 3: `verdict = model_emitted_empty_list` |
| 3 | Model không tạo đủ marker | Không có list marker → rơi vào fallback `_repair_json` | Cần mục 3: `verdict = markers_missing` |
| 4 | Request lỗi / timeout | `out/tools.py` nuốt exception và trả `""` | Cần mục 3: `verdict = empty_response` |
| ~~5~~ | ~~Output bị cắt~~ | Regex bắt buộc có `#Entity_List_End#` (`:301-302`) | **ĐÃ LOẠI**: đo mẫu `truncated` vẫn ra 1 entity nhờ fallback `brace_match` + `json_repair`. Cắt output gây **thiếu**, không gây rỗng. |

**Kết luận A1 (chỉ dựa trên đọc code + probe, chưa cần chạy model):** nếu `json_repair` trên
Colab đã được cài đúng thì nguyên nhân số 1 bị loại, và phần còn lại phải phân biệt bằng cách
đọc output thô. Mà `raw_output.txt` hiện tại không dùng được vì nó đã bị dựng lại (mục 0).
Đó là lý do `out/grid_raw/` của lần chạy mới phải lưu `step1_raw.txt` / `step2_raw.txt` thật.

## 3. Kết quả đọc `_TemplateDebug/*.jsonl`

Không tìm thấy file `.jsonl` nào. Có thể vì:

- Colab runtime bị restart (thư mục là ephemeral, mất khi khởi động lại); hoặc
- `save_debug_log()` chỉ chạy sau khi `_call_llm` trả về, tức là phải đã gọi model thành công ít nhất một lần.

Nếu file có tồn tại, chạy lại `python out/grid_diagnose.py` ngay sau khi pipeline chạy xong,
hoặc tải thư mục `src/GeneratedKGContent/_TemplateDebug/` về máy local rồi chạy.

## 4. Nhật ký gọi vLLM (`vllm_calls.jsonl`)

Đây là nguồn để phân biệt "model trả list rỗng" với "bị cắt output" với "request hỏng".

Chưa có `vllm_calls.jsonl` (chỉ xuất hiện sau lần chạy có gọi vLLM thật).

## 5. Đọc `out/grid_output/*.txt` của lần chạy trước

Không có file `step1_raw.txt` / `step2_raw.txt` trên đĩa (đã bị xoá khi khởi động lại Colab).

## 6. Thông tin phiên chạy


