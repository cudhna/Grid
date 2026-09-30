# Hướng dẫn chạy GRID trên Google Colab

## Yêu cầu
- Tài khoản Google (miễn phí)
- GPU T4 (16GB VRAM) - có sẵn miễn phí trên Colab

## Các bước

### 1. Mở Google Colab
- Truy cập: https://colab.research.google.com/
- Tạo notebook mới: **File → New notebook**

### 2. Chọn GPU
- **Runtime → Change runtime type → Hardware accelerator → GPU**
- Lưu: Colab miễn phí cung cấp GPU T4 (16GB VRAM)

### 3. Clone repo và chạy script

```python
# Cell 1: Clone repo
!git clone https://github.com/your-repo/ProjectGRID.git
%cd ProjectGRID
```

```python
# Cell 2: Chạy pipeline
!python out/run_grid_colab.py
```

### 4. Kết quả
Sau khi chạy xong, kết quả được lưu trong `out/grid_output/`:
- `raw_output.txt` - Output thô từ GRID
- `entities.json` - Danh sách entities
- `relations.json` - Danh sách relations
- `step1_raw.txt` - Output thô bước 1 (entity extraction)
- `step2_raw.txt` - Output thô bước 2 (relation extraction)

## Lưu ý

1. **Thời gian chạy**: ~10-15 phút (tải model + khởi động vLLM + chạy GRID)
2. **VRAM**: Qwen3-4B cần ~6-8GB VRAM, đủ cho T4 (16GB)
3. **Nếu muốn dùng model fine-tuned**: Sửa `USE_BASE_MODEL = False` trong `run_grid_colab.py`

## Xử lý lỗi

### Lỗi "CUDA out of memory"
- Restart runtime: **Runtime → Restart runtime**
- Chạy lại script

### Lỗi "vLLM server failed to start"
- Kiểm tra log: `!cat out/vllm_server.log`
- Đảm bảo đã chọn GPU ở bước 2
- Script đã pin `vllm==0.11.0` (hỗ trợ Python 3.13 + T4/CUDA 12) và `transformers<5` (transformers 5.x bỏ `all_special_tokens_extended` mà vLLM 0.11.0 dùng → `AttributeError` khi khởi động server). Lưu ý: vLLM 0.8.x–0.10.x không cài được trên Python 3.13; bản mới nhất (0.30.x, torch 2.13/cu130) không chạy được trên T4
- Nếu vLLM cũ treo từ lần chạy trước: `!pkill -f vllm` hoặc **Runtime → Restart runtime**

### Lỗi "No module named 'xxx'"
- Chạy: `!pip install <package_name>`
- Restart runtime và chạy lại

## Tùy chọn

### Dùng model fine-tuned (task_bank_reward)
Sửa file `out/run_grid_colab.py`:
```python
USE_BASE_MODEL = False  # Dùng task_bank_reward
```

### Tăng giới hạn token
```python
token=64 * 1024,  # Sửa thành 128 * 1024 nếu cần
```

### Batch processing
Để nhiều báo cáo, sửa hàm `prepare_input_text()` để đọc từ nhiều file.
