# Phương pháp 2 — Dựng Knowledge Graph 3 tầng cho Neo4j

> **Lớp nền:** MITRE ATT&CK đã thu hẹp về phạm vi *malware loader*
> **Tầng dữ liệu:** kết quả gán TTP của báo cáo CTI + entity/triple do mô hình GRID trích
> **Script nằm ở:** `phuong_phap_2/` (tầng 1–2) và `out/` (tầng 3)

## Mục lục

| Mục | Nội dung |
|---|---|
| [Tóm tắt nhanh](#tóm-tắt-nhanh) | Sơ đồ 3 tầng |
| [0](#0-vì-sao-phải-thu-hẹp-phạm-vi) | Vì sao bỏ 24.927 object |
| [1](#1-mục-tiêu) | Mục tiêu và nguyên tắc |
| [2](#2-dữ-liệu-đầu-vào) | Bundle ATT&CK, report, chunks |
| [3](#3-quy-trình) | `scope_loader` → `dict_kg` → `attack_kg_neo4j` |
| [4](#4-tầng-3--grid-chạy-trên-google-colab) | Tầng GRID: tách 2 pha, bắt tay A → B, **cách chạy không cần GPU trên máy local** |
| [5](#5-cách-chạy) | Từng lệnh, copy chạy được |
| [6](#6-kết-quả-thực-nghiệm) | Số liệu thật |
| [7](#7-phân-tích-chất-lượng-dữ-liệu) | 4 phát hiện về dữ liệu |
| [8](#8-truy-vấn-cypher-mẫu) | Query mẫu cho từng tầng |
| [9](#9-dữ-liệu-đi-ra) | File sinh ra, ý nghĩa từng trường |
| [10](#10-hạn-chế) | Giới hạn đã biết |
| [11](#11-hướng-phát-triển) | Việc đã làm / còn làm |
| [12](#12-lưu-ý-bảo-mật) | Không commit mật khẩu |
| [Phụ lục A](#phụ-lục-a--tầng-3-grid--chi-tiết) | Chi tiết tầng GRID (A1–A8) |
| [13](#13-tình-trạng-hiện-tại) | Cái gì đã chạy, cái gì chưa |

---

## Tóm tắt nhanh

```text
  TẦNG 1 · LỚP NỀN (ontology)
    MITRE ATT&CK thu hẹp về "malware loader"
    179 node = 171 technique + 8 tactic | 283 cạnh
    scope_loader.py  ->  kg_base_scoped.json
        │
        ▼
  TẦNG 2 · LỚP BÁO CÁO (dữ liệu)
    TTP của report_1.json (đã chuẩn hoá ID)
    28 node | 20 cạnh part_of
    dict_kg.py  ->  kg.json
        │
        ▼
  TẦNG 3 · LỚP GRID (dữ liệu)
    Entity + triple do mô hình GRID trích từ văn bản procedure
    out/run_grid_colab.py (GPU)  +  out/build_kg_full.py (offline)
    ->  out/kg_full.json
        │
        ▼
  attack_kg_neo4j.py  ->  Neo4j
```

**Nguyên tắc bất di bất dịch:** lớp nền không bao giờ bị thay đổi. Mọi thứ mới đều nằm ở
tầng trên, và mỗi node/cạnh đều trả lời được *"vì sao nó ở đây"*.

---

## 0. Vì sao phải thu hẹp phạm vi

Ban đầu nạp toàn bộ MITRE ATT&CK vào Neo4j. Kết quả: đồ thị có **25.639 object**
(697 technique, 730 malware, 176 intrusion-set, 95 tool, 1.758 analytic, 697
detection-strategy…) — quá rộng so với phạm vi nghiên cứu hiện tại, và nhận xét thẳng là:

> *"Đây không phải KG phục vụ CTI, mà chỉ là một bản sao của ATT&CK."*

**Quyết định:** phạm vi nghiên cứu = **malware loader**, và chỉ giữ 2 loại node
**TACTIC + TECHNIQUE**. Mục tiêu là đổi thứ tự ưu tiên của đồ thị: từ *"toàn bộ ATT&CK"*
sang *"định nghĩa phạm vi loader (tầng ontology) + kết quả gán TTP của báo cáo (tầng dữ liệu)"*.

**Kết quả:** 25.639 object → **179 node lớp nền + 28 node lớp báo cáo**.
Bị loát khỏi phạm vi: 533 node TTP + toàn bộ 24.927 object không phải TTP.

---

## 1. Mục tiêu

Dựng một knowledge graph trong Neo4j gồm **3 tầng**:

| Tầng | Tên | Nội dung | Nguồn |
|---|---|---|---|
| 1 | **Lớp nền** (ontology) | Định nghĩa phạm vi *malware loader*, cắt từ chính MITRE ATT&CK. Chỉ giữ `x-mitre-tactic` và `attack-pattern`. | `enterprise-attack.json` |
| 2 | **Lớp báo cáo** (dữ liệu) | Kết quả gán TTP của một báo cáo CTI, phủ lên lớp nền, luôn ghi rõ nguồn và phạm vi. | `report_1.json` |
| 3 | **Lớp GRID** (dữ liệu) | Entity và triple mô hình GRID trích trực tiếp từ văn bản procedure. | `out/grid_raw/` |

### Nguyên tắc

- ATT&CK là ontology gốc. Dữ liệu từ báo cáo **chỉ bổ sung, không thay thế**.
- **Không** dùng lại ontology riêng của GRID.
- Mỗi node đều trả về được *"vì sao được giữ"* → trường `keep_reason` → kiểm toán được.
- Chạy lại nhiều lần không nhân đôi dữ liệu (`MERGE` + khóa duy nhất).
- Tầng 3 phải tách được **"model trích"** với **"code suy ra"**, và mỗi triple phải truy
  về được một câu trong văn bản báo cáo — hoặc bị gắn cờ, **không được xoá**.

---

## 2. Dữ liệu đầu vào

### a) `enterprise-attack.json` (46,5 MB)

STIX bundle của MITRE ATT&CK. Đây là **kho object**, không phải file schema.

| Loại object | Số lượng |
|---|---:|
| Tổng object trong bundle | 26.085 |
| Bị loại (`revoked` hoặc `x_mitre_deprecated`) | 446 |
| **Object còn hiệu lực** | **25.639** |
| — attack-pattern (technique) | 697 |
| — x-mitre-tactic | 15 |
| — relationship | 21.262 |
| — x-mitre-analytic | 1.758 |
| — malware | 730 |
| — x-mitre-detection-strategy | 697 |
| — intrusion-set | 176 |
| — x-mitre-data-component | 106 |
| — tool | 95 |
| — campaign | 56 |
| — course-of-action | 44 |
| — khác (matrix, identity, marking) | 3 |

Bản bundle này khá mới: có các technique `T168x`, và tên tactic đã đổi
(`TA0005`: "Defense Evasion" → **"Stealth"**, `TA0112` → **"Defense Impairment"**).

### b) `report_1.json` (9,2 KB)

Kết quả pipeline GRID: danh sách theo chunk (34 chunk), mỗi chunk là danh sách tactic,
mỗi tactic có `techniques[]` gồm `id`, `name`, `procedure`.

Trong bản này: 20 mục technique (19 sau khi chuẩn hoá ID), **7 mục có procedure**
(5 technique khác nhau).

### c) `chunks.jsonl`

Văn bản gốc đã chia chunk. **Chưa dùng** — chưa xác nhận `report_1.json` thuộc báo cáo
nào trong `chunks.jsonl`.

### d) Neo4j đang chạy

Neo4j Desktop hoặc AuraDB.

---

## 3. Quy trình

### Bước 1 · `scope_loader.py` — thu hẹp MITRE về phạm vi malware loader

```text
Input : enterprise-attack.json, report_1.json
Output: kg_base_scoped.json, report_1.canonical.json, scope_report.json
```

Áp dụng lần lượt 8 quy tắc, từ "chắc chắn giữ" đến "loại hẳn":

#### L0 — Loại theo loại node

Chỉ giữ 2 loại: `x-mitre-tactic` và `attack-pattern`. Loại toàn bộ malware, tool,
intrusion-set, campaign, course-of-action, x-mitre-data-component, x-mitre-analytic,
x-mitre-detection-strategy, identity, x-mitre-matrix, marking-definition.

→ Loại 24.927 object, chỉ giữ lại 712 node TTP.

#### R1 · `attack-evidence` (102 technique) — bằng chứng từ chính dữ liệu ATT&CK

Bước này **không** dựa vào ý kiến cá nhân, mà lấy trực tiếp từ dữ liệu của MITRE:

1. **1a** — quét toàn bộ object malware/tool, lấy node mà tên hoặc alias khớp biểu thức
   `loader|downloader|dropper|stager`. Tìm được 25 phần mềm: Power Loader, Smoke Loader,
   IMAPLoader, Gootloader, CANONSTAGER, SplatDropper, XLoader, JSS Loader, XORIndex
   Loader, CSPY Downloader…
2. **1b** — từ 25 phần mềm đó, lấy tất cả quan hệ `uses` trỏ tới attack-pattern.
3. **1c** — giữ technique đó **chỉ khi** nó thuộc 1 trong 8 tactic của vòng đời loader.

**Lý do đúng:** một technique được *một phần mềm loader thật sự dùng* trong chính ATT&CK
thì mặc định là kỹ thuật của loader. Đây là lớp bằng chứng mạnh nhất.

#### R2 · `core-loader` (121 technique) — danh sách lõi do người nghiên cứu định nghĩa

Bổ sung cho R1 các kỹ thuật *"chuẩn"* của mã độc loại mà ATT&CK chưa gán phần mềm nào.
Nhóm theo giai đoạn của vòng đời loader:

| Giai đoạn | Technique |
|---|---|
| **Đến** | `T1566(.001/.002/.004)`, `T1204(.001/.002)`, `T1189`, `T1190`, `T1195(.002)` |
| **Hạ tầng** | `T1583(.001/.003/.004/.006)`, `T1584.001`, `T1587.001`, `T1588(.001/.002)`, `T1608(.001/.002/.003)` |
| **Chạy** | `T1059(.001/.003/.005/.006/.007/.009)`, `T1105`, `T1129`, `T1106`, `T1620`, `T1218(.001/.002/.005/.008/.010/.011)`, `T1559(.001/.002)`, `T1564.001` |
| **Tồn tại** | `T1547(.001/.009)`, `T1543.003`, `T1546.003`, `T1136.001`, `T1574.001`, `T1574.008` |
| **Ẩn mình** | `T1036(.001–.007)`, `T1027(.004/.008/.009)`, `T1140`, `T1553.002`, `T1480`, `T1497(.001/.003)`, `T1685(.001)`, `T1686(.003)`, `T1070.006`, `T1222`, `T1055(.001–.004)`, `T1134.001` |
| **Dò la** | `T1082`, `T1016`, `T1057`, `T1518(.001)`, `T1083`, `T1012`, `T1049`, `T1018` |
| **C2** | `T1071(.001/.004)`, `T1095`, `T1573.002`, `T1102`, `T1219`, `T1568.002`, `T1090(.002/.003)`, `T1132` |

Danh sách này viết thẳng trong **code** (`CORE_TECHNIQUES`) để kiểm toán được, không nằm
trong file cấu hình riêng. Nếu một ID không còn tồn tại trong bundle thì script **báo lỗi**
chứ không bỏ qua âm thầm.

#### R3 · `report` (19 technique)

Technique nào xuất hiện trong báo cáo thì **luôn giữ**, kể cả khi nằm ngoài phạm vi
loader. Một technique chỉ được báo cáo nhắc tới mà không thuộc định nghĩa loader sẽ có
`in_loader_scope = false` và `layer = "report"` (không đưa vào lớp nền).

**Lý do:** không được xoá thông tin người đọc thật, nhưng phải tách bạch được.

#### R4 · `parent-closure` (5 technique)

Các technique cha của một sub-technique đã được giữ. Bắt buộc: giữ `T1218.011` mà bỏ
`T1218` thì sub-technique bị mồ côi. Dùng BFS ngược qua quan hệ `subtechnique-of`.

5 technique cha được bổ sung: `T1037`, `T1053`, `T1069`, `T1087`, `T1137`.

> `T1486` thuộc Impact nên không có sub-technique; nó được giữ nhờ R3, không phải R4.

#### L1 — Loại tactic ngoài vòng đời loader

| Quyết định | Tactic | ID |
|---|---|---|
| **Giữ** | Initial Access | `TA0001` |
| **Giữ** | Execution | `TA0002` |
| **Giữ** | Persistence | `TA0003` |
| **Giữ** | Stealth | `TA0005` |
| **Giữ** | Discovery | `TA0007` |
| **Giữ** | Command and Control | `TA0011` |
| **Giữ** | Resource Development | `TA0042` |
| **Giữ** | Defense Impairment | `TA0112` |
| *Giữ thêm* | Collection | `TA0009` |
| *Giữ thêm* | Impact | `TA0040` |
| **Loại** | Credential Access | `TA0006` |
| **Loại** | Privilege Escalation | `TA0004` |
| **Loại** | Lateral Movement | `TA0008` |
| **Loại** | Exfiltration | `TA0010` |
| **Loại** | Reconnaissance | `TA0043` |

> 8 tactic đầu thuộc vòng đời loader. Collection và Impact được giữ **thêm** chỉ vì báo cáo
> nhắc tới (quy tắc R3).

#### L2, L3 — Loại technique và cạnh

Technique không được R1–R4 giữ thì loại (519/697 technique bị loại). Đồ thị lớp nền chỉ
giữ 2 loại quan hệ:

| Quan hệ | Hướng | Số cạnh | Nguồn |
|---|---|---:|---|
| `PART_OF` | technique → tactic | 184 | `kill_chain_phases` |
| `SUBTECHNIQUE_OF` | sub-technique → cha | 99 | bundle |

Mọi cạnh có dấu mũi châm đều bị loại. Không giữ `uses` / `mitigates` / `detects` /
`attributed-to` / `subtechnique-of` với node ngoài phạm vi.

#### Chuẩn hoá ID báo cáo

`report_1.json` do mô hình sinh ra, nên có thể chứa ID đã bị MITRE thu hồi. Script tra
quan hệ `revoked-by` (157 quan hệ trong bundle này) để đổi sang ID hiện hành:

```text
T1086 (PowerShell)  →  T1059.001 (PowerShell)
```

Sau chuẩn hoá: **19 technique** thay vì 20, và 19/19 đều tồn tại trong ATT&CK.

File `report_1.canonical.json` giữ nguyên cấu trúc list-of-chunk, thêm `original_id` +
`canonicalized` cho mục đã đổi, và chuẩn hoá tên tactic theo ATT&CK (giữ tên gốc ở
trường `report_name`).

> ⚠️ **Yêu tố hai:** pipeline GRID cần được sửa để không sinh ID đã deprecated.
> Lỗi này đã xảy ra ở mục `T1086`.

---

### Bước 2 · `dict_kg.py` — dựng lớp báo cáo

```text
Input : enterprise-attack.json, report_1.canonical.json   ← PHẢI dùng bản đã chuẩn hoá
Output: kg.json, flags.json
```

- **Khớp từ điển ATT&CK:** quét procedure không rỗng, khớp chuỗi để gán ID có sẵn.
  Tên dài (>4 ký tự) khớp không phân biệt hoa/thường; tên ngắn (≤4) phân biệt hoa/thường
  để bớt nhiễu. Tên trùng nhiều đối tượng được gắn cờ `ambiguous`.
- **Kiểm tra từng technique:** ID có tồn tại trong ATT&CK không, tên có khớp không, có bị
  deprecated không. **Chỉ gắn cờ** (`flags.json`), không tự sửa hay xoá.
- **Sinh triple**, kèm trường `source` để phân biệt:

| `source` | Ý nghĩa |
|---|---|
| `attack` | Quan hệ lấy từ ATT&CK (technique `part_of` tactic) |
| `report` | Entity xuất hiện trong procedure của technique (`mentioned_in_procedure_of`, kèm chunk và vị trí ký tự) |

- Có thêm cờ `--only-ttp`: chỉ giữ node tactic/technique, bỏ qua
  malware/tool/intrusion-set/campaign. Dùng cờ này để phù hợp phạm vi hiện tại.
  *(Trên dữ liệu này tình cờ cũng không có entity nào khớp được, nên khác biệt chưa thay
  đổi kết quả — nhưng cờ là để phạm vi không phụ thuộc vào máy có khớp hay không.)*

---

### Bước 3 · `attack_kg_neo4j.py` — nạp 3 tầng vào Neo4j

```text
Input: kg_base_scoped.json (lớp nền) + kg.json (lớp báo cáo) hoặc out/kg_full.json (3 tầng)
```

| Tham số | Tác dụng |
|---|---|
| `--scoped` | Nạp lớp nền **đã thu hẹp** (mặc định, phù hợp phạm vi hiện tại) |
| `--attack` | Nạp **toàn bộ** ATT&CK (khi cần đồ thị đầy đủ) |
| `--kg` | File lớp trên: `kg.json` (chỉ tầng 2) hoặc `out/kg_full.json` (cả 3 tầng) |
| `--dry-run` | **Không cần Neo4j** — chỉ in số node/cạnh sẽ nạp, node theo từng lớp, số cạnh GRID |

Cách xử lý:

- **Node lớp nền:** nhãn theo type (`AttackPattern`, `XMitreTactic`), `id = external_id`.
- **Node lớp trên:** `MERGE` vào node nền nếu đã tồn tại (chỉ ghi thêm `in_loader_scope` /
  `keep_reason`); node chưa có trong nền thì tạo mới, gắn `layer = "report"`,
  `in_loader_scope = false`, `keep_reason = ["report"]`.
- **Node `Report`** + cạnh `OBSERVES` từ `report_1` tới các technique trong báo cáo.
- **Cạnh `source = "attack"`:** cạnh đã có sẵn trong lớp nền → chỉ set
  `confirmed_by_report = true`.
- **Cạnh `source = "grid"`:** nạp mới với `layer = "grid"`, kèm `inferred_by`, `evidence`,
  `evidence_status`, `rel_type_unmapped`, `not_an_edge`.
- **Node có `sources`:** thêm trường `layers` (danh sách các lớp đã chạm node), còn
  `layer` lấy theo thứ tự `base` > `grid` > `report` — node đã có trong lớp nền **giữ**
  `layer = "base"`.
- **Giá trị kiểu dict** (vd `evidence_matched_words`) được đổi thành chuỗi JSON vì Neo4j
  chỉ nhận primitive hoặc list primitive.
- Chạy lại nhiều lần không nhân đôi dữ liệu (`MERGE` + khoá duy nhất).

---

## 4. Tầng 3 — GRID (chạy trên Google Colab)

> Chi tiết đầy đủ ở **Phụ lục A**. Tóm tắt trình tự ở đây.

### Điều kiện bắt buộc: GPU

Script dừng với exit code 2 **trước khi** tải vLLM (~3 GB) và model (~8 GB) nếu
`torch.cuda.is_available()` là `False`. Lý do: vLLM cần `libcuda.so.1`, thiếu thì chết
với `Failed to infer device type` sau khi đã tải xong 11 GB.

```python
# Bật GPU: Runtime -> Change runtime type -> Hardware accelerator -> T4 GPU
!nvidia-smi          # phải in ra tên GPU
```

Bỏ qua kiểm tra: `os.environ["GRID_ALLOW_NO_GPU"]="1"` — chỉ để chẩn đoán, **không** chạy
được model.

### Vì sao tách thành 2 pha

```text
   PHAI TRÊN GPU (Colab T4)        OFFLINE, trên máy VS Code
   ──────────────────────────        ──────────────────────────────
   A1  Chẩn đoán parser              B1  out/type_mapping.json
   A2  Chọn checkpoint               B2  Khớp entity → external_id
   A3  Chạy GRID từng procedure      B3  Cạnh USES suy ra bằng CODE
   A4  Xuất out/grid_raw/            B4  Triple model trích + câu bằng chứng
                                     B5  out/kg_full.json + nạp Neo4j
```

Lý do tách: máy local không có GPU, và phần B **không gọi model** nên chạy lại không tốn kém.

### Bắt tay A → B

1. Commit + push code lên `github.com/cudhna/Grid`.
2. Trên Colab: `!git clone` → `%cd Grid` → `!git pull` → `!python out/run_grid_colab.py`.
3. **Tải nguyên thư mục `out/grid_raw/` về máy local** (thư mục Colab là *ephemeral*,
   mất sạch khi restart runtime).
4. Trong VS Code: `python out\build_kg_full.py` → `python out\selfcheck_part_b.py` →
   `python phuong_phap_2\attack_kg_neo4j.py ... --dry-run` → bỏ `--dry-run` để nạp thật.

Hướng dẫn Colab chi tiết: [`out/colab_guide.md`](../out/colab_guide.md)

### Cách chạy KHÔNG cần GPU — trên chính máy này (đã kiểm chứng chạy thật)

Máy local **không có GPU NVIDIA** (chỉ Intel UHD iGPU), nên vLLM không dùng được:
vLLM không có nhánh CPU, nó chết ngay ở tầng import với
`libcuda.so.1: cannot open shared object file` chứ không chậm dần.

Cách dùng thật ở đây: **tải model về máy 1 lần dưới dạng GGUF**, phục vụ bằng
`llama-server` (llama.cpp, chạy CPU), rồi cho GRID gọi vào endpoint
OpenAI-compatible đó qua chế độ `GRID_MODE=external`.

#### 1. Lệnh duy nhất — cài hết và chạy thẳng

Tại thư mục gốc repo `E:\04_Projects_Web\Grid`:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_local_oneclick.ps1
```

Script [`run_local_oneclick.ps1`](../run_local_oneclick.ps1) làm hết 6 việc trong 1 lệnh:

| Bước | Việc | Kết quả đo được |
|---|---|---|
| 0 | Dò thư mục gốc repo, tạo thư mục cần thiết | — |
| 1 | Tải model GGUF từ HuggingFace (bỏ qua nếu đã có) | 2.382 MB, ~6 phút ở ~6,7 MB/s |
| 2 | Tải + giải nén `llama-server.exe` (llama.cpp CPU x64) | 18,3 MB |
| 3 | Khởi động `llama-server` nền, cổng 8080 | xem lệnh server bên dưới |
| 4 | Chờ `GET /v1/models` sẵn sàng (tối đa 600 s) | — |
| 5 | Đặt biến môi trường `GRID_MODE=external` + `VLLM_*` | — |
| 6 | Chạy `python out\run_grid_colab.py` (A1 → A3 → A4) | ghi vào `out\grid_raw\` |

Lệnh server mà script tự chạy:

```powershell
E:\tools\llama.cpp\llama-server.exe `
  -m "E:\models\Qwen3-4B-Instruct-2507-Q4_K_M.gguf" `
  -c 16384 -np 1 `
  --alias Qwen3-4B-Instruct-2507-Q4_K_M.gguf `
  --threads 8 --n-gpu-layers 0 `
  --host 127.0.0.1 --port 8080
```

Ba tham số **không được bỏ**, mỗi tham số một lý do:

- **`--alias <tên file .gguf>`** — `preflight_endpoint()` trong `out/run_grid_colab.py`
  dừng với exit 3 nếu `VLLM_MODEL_NAME` không nằm trong danh sách server đang
  phục vụ. `--alias` làm `id` trong `/v1/models` **luôn khớp** với tên file.
- **`-np 1`** — llama.cpp mặc định chia context cho nhiều slot. Prompt GRID dùng
  khoảng 2.700 token; nếu `-c 16384` bị chia cho 8 slot thì mỗi slot chỉ còn
  ~2.048 token, request sẽ vượt cửa sổ ngữ cảnh và bị cắt.
- **`--n-gpu-layers 0`** — ép chạy CPU hoàn toàn, không phụ thuộc GPU.

#### 2. Chỉ cài model, chưa chạy GRID

```powershell
powershell -ExecutionPolicy Bypass -File .\run_local_oneclick.ps1 -SkipRun
```

#### 3. Chạy lại (model + llama.cpp đã có → không tải lại)

```powershell
powershell -ExecutionPolicy Bypass -File .\run_local_oneclick.ps1
```

#### 4. Lệnh thủ công từng bước (không dùng script)

```powershell
# a) Tải model — 1 lần duy nhất, 2.382 MB
curl.exe -L --retry 5 -o E:\models\Qwen3-4B-Instruct-2507-Q4_K_M.gguf `
  https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/resolve/main/Qwen3-4B-Instruct-2507-Q4_K_M.gguf

# b) Bật server (chạy nền)
Start-Process E:\tools\llama.cpp\llama-server.exe -WindowStyle Hidden `
  -ArgumentList '-m "E:\models\Qwen3-4B-Instruct-2507-Q4_K_M.gguf" -c 16384 -np 1 `
                --alias Qwen3-4B-Instruct-2507-Q4_K_M.gguf --threads 8 `
                --n-gpu-layers 0 --host 127.0.0.1 --port 8080'

# c) Kiểm tra server đã sẵn sàng chưa
curl.exe http://localhost:8080/v1/models

# d) Chạy GRID
Set-Location E:\04_Projects_Web\Grid
$env:GRID_MODE            = 'external'
$env:VLLM_URL             = 'http://localhost:8080/v1'
$env:VLLM_API_KEY         = 'EMPTY'
$env:VLLM_MODEL_NAME      = 'Qwen3-4B-Instruct-2507-Q4_K_M.gguf'
$env:VLLM_REQUEST_TIMEOUT = '3600'
python out\run_grid_colab.py

# e) Tắt server khi xong
Get-Process llama-server -ErrorAction SilentlyContinue | Stop-Process -Force
```

#### 5. Chế độ `external` khác gì so với `colab`

| Việc | `GRID_MODE=colab` | `GRID_MODE=external` |
|---|---|---|
| Kiểm tra GPU (`check_gpu`) | Có, dừng exit 2 nếu không có | **Bỏ qua** |
| Cài `vllm`, `transformers`, `accelerate`, `safetensors` | Có (~4 GB) | **Bỏ qua** |
| Tải model từ HuggingFace (`snapshot_download`) | Có (~8 GB) | **Bỏ qua** |
| Khởi động `vllm serve` | Có | **Bỏ qua** |
| `preflight_endpoint()` (kiểm tra endpoint sống) | Không | **Có** |
| Tắt server khi xong | Có | **Không** (để nguyên) |
| Cài `json-repair`, `requests`, `openai`, `pandas`, `pyarrow` | Có | Có |

Chế độ `external` lấy tên model **từ `/v1/models`** chứ không đoán. Nếu endpoint
chết hoặc tên model lệch, script dừng ngay với exit 3 kèm hướng dẫn, thay vì
im lặng chạy tiếp rồi ra `entities: 0`.

#### 6. Số liệu đo thật trên máy này

Máy: i5-10210U, 4 nhân / 8 luồng, 16 GB RAM, **không GPU**, PowerShell 5.1, Python 3.14.7.

| Phép đo | Kết quả |
|---|---|
| Cỡ model Q4_K_M | 2.382 MB, magic `GGUF` + version 3 |
| Tốc độ sinh text (đã khởi động) | **2,89 token/giây** (300 token trong 103,7 s) |
| Lệnh mẫu 6 token | trả đúng `{"ok":true}` → chat template Qwen3 đúng |
| `preflight_endpoint()` | PASS, `served` = `Qwen3-4B-Instruct-2507-Q4_K_M.gguf` |
| Tải model | 2.382 MB, ~6 phút |

Ước tính thời gian chạy GRID trên CPU: 8 lần chạy × 2 bước = 16 lệnh gọi model.
Với mỗi lệnh khoảng 300–800 token output, tổng khoảng 5.000–13.000 token →
**khoảng 30–75 phút sinh token**, cộng thời gian xử lý prompt.
Dự kiến **1,5–3 giờ**.

> Con số 1,5–3 giờ là **ước tính**, chưa phải kết quả đo. `out/grid_raw/` hiện mới
> có `diagnosis.md` của A1, chưa có lần chạy model nào hoàn tất. Khi chạy xong,
> `vllm_calls.jsonl` ghi `completion_tokens` và `finish_reason` của từng lệnh để
> đối chiếu lại ước tính này.

#### 7. Lỗi đã gặp và cách xử lý

| Triệu chứng | Nguyên nhân | Xử lý |
|---|---|---|
| `this GGUF file is version <số> but this software only supports up to version 3` | File `.gguf` hỏng: `curl -C -` nối tiếp dữ liệu vào một file không phải GGUF, hoặc tải dở | Script tự kiểm tra 4 byte magic `GGUF`; file sai magic bị **xoá và tải lại từ đầu**. Nếu vẫn lỗi: `Remove-Item E:\models\*.gguf -Force` |
| `DỪNG: không gọi được endpoint` (exit 3) | `llama-server` chưa lên, hoặc sai cổng | Xem `E:\tools\llama.cpp\server.err.log`; thử `curl http://localhost:8080/v1/models` |
| `DỪNG: tên model trong VLLM_MODEL_NAME không khớp endpoint` (exit 3) | Không truyền `--alias` khi bật server, hoặc đã đổi tên file `.gguf` | Đặt `VLLM_MODEL_NAME` đúng với `id` mà `/v1/models` trả về |
| `llama-server đã thoát ngay` | Sai tham số, thiếu DLL, hoặc file model hỏng | Script in 25 dòng cuối của `server.err.log` |
| `Port 8080 đang phục vụ model khác` | Còn `llama-server` cũ từ lần chạy trước | `Get-Process llama-server \| Stop-Process -Force`, hoặc dùng `-Port` khác |
| Port đang bận nhưng script dừng | Script cố ý **không** giết server đang phục vụ đúng model | Đây là hành vi đúng: không giết nhầm server của việc khác |

#### 8. Vì sao không dùng Ollama

Ollama làm được việc tương tự nhưng **dễ dùng nhầm model**. Repo `qwen3` của
Ollama có tag `qwen3:4b` là **Qwen3-4B bản gốc** (có chế độ thinking), **không
phải** bản `Instruct-2507` đang dùng trên Colab. Dùng nhầm sẽ lặng lẽ thay đổi
thiết lập thực nghiệm.

Nếu vẫn muốn dùng Ollama thì phải chỉ đúng tag:

```powershell
winget install Ollama.Ollama
ollama pull qwen3:4b-instruct-2507-q4
$env:GRID_MODE            = 'external'
$env:VLLM_URL             = 'http://localhost:11434/v1'
$env:VLLM_MODEL_NAME      = 'qwen3:4b-instruct-2507-q4'
$env:VLLM_REQUEST_TIMEOUT = '3600'
python out\run_grid_colab.py
```

Bản quant của Ollama không phải đúng Q4_K_M của unsloth, nên kết quả trích xuất
có thể **khác đôi chút** so với Colab. Nếu cần số liệu đối chiếu được với Colab
thì dùng đường llama.cpp ở trên.

---

## 5. Cách chay

Yêu cầu: Python 3, driver Neo4j (cài một lần):

```powershell
python -m pip install neo4j
```

### Pha 1 — Tầng 1 và 2 (chạy được ngay, không cần GPU)

```powershell
cd phuong_phap_2
```

**(1) Thu hẹp phạm vi + chuẩn hoá báo cáo**

```powershell
python scope_loader.py --attack enterprise-attack.json --report report_1.json --out .
```

In ra: số technique theo từng quy tắc, số node lớp nền, ID đã đổi, cảnh báo ID sai.

**(2) Dựng lớp báo cáo — PHẢI dùng bản đã chuẩn hoá**

```powershell
python dict_kg.py --attack enterprise-attack.json --report report_1.canonical.json --out . --only-ttp
```

**(3) Kiểm tra trước khi nạp (không cần Neo4j)**

```powershell
python attack_kg_neo4j.py --scoped kg_base_scoped.json --kg kg.json --password x --dry-run
```

**(4) Nạp vào Neo4j, lần đầu (`--wipe` xoá graph cũ)**

```powershell
python attack_kg_neo4j.py --scoped kg_base_scoped.json --kg kg.json --report-name report_1 --uri bolt://localhost:7687 --user neo4j --password MAT_KHAU_CUA_BAN --wipe
```

> Trong PowerShell viết trên **một dòng**, không dùng dấu `^`.

**(5) Thêm báo cáo khác:** chạy lại (1)(2) với report mới, rồi lệnh (4) **bỏ `--wipe`**,
đổi `--report-name`. Chỉ nạp lớp nền: bỏ `--kg`.

Với AuraDB: dùng `--uri neo4j+s://xxxxxxxx.databases.neo4j.io`

### Pha 2 — Tầng 3 (Colab + VS Code)

Trên Colab:

```python
!git clone https://github.com/cudhna/Grid.git
%cd Grid
!git pull
!python out/run_grid_colab.py
```

Trải nguyên thư mục `out/grid_raw/` về máy local, rồi trong VS Code:

```powershell
# Ghép KG 3 tầng (offline)
python out\build_kg_full.py

# Kiểm tra bất biến + tương thích Neo4j (dùng fixture tổng hợp, KHÔNG phải kết quả thật)
python out\selfcheck_part_b.py

# Xem số liệu sẽ nạp, rồi mới nạp thật
python phuong_phap_2\attack_kg_neo4j.py --scoped phuong_phap_2\kg_base_scoped.json --kg out\kg_full.json --report-name report_1 --password MAT_KHAU --dry-run
```

---

## 6. Kết quả thực nghiệm

*Số liệu thật trên dữ liệu này.*

### Bước 1 — phân bố theo quy tắc

| Quy tắc | Số technique |
|---|---:|
| R1 attack-evidence | 102 |
| R2 core-loader | 121 |
| R3 report | 19 |
| R4 parent-closure | 5 |

> R1 và R2 có giao nhau, nên tổng là **171 technique** thuộc phạm vi loader.

### Bước 1 — kết quả

| Chỉ số | Giá trị |
|---|---|
| Lớp nền (định nghĩa malware loader) | **179 node** = 171 technique + 8 tactic |
| Cạnh lớp nền | **283 cạnh** = 184 `PART_OF` + 99 `SUBTECHNIQUE_OF` |
| Chỉ có trong báo cáo, nằm ngoài phạm vi | 7 technique + 2 tactic |
| Node TTP bị loại khỏi phạm vi | 533 / 712 |
| Node không phải TTP bị loại toàn bộ | 24.927 |

### Bước 2 — kết quả

| Chỉ số | Giá trị |
|---|---|
| Technique khác nhau | 19 |
| Mục có procedure | 7 (5 technique khác nhau) |
| Node | 28 (19 technique + 9 tactic) |
| Triple `part_of` | 20 |
| Cờ kiểm tra | 1 |
| Entity khớp được từ điển ATT&CK | **0** |

> 0 entity khớp được chính là lý do cần tầng 3 (xem mục 7).

### Bước 3 — đồ thị cuối cùng trong Neo4j (tầng 1 + 2)

| Chỉ số | Giá trị |
|---|---|
| Node | **188** (179 lớp nền + 9 node lớp báo cáo) |
| Cạnh | **302** (283 lớp nền + 19 cạnh `OBSERVES`) |
| Technique báo cáo nằm trong phạm vi loader | 12/19 |
| Technique báo cáo nằm ngoài phạm vi | 7/19 (6 thuộc Impact + 1 Malvertising) |

> 20 cạnh `part_of` của lớp báo cáo trùng với lớp nền nên không tạo lại, tránh cạnh trùng.

---

## 7. Phân tích chất lượng dữ liệu

Bốn phát hiện khi chạy thử:

### (1) ID bị thu hồi trong báo cáo

`report_1.json` có `T1086`; MITRE đã thu hồi ID này và chuyển thành `T1059.001`. Nếu nạp
nguyên report vào Neo4j, `T1086` sẽ trở thành một node *"mồ côi"* không gắn được tactic
nào → kết quả gán TTP bị sai cho 1/19 technique.

Đã xử lý bằng bước chuẩn hoá ID. **Bài học:** pipeline sinh TTP phải kiểm tra ID còn hiệu
lực trước khi đưa vào KG.

### (2) Tên technique sai trong báo cáo

`flags.json` còn 1 cờ:

```text
T1036.001   báo cáo ghi "Masquerading",  ATT&CK gọi "Invalid Code Signature"
```

**Nguyên nhân:** mô hình nhớ tên technique **cha** (`T1036` Masquerading) thay vì tên
sub-technique (`T1036.001`). Đây là lỗi phổ biến khi LLM sinh TTP.

Đã giữ nguyên (không tự sửa) và ghi cờ để báo cáo. Nếu cần, sửa ở bước kiểm tra tên bằng
cách gán ID → tên chuẩn của ATT&CK, nhưng phải lưu lại tên gốc để truy vết.

### (3) Hạn chế độ dày dữ liệu báo cáo

Chỉ 7/34 mục có procedure. 21/34 chunk rỗng. 19 technique trong báo cáo đều rải rác,
không đủ để suy ra chuỗi hành động (kill chain) của một cuộc tấn công. Đây là lý do KG
chưa thể *"kể chuyện"* như một báo cáo chân thực.

### (4) Tầng 2 không tạo được quan hệ giữa các entity

Vì 0 entity khớp được từ điển ATT&CK, lớp báo cáo chỉ có node technique/tactic và các
cạnh `part_of` — **không có quan hệ nào giữa các entity**. Đây chính là khoảng trống lớn
nhất, và là lý do tồn tại tầng 3.

---

## 8. Truy vấn Cypher mẫu

> Không chạy `RETURN *` — lớp nền vẫn là 179 node, nhưng vẫn nên chọn đúng phạm vi.

### Kiểm tra phạm vi

```cypher
// Toàn bộ node theo phạm vi
MATCH (t:AttackPattern) RETURN t.in_loader_scope AS in_scope, count(*) AS n ORDER BY n DESC

// Kỹ thuật loader, theo nhóm và lý do được giữ
MATCH (t:AttackPattern) WHERE t.in_loader_scope
RETURN t.keep_reason AS reason, count(*) AS n ORDER BY n DESC

// Kỹ thuật chỉ có trong báo cáo, nằm ngoài phạm vi loader
MATCH (t:AttackPattern) WHERE t.in_loader_scope = false AND t.layer = 'report'
RETURN t.id, t.name, t.keep_reason
```

### Kết quả gán TTP của báo cáo

```cypher
// Technique báo cáo quan sát + tactic tương ứng
MATCH (r:Report {id:'report_1'})-[:OBSERVES]->(t)-[:PART_OF]->(k) RETURN r, t, k

// Phân bố theo tactic
MATCH (r:Report {id:'report_1'})-[:OBSERVES]->(t)-[:PART_OF]->(k)
RETURN k.name AS tactic, count(*) AS n ORDER BY n DESC

// Chỉ phần trong phạm vi loader
MATCH (r:Report {id:'report_1'})-[:OBSERVES]->(t) WHERE t.in_loader_scope
RETURN t.id, t.name

// Cây sub-technique của một technique
MATCH (p:AttackPattern)-[:SUBTECHNIQUE_OF*1..2]->(c:AttackPattern {id:'T1059'})
RETURN p.id, p.name
```

### Tầng 3 — GRID

```cypher
// Chủ thể nào dùng technique nào — cạnh do MODEL trích (chỉ cạnh có bằng chứng)
MATCH (a)-[e]->(t:AttackPattern) WHERE e.source='grid' AND e.inferred_by='grid'
RETURN a.name, type(e), t.name, e.evidence LIMIT 25

// Cạnh do CODE suy ra — tách riêng để không nhầm với kết quả model
MATCH (a)-[e:USES]->(t:AttackPattern) WHERE e.inferred_by='code'
RETURN a.name, t.name, e.edge_role, e.procedure_id

// Triple GRID chưa tìm được câu bằng chứng (đã gắn cờ, KHÔNG bị xoá)
MATCH (a)-[e]->(b) WHERE e.inferred_by='grid' AND e.evidence IS NULL
RETURN a.name, type(e), b.name, e.rel_type_grid

// Node đã được cả báo cáo và GRID chạm vào
MATCH (n) WHERE size(n.layers) > 1 RETURN n.id, n.name, n.layers, n.layer
```

### Kiểm tra chất lượng

```cypher
// Technique có tên khác tên chuẩn của ATT&CK (lấy từ flags.json)
// Node lớp báo cáo chưa có node nền nào nối tới (dang số)
MATCH (a)-[e]->(b) WHERE e.layer = 'report' AND NOT a:Report RETURN a, e, b
```

> **Mẹo:** trong tab Graph, chọn caption của từng loại node là `"name"` để dễ đọc.

---

## 9. Dữ liệu đi ra

| File | Nội dung |
|---|---|
| `kg_base_scoped.json` | **LỚP NỀN** đã thu hẹp.<br>Node: `id`, `type`, `name`, `external_id`, `stix_id`, `url`, `description`, `is_subtechnique`, `layer`, `in_loader_scope`, `keep_reason`.<br>Cạnh: `h`, `r` (`part_of` \| `subtechnique_of`), `t`, `source`, `layer`.<br>`meta`: phạm vi, 8 tactic, mô tả 4 quy tắc, thống kê. |
| `report_1.canonical.json` | Report đã chuẩn hoá ID. Dùng cho `dict_kg.py`. |
| `scope_report.json` | **BÁO CÁO KIỂM TOÁN:** số lượng theo quy tắc, danh sách node giữ kèm `keep_reason`, danh sách node bị loại theo loại, danh sách tactic bị loại, danh sách 25 phần mềm dùng làm bằng chứng, ID đã đổi, ID không tìm thấy. |
| `kg.json` | KG của riêng báo cáo (tầng 2). |
| `flags.json` | Cờ kiểm tra tên / ID. |
| `out/grid_raw/` | **Kết quả GRID** (tầng 3) — xem Phụ lục A. |
| `out/type_mapping.json` | Ánh xạ type GRID → STIX/ATT&CK (cần duyệt). |
| `out/kg_full.json` | **KG 3 tầng** — định dạng giống `kg.json`. |
| `out/report.md` | Báo cáo tổng hợp toàn bộ quy trình. |
| Neo4j | Đồ thị 3 tầng. |

---

## 10. Hạn chế

- **Phạm vi loader định nghĩa bằng 2 lớp:** R1 là bằng chứng từ ATT&CK, R2 là danh sách
  do người nghiên cứu chọn. R2 có tính chủ quan; nếu muốn bảo vệ hơn thì lấy **chỉ R1**
  (102 technique) và bỏ R2 khỏi `CORE_TECHNIQUES`.
- **Chỉ giữ 2 loại quan hệ nền** nên đồ thị chuyển mạch không thể *"di chuyển"* giữa 2 phần
  mềm khác nhau. Muốn mở rộng: thêm quan hệ `subtechnique-of`, hoặc giữ lại node software
  nhưng gắn nhãn `"out-of-scope"` thay vì xoá.
- **24.927 object không phải TTP bị loại hoàn toàn**, gồm cả 1.758 analytic và 697
  detection-strategy. Nếu muốn dùng chúng để đánh giá phát hiện, phải nạp lại và gắn nhãn riêng.
- **Phụ thuộc procedure:** chỉ 5/19 technique có procedure nên lớp báo cáo rỗng. Tầng 3
  chỉ khắc phục được phần này, không phá được giới hạn của văn bản gốc.
- **Khớp từ điển bỏ sót entity** ATT&CK chưa biết (`CyberLock`, `Lucky_Gh0$t` không có
  trong ATT&CK) và không tạo quan hệ giữa các entity đó.
- **Chưa xác nhận** `report_1.json` thuộc báo cáo nào trong `chunks.jsonl`.
- **Tên tactic trong bản ATT&CK này đã đổi** (`TA0005 = "Stealth"`). Không nên hardcode
  tên, luôn dùng `x_mitre_shortname`.
- **Bundle `enterprise-attack.json` phải dùng lại khi MITRE ra bản mới**, nếu không danh
  sách ID trong `CORE_TECHNIQUES` sẽ báo lỗi.
- **Tầng 3 chưa có số liệu thật** — xem mục 12.

---

## 11. Hướng phát triển

- [~] Thêm bước trích entity báo cáo (NER) và tạo node malware/tool ở `layer = "report"`,
      kèm quan hệ `uses` giữa entity đó và technique.
      *(mã đã viết ở tầng 3 — Phụ lục A — nhưng **chưa chạy**, xem mục 13)*
- [ ] Lưu chunk vào cạnh `OBSERVES` để truy về nguồn gốc của từng technique.
- [ ] Xác nhận báo cáo nguồn trong `chunks.jsonl` để thay procedure bằng văn bản gốc.
- [ ] Tự động sửa lỗi *"tên technique sai"* bằng ID → tên chuẩn, lưu tên gốc để truy vết.
- [ ] Bổ sung quy tắc R5: giữ kỹ thuật nằm trong cùng *"chi phí phát hiện"* ATT&CK
      (có detection strategy), phục vụ cho mục tiêu phát hiện mẫu.
- [ ] Mở rộng phạm vi sang các loại malware khác (stealer, RAT, wiper) theo cùng 4 quy tắc,
      chỉ thay `LOADER_TACTICS` và `CORE_TECHNIQUES`.

---

## 12. Lưu ý bảo mật

Không ghi mật khẩu Neo4j vào tài liệu, cũng không chia sẻ lệnh có mật khẩu thật. Script chỉ
nhận mật khẩu qua tham số dòng lệnh nên không được dán vào script hay commit lên git.

Nếu đã dán mật khẩu vào nơi công khai và dùng lại ở chỗ khác thì nên đổi.

---

# Phụ lục A · Tầng 3 GRID — chi tiết

Mục 7 nói *"tầng 2 không tạo được quan hệ giữa các entity"* là khoảng trống lớn nhất. Phụ
lục này bổ sung tầng đó bằng cách chạy mô hình GRID trực tiếp trên **văn bản procedure**
của báo cáo.

Khác biệt cốt lõi với `dict_kg.py` (tầng 2):

| | Tầng 2 (`dict_kg.py`) | Tầng 3 (GRID) |
|---|---|---|
| Cách tìm entity | Khớp **tên** có sẵn trong từ điển ATT&CK | Model tự đọc văn bản và gọi tên |
| Entity lạ (`CyberLock`, `Lucky_Gh0$t`) | Bỏ sót | Tìm ra |
| Quan hệ giữa các entity | Không có | Có (model trích) |

## A.1 · Cấu hình lần chạy (đã đặt trong `out/run_grid_colab.py`)

| Tham số | Giá trị | Lý do |
|---|---|---|
| `GRID_TEMP` | `0.0` | Yêu cầu temperature 0 |
| `MAX_RETRIES` | `2` | Rỗng thì thử lại tối đa 2 lần, ghi log vào `attempts.json` |
| `INCLUDE_TECHNIQUE_HEADER` | `False` | Bỏ dòng tiêu đề `[Chunk n] Tactic - Txxxx` khỏi input |
| `RUN_AGGREGATE` | `True` | Chạy 1 lần gộp cả 7 procedure (để so sánh với lần chạy cũ) |
| `RUN_PER_PROCEDURE` | `True` | Chạy riêng từng procedure |
| `MAX_NEW_TOKENS` | `8192` | Phải nhỏ hơn `max_model_len` |
| `MAX_MODEL_LEN` | `16384` | Tổng prompt ~3.1K token → rất dư |

Vì `temperature = 0`, các lần thử lại gần như tất định; khác biệt (nếu có) đến từ
**batching không tất định của vLLM**, không phải từ nhiệt độ. `attempts.json` ghi rõ điều này.

## A.2 · Bắt buộc phải cài `json_repair`

`article_io_cache_parser._robust_json_parse()` gọi `import json_repair` để đọc marker
`#Entity_List_Start#` / `#Relationship_List_Start#`, và **3 chỗ** bọc trong
`except Exception: pass` — nuốt luôn `ImportError`.

→ parse hỏng **âm thầm**, `entities` / `relations` = `[]` dù model đã trả kết quả đúng.

Đã đo lại: thiếu `json_repair` thì **cả 6 mẫu chuẩn đều ra 0**; cài vào thì `entity` = 1,
`relation` = 2+1, `broken_json` = 1.

Vì biểu hiện giống hệt "parser hỏng", probe A1 có **3 verdict** riêng:

| verdict | nghĩa | hành động |
|---|---|---|
| `parser_ok` | parser đọc đúng cả 6 mẫu | chạy tiếp |
| `missing_json_repair` | **không phải lỗi code** — chỉ thiếu package | `pip install json-repair` |
| `parser_broken` | `json_repair` đã có mà vẫn sai | lỗi trong `_robust_json_parse` |

`out/run_grid_colab.py` cài `json-repair` (51 kB) **trước** khi probe nên trên Colab
luôn ra `parser_ok`.

> **Bài học chung:** `except Exception: pass` quanh `import` biến "thiếu dependency"
> thành "kết quả rỗng" — rất khó chẩn đoán. Gặp kết quả rỗng thì kiểm tra dependency
> trước khi nghi ngờ model.

## A.3 · Cấu trúc `out/grid_raw/`

```text
out/grid_raw/
├── procedure_map.json     procedure → {chunk, technique_id, tactic, grid_dir}
├── manifest.json          cấu hình lần chạy + số entity/relation từng lần chạy
├── run.log                log toàn bộ
├── vllm_calls.jsonl       mỗi lần gọi LLM: token, finish_reason, truncated, lỗi
├── diagnosis.md           báo cáo chẩn đoán A1
├── template_debug/        prompt + output thô bóc từ _TemplateDebug/*.jsonl
├── aggregate/             lần chạy gộp cả 7 procedure
└── proc_01_T1486/ … proc_07_T1036.001/
```

Mỗi thư mục lần chạy có 11 file:

| File | Nội dung |
|---|---|
| `input.txt` | Đúng văn bản đã gửi model (đã bỏ dòng tiêu đề) |
| `prompt_step1.json` / `prompt_step2.json` | Prompt đầy đủ mà GRID dựng ra |
| `step1_raw.txt` / `step2_raw.txt` | **Output thô** của model từng bước |
| `raw_output.txt` | Output GRID dựng lại (xem cảnh báo) |
| `raw_output.NOTE.txt` | Giải thích khác biệt ở trên |
| `entities.json` / `triplets.json` | **Kết quả đã parse — dữ liệu Phần B dùng** |
| `attempts.json` | Từng lần thử: số entity/relation, độ dài output, verdict, lỗi |

> ⚠️ **`raw_output.txt` KHÔNG phải output thô của model.** Nó do
> `GRID_backbone._build_final_split_output()` dựng lại từ `final_entities` /
> `final_relations` **sau khi đã parse**. Muốn xem model thực sự sinh ra gì thì đọc
> `step1_raw.txt` / `step2_raw.txt`.

> `relation.json` (tên ở lần chạy cũ) vẫn được ghi lại cho tương thích, và Phần B vẫn
> đọc được cả hai tên — nên không cần chạy lại nếu đã tải `grid_raw/` từ lần trước.

## A.4 · B1 — Ánh xạ type (`out/type_mapping.json`)

Đọc từ `src/grid/GRID_backbone.py` (`ENTITY_TYPES`, `REL_TYPES`): **33 entity type** và
**44 relation type**.

Từ vựng quan hệ đo được trong `enterprise-attack.json` chỉ có 6 giá trị: `uses`,
`mitigates`, `detects`, `subtechnique-of`, `revoked-by`, `attributed-to`. Mọi
`attack_relationship` đều nằm trong 6 giá trị này.

| Nhóm | `mapped` | `alias` | `approximate` | `unmapped` | Tổng |
|---|---:|---:|---:|---:|---:|
| entity type | 8 | 2 | 11 | 12 | 33 |
| relation type | 3 | 0 | 6 | 35 | 44 |

**Cần người nghiên cứu duyệt:** mọi mục `approximate` là đề xuất gần nhất, chưa chắc đúng
ngữ nghĩa. Mọi mục `unmapped` giữ nguyên tên GRID và gắn cờ `unmapped` — **không có gì bị xoá**.

## A.5 · B2 — Khớp entity với ATT&CK

4 bước theo thứ tự:

1. Mã technique trong văn bản (regex, vd `T1112`) → nối vào node technique có sẵn.
2. Khớp `malware` / `tool` / `intrusion-set` theo tên và alias.
3. Khớp `attack-pattern` theo tên.
4. Không khớp được → tạo node mới `grid:<Tên>`.

Mơ hồ (nhiều object cùng tên) hoặc không có → **để trống `external_id` và tạo node mới**,
không đoán. Node mới gắn `layer = "report"`, không đưa vào lớp nền.

## A.6 · B3 — Cạnh `uses` suy ra bằng code

Mỗi procedure: chủ thể được trích nối cạnh `uses` tới `technique_id` của procedure đó.

Gắn `source = "grid"`, **`inferred_by = "code"`**, kèm câu bằng chứng (nguyên văn procedure)
và số chunk.

> Đây là **suy ra bằng code, KHÔNG phải model trích** — tách riên để không nhầm.

## A.7 · B4 — Triple do model trích

Mỗi triple GRID phải có câu bằng chứng chứa **cả chủ thể lẫn đối tượng** trong văn bản báo
cáo. Tìm theo vòng chính xác, rồi vòng gần đúng (`found_partial_name`, lưu
`evidence_matched_words`).

| `evidence_status` | Nghĩa |
|---|---|
| `found` | Tìm được câu chứa cả hai |
| `found_partial_name` | Chỉ khớp gần đúng — ghi kèm từ đã khớp |
| `no_evidence_sentence` | Không tìm được câu nào |
| `insufficient_name` / `self_reference` | Tên quá ngắn, hoặc câu chỉ nhắc lại chính nó |

Không tìm được → gắn cờ. **KHÔNG xoá triple.** Không bổ sung kiến thức ngoài văn bản.

## A.8 · B5 — `out/kg_full.json` và nạp Neo4j

Định dạng giống hệt `kg.json` (`nodes` / `triples`), nên nạp bằng **cùng một lệnh**:

```powershell
python phuong_phap_2\attack_kg_neo4j.py --scoped phuong_phap_2\kg_base_scoped.json --kg out\kg_full.json --report-name report_1 --password MAT_KHAU
```

Lớp nền **không đổi**. Phân biệt trong `kg_full.json`:

| `source` / `inferred_by` | Nghĩa |
|---|---|
| `attack` | Cạnh `part_of` lấy từ bundle ATT&CK (tầng 2 dùng lại) |
| `grid` + `inferred_by: "code"` | Cạnh `USES` **suy ra bằng code** (B3) |
| `grid` + `inferred_by: "grid"` | Triple **do model GRID trích** (B4) |

Node/cạnh lớp GRID có `source = "grid"`, `layer = "grid"`. Trường `negation` không phải
cạnh thật: cạnh đó gắn `not_an_edge = true` để người dùng quyết định.

---

## 13. Tình trạng hiện tại

| Phần | Trạng thái |
|---|---|
| A1 chẩn đoán | ✅ Chạy được offline. Kết luận: `raw_output.txt` không phải output thô; nguyên nhân số 1 (thiếu `json_repair`) đã tái hiện và khắc phục; giả thuyết "cắt output" đã loại. |
| A2 checkpoint | ✅ Bảng kích thước đo từ HuggingFace API. |
| A3 / A4 chạy GRID | ❌ **CHƯA CHẠY** — cần GPU. `out/grid_raw/` hiện chỉ có `diagnosis.md`. |
| B1 ánh xạ type | ✅ Đã sinh `out/type_mapping.json`, **đang chờ duyệt** các mục `approximate`. |
| B2–B5 ghép KG | ❌ **CHƯA CHẠY** — cần `out/grid_raw/` từ Colab. `out/kg_full.json` chưa được sinh. |
| Loader Neo4j (B5) | ✅ Đã sửa, `--dry-run` đã kiểm tra với cả `kg.json` và `kg_full.json` (fixture tổng hợp). |
| Self-check | ✅ `out/selfcheck_part_b.py` — dùng fixture tổng hợp, **không phải kết quả thật**. |

> **Không có con số nào trong tài liệu này là ước lượng.** Mọi số đều từ lần chạy thật.
> Những phần phụ thuộc kết quả GRID được ghi rõ là *chưa chạy*.
