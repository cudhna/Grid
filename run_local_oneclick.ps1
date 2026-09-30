#Requires -Version 5.1
<#
.SYNOPSIS
    Cài model + chạy GRID (tầng 3) ngay trên máy Windows, KHÔNG cần GPU.

.DESCRIPTION
    Một lệnh duy nhất làm hết 6 việc:
      1. Tải model GGUF từ HuggingFace về $ModelsDir   (giống snapshot_download của Colab)
      2. Tải + giải nén llama-server.exe (llama.cpp, bản CPU x64)
      3. Khởi động llama-server nền (OpenAI-compatible)
      4. Chờ endpoint /v1/models sẵn sàng
      5. Đặt biến môi trường GRID_MODE=external ...
      6. Chạy python out\run_grid_colab.py  (A1 -> A3 -> A4)

    Vì sao dùng llama.cpp chứ không dùng Ollama:
      - Ollama là daemon riêng, tên model trong registry không kiểm soát được,
        dễ vô tình dùng NHẦM bản Qwen3 gốc (có thinking) thay vì bản
        Instruct-2507 đang dùng trên Colab -> sai thiết lập thực nghiệm.
      - GGUF tải đúng 1 file, tự lưu vào đường dẫn mình chọn, không cần registry.

    Vì sao KHÔNG gọi được vLLM ở đây:
      vLLM không có nhánh CPU. Nó chết ngay ở tầng import với
      "libcuda.so.1: cannot open shared object file" chứ không chậm dần.
      Vì vậy chế độ local dùng GRID_MODE=external, script bỏ qua toàn bộ
      bước GPU check + tải vLLM + bật vLLM.

.PARAMETER SkipRun
    Chỉ cài xong rồi dừng, không chạy GRID (để kiểm tra model trước).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\run_local_oneclick.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\run_local_oneclick.ps1 -Ctx 32768 -Threads 6
#>

[CmdletBinding()]
param(
    # Để trống -> tự dò thư mục gốc repo (xử lý ở bên dưới, vì $PSScriptRoot
    # có thể rỗng khi gọi qua `powershell.exe -File`).
    [string]$RepoRoot      = "",
    [string]$ModelsDir     = "E:\models",
    [string]$LlamaDir      = "E:\tools\llama.cpp",
    [string]$GgufFile      = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
    [string]$GgufRepo      = "unsloth/Qwen3-4B-Instruct-2507-GGUF",
    [int]   $Port          = 8080,
    # Ngữ cảnh. GRID dùng ~2,7K token cho prompt Step 1 + ~445 token input,
    # và MAX_NEW_TOKENS=8192 cho output -> 16384 là vừa khít.
    [int]   $Ctx           = 16384,
    # Số luồng CPU. Mặc định lấy số luồng logic của máy.
    [int]   $Threads       = 0,
    [int]   $ReadyTimeoutS = 600,
    # Ngưỡng cỡ model tối thiểu (MB) để coi là tải đủ thay vì tải dở.
    # 2382 MB là cỡ thật của Q4_K_M. Giảm nếu bạn dùng bản quant nhỏ hơn.
    [int]   $MinModelMB    = 2000,
    [switch]$SkipRun
)

# PowerShell 5.1 mặc định có thể chỉ TLS 1.0 -> GitHub API trả lỗi SSL.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ErrorActionPreference = 'Stop'
$Utf8 = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = $Utf8

function Write-Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok   ($m) { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn2($m) { Write-Host "  [CẢNH BÁO] $m" -ForegroundColor Yellow }
function Write-Fail ($m) { Write-Host "  [LỖI]  $m" -ForegroundColor Red }

if ($Threads -le 0) {
    $Threads = [Environment]::ProcessorCount
}

# --------------------------------------------------------------------------
# 0. Chuẩn bị thư mục
# --------------------------------------------------------------------------
Write-Step "0/6 · Chuẩn bị thư mục"

# Dò thư mục gốc repo theo thứ tự độ tin cậy giảm dần.
if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    Write-Fail "Không xác định được thư mục gốc repo. Hãy truyền -RepoRoot <đường dẫn>."
    exit 1
}

Set-Location -Path $RepoRoot
Write-Host "  Repo      : $RepoRoot"
Write-Host "  Model dir : $ModelsDir"
Write-Host "  Llama dir : $LlamaDir"
Write-Host "  Threads   : $Threads  |  Ctx: $Ctx  |  Port: $Port"

foreach ($d in @($ModelsDir, $LlamaDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'out\run_grid_colab.py'))) {
    Write-Fail "Không thấy out\run_grid_colab.py trong $RepoRoot. Chạy script từ thư mục gốc repo."
    exit 1
}
$OutRaw = Join-Path $RepoRoot 'out\grid_raw'
New-Item -ItemType Directory -Path $OutRaw -Force | Out-Null

$GgufPath = Join-Path $ModelsDir $GgufFile
$GgufUrl  = "https://huggingface.co/$GgufRepo/resolve/main/$GgufFile"

# --------------------------------------------------------------------------
# 1. Tải model GGUF (1 lần duy nhất)
# --------------------------------------------------------------------------
Write-Step "1/6 · Tải model GGUF"

# Ngưỡng cỡ để phát hiện file tải dở (curl -C nối tiếp nên file cũng có thể nửa chừng).
$expectedMinBytes = $MinModelMB * 1MB

function Get-RemoteSize($url) {
    try {
        $r = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 60
        $len = $r.Headers['Content-Length']
        if ($len) { return [int64]$len }
    } catch {
        Write-Warn2 "Không HEAD được ($($_.Exception.Message)). Sẽ dùng ngưỡng cỡ tối thiểu."
    }
    return 0
}

# Định dạng GGUF bắt đầu bằng magic "GGUF" (0x47 0x47 0x55 0x46), rồi mới tới
# version (uint32). Bắt buộc kiểm tra magic, KHÔNG chỉ kiểm tra cỡ file.
function Test-GgufMagic($path) {
    if (-not (Test-Path -LiteralPath $path)) { return $false }
    try {
        $fs = [System.IO.File]::OpenRead($path)
        $buf = New-Object byte[] 4
        $n = $fs.Read($buf, 0, 4)
        $fs.Close()
        if ($n -lt 4) { return $false }
        return ($buf[0] -eq 0x47 -and $buf[1] -eq 0x47 -and $buf[2] -eq 0x55 -and $buf[3] -eq 0x46)
    } catch {
        return $false
    }
}

$needDownload = $true
$useResume    = $false

if (Test-Path -LiteralPath $GgufPath) {
    $haveBytes = (Get-Item -LiteralPath $GgufPath).Length
    if (Test-GgufMagic $GgufPath) {
        if ($haveBytes -ge $expectedMinBytes) {
            Write-Ok "Model đã có ($([math]::Round($haveBytes/1MB)) MB), bỏ qua tải: $GgufPath"
            $needDownload = $false
        } else {
            Write-Host "  File GGUF hợp lệ nhưng mới có $([math]::Round($haveBytes/1MB)) MB -> tải tiếp."
            $useResume = $true
        }
    } else {
        # KHÔNG nối tiếp vào file không phải GGUF. curl -C - chỉ ghi tiếp byte,
        # không kiểm tra nguồn, nên file rác -> thành file 2,3 GB hỏng mà
        # llama-server báo lỗi rất khó hiểu:
        #   "this GGUF file is version <số> but this software only supports up to version 3"
        Write-Warn2 "File tồn tại nhưng KHÔNG phải GGUF hợp lệ (magic sai). Xoá để tải lại từ đầu."
        Remove-Item -LiteralPath $GgufPath -Force
        $useResume = $false
    }
}

if ($needDownload) {
    $remote = Get-RemoteSize $GgufUrl
    if ($remote -gt 0) {
        Write-Host ("  Kích thước trên server: {0} MB" -f [math]::Round($remote / 1MB))
    }
    Write-Host "  Nguồn: $GgufUrl"
    Write-Host "  Đang tải... (giữ nguyên cửa sổ này; tải tiếp được nếu mạng đứt)"

    if ($useResume) {
        & curl.exe -L -C - --retry 5 --retry-delay 5 --fail -o $GgufPath $GgufUrl
    } else {
        & curl.exe -L --retry 5 --retry-delay 5 --fail -o $GgufPath $GgufUrl
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "curl tải model thất bại (exit $LASTEXITCODE)."
        Write-Host "  Chạy lại script: file hợp lệ sẽ được tải tiếp, file hỏng sẽ bị xoá tự động."
        exit 1
    }

    if (-not (Test-GgufMagic $GgufPath)) {
        Write-Fail "Tải xong nhưng 4 byte đầu không phải magic GGUF -> file KHÔNG dùng được."
        Write-Host "  Xoá rồi chạy lại:  Remove-Item '$GgufPath' -Force"
        exit 1
    }
    $got = (Get-Item -LiteralPath $GgufPath).Length
    if ($got -lt $expectedMinBytes) {
        Write-Fail "File model quá nhỏ ($([math]::Round($got/1MB)) MB) — tải dở."
        Write-Host "  Chạy lại script để tải tiếp."
        exit 1
    }
    Write-Ok "Tải xong ($([math]::Round($got/1MB)) MB): $GgufPath"
}

# --------------------------------------------------------------------------
# 2. Tải + giải nén llama-server (llama.cpp CPU x64)
# --------------------------------------------------------------------------
Write-Step "2/6 · Chuẩn bị llama-server (llama.cpp)"

function Find-LlamaServer {
    if (Test-Path -LiteralPath (Join-Path $LlamaDir 'llama-server.exe')) {
        return (Join-Path $LlamaDir 'llama-server.exe')
    }
    $hit = Get-ChildItem -Path $LlamaDir -Recurse -Filter 'llama-server.exe' -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $null
}

# Tra URL lúc chạy, KHÔNG hardcode số build.
# Lý do: llama.cpp chỉ đóng gói Windows trong các build nightly dạng tag "bNNNNN".
# Endpoint /releases/latest trả về bản semver (v0.5.0) KHÔNG có file Windows,
# nên phải quét danh sách release gần đây.
function Get-LlamaCppWinZipUrl {
    $headers = @{ 'User-Agent' = 'Grid-local-runner'; 'Accept' = 'application/vnd.github+json' }
    $pattern = 'llama-b*-bin-win-cpu-x64.zip'
    for ($page = 1; $page -le 3; $page++) {
        try {
            $rels = Invoke-RestMethod -Headers $headers `
                    -Uri "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=30&page=$page" `
                    -TimeoutSec 60
        } catch {
            Write-Warn2 "Không đọc được danh sách release (trang $page): $($_.Exception.Message)"
            return $null
        }
        foreach ($rel in $rels) {
            foreach ($a in $rel.assets) {
                if ($a.name -like $pattern) {
                    Write-Ok "Tìm thấy $($a.name) trong release $($rel.tag_name)"
                    return $a.browser_download_url
                }
            }
        }
    }
    return $null
}

$LlamaExe = Find-LlamaServer
if ($LlamaExe) {
    Write-Ok "llama-server đã có: $LlamaExe"
} else {
    $zipUrl = Get-LlamaCppWinZipUrl
    if (-not $zipUrl) {
        Write-Fail "Không tìm thấy gói Windows CPU của llama.cpp."
        Write-Host "  Tải thủ công từ: https://github.com/ggml-org/llama.cpp/releases"
        Write-Host "  Chọn file tên dạng llama-b<so>-bin-win-cpu-x64.zip, giải nén vào: $LlamaDir"
        Write-Host "  Rồi chạy lại script này."
        exit 1
    }
    $zip = Join-Path $env:TEMP 'llama-bin-win-cpu-x64.zip'
    Write-Host "  Đang tải $zipUrl"
    & curl.exe -L --retry 5 --retry-delay 5 --fail -o $zip $zipUrl
    if ($LASTEXITCODE -ne 0) { Write-Fail "Tải llama.cpp thất bại (exit $LASTEXITCODE)."; exit 1 }

    Write-Host "  Đang giải nén vào $LlamaDir"
    Expand-Archive -LiteralPath $zip -DestinationPath $LlamaDir -Force
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

    $LlamaExe = Find-LlamaServer
    if (-not $LlamaExe) { Write-Fail "Giải nén xong nhưng không thấy llama-server.exe."; exit 1 }
    Write-Ok "Đã cài: $LlamaExe"
}

# --------------------------------------------------------------------------
# 3. Khởi động llama-server
# --------------------------------------------------------------------------
Write-Step "3/6 · Khởi động llama-server"

$baseUrl  = "http://localhost:$Port/v1"
$srvLog   = Join-Path $LlamaDir 'server.log'
$errLog   = Join-Path $LlamaDir 'server.err.log'

function Test-EndpointAlive($url) {
    try {
        $r = Invoke-RestMethod -Uri "$url/models" -Method Get -TimeoutSec 5
        return $r
    } catch { return $null }
}

$existing = Test-EndpointAlive $baseUrl
$reuse = $false
if ($existing -and $existing.data) {
    $ids = @($existing.data | ForEach-Object { $_.id })
    if ($ids -contains $GgufFile) {
        Write-Ok "Server đang chạy sẵn ở $baseUrl với đúng model -> dùng lại."
        $reuse = $true
    } else {
        Write-Warn2 "Port $Port đang phục vụ model khác: $($ids -join ', ')"
        Write-Fail "Đổi -Port sang số khác, hoặc tắt tiến trình đang chiếm port."
        exit 1
    }
}

if (-not $reuse) {
    Get-Process -Name 'llama-server' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # --alias: llama.cpp trả "id" trong /v1/models đúng bằng chuỗi này.
    #   Bắt buộc, vì preflight_endpoint() của run_grid_colab.py dừng (exit 3)
    #   nếu tên model cấu hình không nằm trong danh sách server đang phục vụ.
    # -np 1: llama.cpp mặc định chia context cho nhiều slot. Prompt GRID ~2,7K
    #   token, nếu context bị chia còn ~2K/slot thì request sẽ vượt cửa sổ ngữ cảnh.
    # --n-gpu-layers 0: ép chạy CPU hoàn toàn (máy này không có GPU NVIDIA).
    $serverArgs = @(
        '-m', ('"' + $GgufPath + '"'),
        '-c', "$Ctx",
        '-np', '1',
        '--alias', $GgufFile,
        '--threads', "$Threads",
        '--n-gpu-layers', '0',
        '--host', '127.0.0.1',
        '--port', "$Port"
    )
    Write-Host "  $LlamaExe $($serverArgs -join ' ')"

    Start-Process -FilePath $LlamaExe -ArgumentList $serverArgs `
                  -WorkingDirectory (Split-Path -Parent $LlamaExe) `
                  -WindowStyle Hidden `
                  -RedirectStandardOutput $srvLog `
                  -RedirectStandardError  $errLog | Out-Null
    Write-Ok "Đã khởi động (log: $srvLog)"

    Write-Step "4/6 · Chờ endpoint sẵn sàng (tối đa $ReadyTimeoutS giây)"
    $deadline = (Get-Date).AddSeconds($ReadyTimeoutS)
    $ready = $null
    while ((Get-Date) -lt $deadline) {
        $ready = Test-EndpointAlive $baseUrl
        if ($ready -and $ready.data) { break }
        # Server chết ngay (sai tham số / thiếu DLL) thì không chờ mãi.
        if (-not (Get-Process -Name 'llama-server' -ErrorAction SilentlyContinue)) {
            Write-Fail "llama-server đã thoát ngay. Xem log:"
            if (Test-Path $errLog) { Get-Content $errLog -Tail 25 | ForEach-Object { Write-Host "      $_" } }
            exit 1
        }
        Start-Sleep -Seconds 3
    }
    if (-not ($ready -and $ready.data)) {
        Write-Fail "Endpoint chưa sẵn sàng sau $ReadyTimeoutS giây. Xem $srvLog và $errLog."
        exit 1
    }
    Write-Ok "Endpoint sẵn sàng: $baseUrl"
}

$served = @((Test-EndpointAlive $baseUrl).data | ForEach-Object { $_.id })
Write-Host "  Server đang phục vụ: $($served -join ', ')"

# --------------------------------------------------------------------------
# 5. Đặt biến môi trường cho GRID
# --------------------------------------------------------------------------
Write-Step "5/6 · Cấu hình GRID (chế độ external)"

if ($served -notcontains $GgufFile) {
    Write-Fail "Server không phục vụ đúng '$GgufFile'. Thực tế: $($served -join ', ')"
    exit 1
}

$env:GRID_MODE             = 'external'
$env:VLLM_URL              = $baseUrl
$env:VLLM_API_KEY          = 'EMPTY'
$env:VLLM_MODEL_NAME       = $GgufFile
# CPU chậm hơn nhiều lần so với T4: một procedure có thể mất hàng chút giờ.
$env:VLLM_REQUEST_TIMEOUT  = '3600'

Write-Host "  GRID_MODE            = $env:GRID_MODE"
Write-Host "  VLLM_URL             = $env:VLLM_URL"
Write-Host "  VLLM_MODEL_NAME      = $env:VLLM_MODEL_NAME"
Write-Host "  VLLM_REQUEST_TIMEOUT = $env:VLLM_REQUEST_TIMEOUT"
Write-Ok "Chế độ external: không kiểm tra GPU, không tải vLLM, không bật vLLM."

if ($SkipRun) {
    Write-Host "`nĐã cài xong (-SkipRun). Chạy GRID bằng lệnh:"
    Write-Host "  `$env:GRID_MODE='external'; `$env:VLLM_URL='$baseUrl'; `$env:VLLM_MODEL_NAME='$GgufFile'"
    Write-Host "  python out\run_grid_colab.py"
    exit 0
}

# --------------------------------------------------------------------------
# 6. Chạy GRID
# --------------------------------------------------------------------------
Write-Step "6/6 · Chạy GRID (A1 -> A3 -> A4)"
Write-Host "  Kết quả ghi vào: $OutRaw"
Write-Host "  Ước tính trên CPU: vài giờ cho 8 lần chạy (1 aggregate + 7 procedure)."
Write-Host "  Có thể đóng cửa sổ này; server vẫn chạy nền."
Write-Host ""

python (Join-Path $RepoRoot 'out\run_grid_colab.py')
$code = $LASTEXITCODE

Write-Host ""
if ($code -eq 0) {
    Write-Ok "GRID chạy xong. Kiểm tra $OutRaw"
} else {
    Write-Fail "GRID dừng với exit code $code. Xem $OutRaw\run.log"
}
exit $code