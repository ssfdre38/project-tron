#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Start the Tron model inference server (llama-server direct — bypasses Ollama engine overhead).

.DESCRIPTION
    Runs llama-server.exe directly with the tron-model GGUF, providing an OpenAI-compatible
    /v1/chat/completions endpoint. This gets ~18 t/s on CPU vs ~4 t/s through Ollama 0.24.x
    due to a regression in Ollama's --ollama-engine path for Gemma 4 architecture.

    Tron's appsettings.json should point to http://localhost:11435 (not Ollama's 11434).

.PARAMETER Model
    Path to the GGUF model file. Defaults to searching common locations.

.PARAMETER LlamaServerPath
    Path to llama-server executable. Defaults to searching PATH and common locations.

.PARAMETER Port
    Port to listen on. Default: 11435 (avoids conflict with Ollama on 11434).

.PARAMETER Threads
    CPU threads. Default: auto-detected (logical core count).

.PARAMETER Host
    Bind address. Default: 127.0.0.1 (local only). Use 0.0.0.0 for network access.

.PARAMETER CtxSize
    Context window tokens. Default: 8192.

.EXAMPLE
    .\start-tron-server.ps1
    # Auto-detects llama-server and model, starts on port 11435

.EXAMPLE
    .\start-tron-server.ps1 -Model "D:\models\tron-model-v1.gguf" -Port 11435
    # Use fine-tuned model after training

.EXAMPLE
    .\start-tron-server.ps1 -LlamaServerPath "C:\llama.cpp\llama-server.exe" -Threads 8
#>
param(
    [string]$Model      = "",
    [string]$LlamaServerPath = "",
    [int]$Port          = 11435,
    [int]$Threads       = 0,
    [string]$BindHost   = "127.0.0.1",
    [int]$CtxSize       = 8192,
    [switch]$FlashAttn  = $true,
    [switch]$Verbose    = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Locate llama-server ---
if (-not $LlamaServerPath) {
    $candidates = @(
        # Relative to this script's location
        (Join-Path $PSScriptRoot "..\..\llama-cpp\llama-server.exe"),
        # gemma4-turbo-family (user's own build)
        "C:\Users\$env:USERNAME\gemma4-turbo-family\llama-cpp\llama-server.exe",
        # Common install locations
        "C:\llama.cpp\llama-server.exe",
        "C:\Program Files\llama.cpp\llama-server.exe",
        "$env:LOCALAPPDATA\llama.cpp\llama-server.exe"
    )
    # Also check PATH
    $inPath = Get-Command "llama-server" -ErrorAction SilentlyContinue
    if ($inPath) { $candidates = @($inPath.Source) + $candidates }

    $LlamaServerPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $LlamaServerPath) {
        Write-Error @"
llama-server not found. Options:
  1. Pass -LlamaServerPath <path>
  2. Add llama-server to PATH
  3. Download llama.cpp from https://github.com/ggml-org/llama.cpp/releases
     and place llama-server.exe in: model\llama-cpp\llama-server.exe
"@
        exit 1
    }
}
Write-Host "[tron-server] Using llama-server: $LlamaServerPath"

# --- Locate model ---
if (-not $Model) {
    $modelCandidates = @(
        # Fine-tuned model (preferred if it exists)
        (Join-Path $PSScriptRoot "..\training\output\tron-model-v1.gguf"),
        # Base Gemma4 E2B IQ4_XS
        "C:\Users\$env:USERNAME\gemma4-turbo-family\gemma4-e2b-iq4xs-turbo.gguf",
        "C:\Users\$env:USERNAME\gemma4-turbo-family\gemma4-e4b-iq4xs-turbo.gguf",
        "$env:USERPROFILE\gemma4-turbo-family\gemma4-e2b-iq4xs-turbo.gguf"
    )
    $Model = $modelCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $Model) {
        Write-Error @"
Model GGUF not found. Options:
  1. Pass -Model <path-to-gguf>
  2. Download a compatible GGUF and place it in: model\training\output\tron-model-v1.gguf
  3. Download gemma4-e2b from https://ollama.com/ssfdre38/gemma4-turbo
     or from Hugging Face and specify with -Model
"@
        exit 1
    }
}
Write-Host "[tron-server] Using model: $Model"

# --- Auto-detect thread count ---
if ($Threads -eq 0) {
    $cpu = Get-CimInstance Win32_Processor
    # Use all logical cores — better for prompt processing (pp), negligible diff for generation (tg)
    $Threads = $cpu.NumberOfLogicalProcessors
    Write-Host "[tron-server] Auto-detected $($cpu.NumberOfCores) physical / $Threads logical cores"
}

# --- Check port availability ---
$portInUse = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Warning "[tron-server] Port $Port is already in use. Is a tron-server instance already running?"
    Write-Warning "  Stop it with: Stop-Process -Id (Get-NetTCPConnection -LocalPort $Port -State Listen).OwningProcess"
    exit 1
}

# --- Build args ---
$args = @(
    "--model",        $Model,
    "--threads",      $Threads,
    "--ctx-size",     $CtxSize,
    "--host",         $BindHost,
    "--port",         $Port,
    "--batch-size",   512,
    "--ubatch-size",  512,
    "--n-predict",    -1,
    "--no-mmap"              # Ensures model is fully in RAM — more consistent inference timing
)

if ($FlashAttn) {
    $args += @("--flash-attn", "on")
}

if ($Verbose) {
    $args += "--verbose-prompt"
} else {
    $args += "--log-disable"   # Suppress per-token logs for clean output
}

# --- Print config summary ---
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗"
Write-Host "║          TRON Model Inference Server             ║"
Write-Host "╠══════════════════════════════════════════════════╣"
Write-Host "║  Endpoint : http://${BindHost}:${Port}/v1/chat/completions"
Write-Host "║  Model    : $(Split-Path $Model -Leaf)"
Write-Host "║  Threads  : $Threads"
Write-Host "║  Context  : $CtxSize tokens"
Write-Host "║  Flash    : $FlashAttn"
Write-Host "╚══════════════════════════════════════════════════╝"
Write-Host ""
Write-Host "[tron-server] Configure Tron: `"Ai`": { `"EndpointUrl`": `"http://localhost:$Port`", `"Model`": `"tron-model`" }"
Write-Host "[tron-server] Starting..."
Write-Host ""

# --- Launch ---
& $LlamaServerPath @args
