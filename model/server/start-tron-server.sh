#!/usr/bin/env bash
# start-tron-server.sh — Tron model inference server (llama-server direct)
# Cross-platform: Linux / macOS
#
# Usage:
#   ./start-tron-server.sh [--model PATH] [--port PORT] [--threads N]
#
# Performance note:
#   Bypasses Ollama's --ollama-engine overhead for Gemma 4 (which runs 4x slower on CPU).
#   Direct llama-server gives ~18 t/s vs ~4 t/s on a 6-core CPU.

set -euo pipefail

MODEL=""
PORT=11435
BIND_HOST="127.0.0.1"
THREADS=0
CTX_SIZE=32768
FLASH_ATTN=1
LLAMA_SERVER=""

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --model)       MODEL="$2"; shift 2 ;;
        --port)        PORT="$2"; shift 2 ;;
        --host)        BIND_HOST="$2"; shift 2 ;;
        --threads)     THREADS="$2"; shift 2 ;;
        --ctx-size)    CTX_SIZE="$2"; shift 2 ;;
        --no-flash)    FLASH_ATTN=0; shift ;;
        --llama-server) LLAMA_SERVER="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# --- Locate llama-server ---
if [[ -z "$LLAMA_SERVER" ]]; then
    CANDIDATES=(
        "$(dirname "$0")/../../llama-cpp/llama-server"
        "/usr/local/bin/llama-server"
        "/usr/bin/llama-server"
        "$HOME/.local/bin/llama-server"
        "$HOME/llama.cpp/build/bin/llama-server"
    )
    for c in "${CANDIDATES[@]}"; do
        if [[ -x "$c" ]]; then LLAMA_SERVER="$c"; break; fi
    done
    if [[ -z "$LLAMA_SERVER" ]]; then
        echo "Error: llama-server not found. Pass --llama-server <path> or add to PATH." >&2
        exit 1
    fi
fi
echo "[tron-server] llama-server: $LLAMA_SERVER"

# --- Locate model ---
if [[ -z "$MODEL" ]]; then
    CANDIDATES=(
        "$(dirname "$0")/../training/output/tron-model-v1.gguf"
        "$HOME/gemma4-turbo-family/gemma4-e2b-iq4xs-turbo.gguf"
        "$HOME/gemma4-turbo-family/gemma4-e4b-iq4xs-turbo.gguf"
    )
    for c in "${CANDIDATES[@]}"; do
        if [[ -f "$c" ]]; then MODEL="$c"; break; fi
    done
    if [[ -z "$MODEL" ]]; then
        echo "Error: Model GGUF not found. Pass --model <path>." >&2
        exit 1
    fi
fi
echo "[tron-server] model: $MODEL"

# --- Auto-detect threads ---
if [[ $THREADS -eq 0 ]]; then
    if command -v nproc &>/dev/null; then
        THREADS=$(nproc)
    elif [[ "$(uname)" == "Darwin" ]]; then
        THREADS=$(sysctl -n hw.logicalcpu)
    else
        THREADS=4
    fi
fi
echo "[tron-server] threads: $THREADS"

# --- Build args ---
ARGS=(
    --model     "$MODEL"
    --threads   "$THREADS"
    --ctx-size  "$CTX_SIZE"
    --host      "$BIND_HOST"
    --port      "$PORT"
    --batch-size 512
    --ubatch-size 512
    --no-mmap
    --log-disable
)
[[ $FLASH_ATTN -eq 1 ]] && ARGS+=(--flash-attn on)

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║          TRON Model Inference Server             ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Endpoint : http://${BIND_HOST}:${PORT}/v1/chat/completions"
echo "║  Model    : $(basename "$MODEL")"
echo "║  Threads  : $THREADS"
echo "║  Context  : $CTX_SIZE tokens"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "[tron-server] Configure Tron: \"Ai\": { \"EndpointUrl\": \"http://localhost:$PORT\", \"Model\": \"tron-model\" }"
echo "[tron-server] Starting..."
echo ""

exec "$LLAMA_SERVER" "${ARGS[@]}"
