#!/usr/bin/env bash
# =============================================================================
# serve_vllm.sh - Serve agent or monitor model with 10 GB VRAM constraints
#
# Usage:
#   ./scripts/serve_vllm.sh [agent|monitor] [port] [model]
# =============================================================================

set -euo pipefail

# Load .env if present
if [[ -f .env ]]; then
    # shellcheck disable=SC1091
    source .env
fi

ROLE="${1:-agent}"
PORT="${2:-${VLLM_PORT:-8000}}"
CUSTOM_MODEL="${3:-}"

# Resolve vLLM executable
if [[ -n "${VLLM_BIN:-}" && -x "${VLLM_BIN}" ]]; then
    VLLM_EXEC="${VLLM_BIN}"
elif command -v vllm &>/dev/null; then
    VLLM_EXEC="$(command -v vllm)"
else
    echo "ERROR: vLLM executable not found." >&2
    echo "Please set VLLM_BIN (e.g. in .env or via 'export VLLM_BIN=/path/to/vllm')" >&2
    echo "or ensure 'vllm' is installed on your PATH." >&2
    exit 1
fi

EXTRA_FLAGS=""
if [[ -n "${CUSTOM_MODEL}" ]]; then
    MODEL="${CUSTOM_MODEL}"
    UTILIZATION="0.75"
    MAX_LEN="2048"
    if [[ "${MODEL}" == *"AWQ"* || "${MODEL}" == *"awq"* ]]; then
        EXTRA_FLAGS="--enforce-eager"
    fi
elif [[ "${ROLE}" == "agent" ]]; then
    MODEL="Qwen/Qwen2.5-7B-Instruct-AWQ"
    UTILIZATION="0.75"
    MAX_LEN="2048"
    EXTRA_FLAGS="--enforce-eager"
elif [[ "${ROLE}" == "monitor" ]]; then
    MODEL="Qwen/Qwen2.5-0.5B-Instruct"
    UTILIZATION="0.35"
    MAX_LEN="2048"
elif [[ "${ROLE}" == "monitor7b" ]]; then
    MODEL="Qwen/Qwen2.5-7B-Instruct-AWQ"
    UTILIZATION="0.75"
    MAX_LEN="2048"
    EXTRA_FLAGS="--enforce-eager"
else
    echo "Unknown role: ${ROLE}. Must be 'agent', 'monitor', 'monitor7b', or provide a model tag as third argument." >&2
    exit 1
fi

echo "Starting vLLM server for [${ROLE}]..."
echo "  Executable:  ${VLLM_EXEC}"
echo "  Model:       ${MODEL}"
echo "  Port:        ${PORT}"
echo "  VRAM Ratio:  ${UTILIZATION}"
echo "  Max Context: ${MAX_LEN}"
echo "  Extra Flags: ${EXTRA_FLAGS}"

exec "${VLLM_EXEC}" serve "${MODEL}" \
    --host 127.0.0.1 \
    --port "${PORT}" \
    --gpu-memory-utilization "${UTILIZATION}" \
    --max-model-len "${MAX_LEN}" \
    --enable-auto-tool-choice \
    --tool-call-parser hermes \
    ${EXTRA_FLAGS}
