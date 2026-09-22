#!/bin/bash
# BugTraceAI-API Entrypoint

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

KR_BIN="${KR_BIN:-/usr/local/bin/kr}"
X8_BIN="${X8_BIN:-/usr/local/bin/x8}"
WORDLISTS_DIR="${WORDLISTS_DIR:-/opt/kiterunner/wordlists}"
TEXT_WORDLISTS_DIR="${TEXT_WORDLISTS_DIR:-/opt/wordlists}"
PARAMS_DIR="${PARAMS_DIR:-/opt/params}"
: "${MCP_PORT:?MCP_PORT must be supplied by the deployment environment}"
: "${API_PORT:?API_PORT must be supplied by the deployment environment}"

log_info "BugTraceAI-API: Fully Automated API Testing Engine"

# Verify binaries
for tool in "$KR_BIN" "$X8_BIN"; do
    if [ ! -x "$tool" ]; then
        log_warn "Tool binary $tool not found or not executable"
    fi
done

# Check optional Ollama/Apex AI availability
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
APEX_ENABLED="${APEX_ENABLED:-true}"
APEX_MODEL="${APEX_MODEL:-apex-master:latest}"

if [ "$APEX_ENABLED" = "true" ]; then
    if curl -sf --max-time 3 "${OLLAMA_URL}/api/tags" > /dev/null 2>&1; then
        log_info "AI Analysis : Apex enabled — Ollama reachable at ${OLLAMA_URL} (model: ${APEX_MODEL})"
    else
        log_warn "AI Analysis : Ollama not reachable at ${OLLAMA_URL} — scans will run without AI analysis"
    fi
else
    log_info "AI Analysis : disabled (APEX_ENABLED=false)"
fi

log_info "Discovery : kr"
log_info "Attack    : x8, schemathesis, offat, vulnapi"
log_info "Port      : $MCP_PORT"

case "$1" in
    mcp|mcp-server|--mcp)
        shift
        MODE="stdio"
        HOST="0.0.0.0"
        PORT="$MCP_PORT"

        while [[ $# -gt 0 ]]; do
            case "$1" in
                --sse)      MODE="sse" ;;
                --host)     HOST="$2"; shift ;;
                --port)     PORT="$2"; shift ;;
            esac
            shift
        done

        if [ "$MODE" = "sse" ]; then
            log_info "Starting BugTraceAI-API MCP Server (SSE) on ${HOST}:${PORT}"
            exec python3 /opt/bugtrace-api/main.py --sse --host "$HOST" --port "$PORT"
        else
            log_info "Starting BugTraceAI-API MCP Server (STDIO)"
            exec python3 /opt/bugtrace-api/main.py
        fi
        ;;
    kr|kiterunner|x8|schemathesis|offat|vulnapi)
        log_info "Running delegated tool: $*"
        exec "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
