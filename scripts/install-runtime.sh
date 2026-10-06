#!/usr/bin/env bash
# Explicit API-target deployment; consumes existing configuration without a wizard.
set -euo pipefail
runtime_scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
    --help|-h)
        printf '%s\n' 'Usage: ./scripts/install-runtime.sh' \
            'Builds this API-target service using an existing .env and docker-compose.yml.' \
            'Preserves configuration, provider settings and reports.' \
            'Guided installation: ./install.sh opens the universal Launcher.'
        exit 0 ;;
    '') [[ $# -eq 0 ]] || { printf 'Unexpected arguments.\n' >&2; exit 2; } ;;
    *) printf 'Unknown option: %s. Run ./scripts/install-runtime.sh --help.\n' "$1" >&2; exit 2 ;;
esac
source "$runtime_scripts/runtime-common.sh"
api_prepare_runtime
# Check before starting a long build.
command -v curl >/dev/null || { error 'curl is required for readiness checks.'; exit 1; }
"${COMPOSE[@]}" up --build -d --wait --wait-timeout 240 bugtrace-api
api_verify_ready
success 'Standalone BugTraceAI-API is ready.'
info "REST: http://localhost:$API_HOST_PORT"
info "MCP:  http://localhost:$MCP_HOST_PORT/mcp"
info 'Configuration and reports were preserved. No target scan was started.'
