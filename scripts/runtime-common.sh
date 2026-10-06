#!/usr/bin/env bash
# Shared service/runtime operations. Configuration is read by Compose, never sourced.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
# Packaged API tools currently target amd64; scope the override to this engine.
COMPOSE=(env DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose --project-directory "$SCRIPT_DIR" --env-file "$ENV_FILE" -f "$COMPOSE_FILE")
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
CYAN='\033[0;36m' BOLD='\033[1m' DIM='\033[2m' NC='\033[0m'
OK="${GREEN}✓${NC}"
info() { printf '%s\n' "$*"; }
success() { printf '%s\n' "$*"; }
error() { printf '%s\n' "$*" >&2; }

api_prepare_runtime() {
    [[ -f "$ENV_FILE" ]] || {
        error 'Missing .env. Copy .env.example to .env and configure the ports first.'
        error 'Use ./install.sh for guided setup through the universal Launcher.'
        return 1
    }
    command -v docker >/dev/null && docker compose version >/dev/null 2>&1 || {
        error 'Docker Compose v2 is required. Use ./install.sh for guided dependency setup.'; return 1;
    }
    docker info >/dev/null 2>&1 || { error 'Docker is unavailable; start your runtime and retry.'; return 1; }
    "${COMPOSE[@]}" config --quiet
    local resolved_environment
    resolved_environment=$("${COMPOSE[@]}" config --environment)
    API_PORT=$(printf '%s\n' "$resolved_environment" | awk -F= '$1=="API_PORT" {print $2}')
    MCP_PORT=$(printf '%s\n' "$resolved_environment" | awk -F= '$1=="MCP_PORT" {print $2}')
    local port
    for port in "$API_PORT" "$MCP_PORT"; do
        [[ "$port" =~ ^[0-9]+$ && ${#port} -le 5 ]] && ((10#$port >= 1 && 10#$port <= 65535)) || {
            error 'API_PORT and MCP_PORT must be valid TCP ports.'; return 1;
        }
    done
    ((10#$API_PORT != 10#$MCP_PORT)) || { error 'REST and MCP need different ports.'; return 1; }
}

api_listener_port() {
    local listener
    listener=$("${COMPOSE[@]}" port bugtrace-api "$1")
    listener="${listener%%$'\n'*}"
    local port="${listener##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || { error 'Could not determine the published service port.'; return 1; }
    printf '%s' "$port"
}

api_verify_ready() {
    command -v curl >/dev/null || { error 'curl is required for readiness checks.'; return 1; }
    API_HOST_PORT=$(api_listener_port "$API_PORT")
    MCP_HOST_PORT=$(api_listener_port "$MCP_PORT")
    curl -fsS --retry 12 --retry-connrefused --retry-delay 2 --max-time 5 \
        "http://127.0.0.1:$API_HOST_PORT/health" >/dev/null
    curl -fsS --max-time 5 "http://127.0.0.1:$API_HOST_PORT/docs" >/dev/null
    local response
    response=$(curl -fsS --retry 12 --retry-connrefused --retry-delay 2 --max-time 10 \
        -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"BugTraceAI-install-check","version":"1.0"}}}' \
        "http://127.0.0.1:$MCP_HOST_PORT/mcp")
    printf '%s\n' "$response" | grep -q '"protocolVersion"' || {
        error 'MCP initialization failed. Check ./setup.sh logs.'; return 1;
    }
}
