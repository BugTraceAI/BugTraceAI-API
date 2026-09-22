#!/usr/bin/env bash
#
# BugTraceAI-API Setup Wizard
# Interactive installer for the autonomous API security testing engine
#
# Usage:
#   ./setup.sh              Interactive setup wizard
#   ./setup.sh status       Show service status
#   ./setup.sh start        Start the engine
#   ./setup.sh stop         Stop the engine
#   ./setup.sh restart      Restart the engine
#   ./setup.sh logs         View logs (live)
#   ./setup.sh scan <url>   Launch a scan from CLI
#   ./setup.sh results <id> Get scan results
#   ./setup.sh rebuild      Rebuild Docker image
#   ./setup.sh uninstall    Remove everything
#

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "unknown")"
CONTAINER_NAME="bugtrace-api"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"

# Defaults
DEFAULT_API_PORT=8005
DEFAULT_MCP_PORT=8004
DEFAULT_OLLAMA_URL="http://localhost:11434"
DEFAULT_APEX_MODEL="apex-master:latest"
DEFAULT_APEX_MIN_SEVERITY="high"

# State from wizard
API_PORT=""
MCP_PORT=""
OLLAMA_URL=""
APEX_MODEL=""
APEX_MIN_SEVERITY=""
APEX_ENABLED=""
NETWORK_MODE=""
MENU_SELECTION=0

# Platform
IS_MACOS=false
[[ "$(uname)" == "Darwin" ]] && IS_MACOS=true

# ── Colors & Symbols ────────────────────────────────────────────────────────

RED='\033[0;31m'    GREEN='\033[0;32m'  YELLOW='\033[1;33m'
BLUE='\033[0;34m'   CYAN='\033[0;36m'   BOLD='\033[1m'
DIM='\033[2m'       NC='\033[0m'
OK="${GREEN}✓${NC}" FAIL="${RED}✗${NC}" ARROW="${CYAN}➜${NC}"

# ── Logging ──────────────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }
step()    { echo -e "  ${ARROW} $1"; }

# ── Banner ───────────────────────────────────────────────────────────────────

show_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'BANNER'

   ██████╗ ████████╗ █████╗ ██╗       █████╗ ██████╗ ██╗
   ██╔══██╗╚══██╔══╝██╔══██╗██║      ██╔══██╗██╔══██╗██║
   ██████╔╝   ██║   ███████║██║█████╗███████║██████╔╝██║
   ██╔══██╗   ██║   ██╔══██║██║╚════╝██╔══██║██╔═══╝ ██║
   ██████╔╝   ██║   ██║  ██║██║      ██║  ██║██║     ██║
   ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝      ╚═╝  ╚═╝╚═╝     ╚═╝

BANNER
    echo -e "${NC}"
    echo -e "       ${BOLD}BugTraceAI-API v${VERSION}${NC}"
    echo -e "    Autonomous API Security Testing Engine"
    echo ""
}

# ── Utilities ────────────────────────────────────────────────────────────────

to_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

port_available() {
    local port=$1
    if $IS_MACOS; then
        ! lsof -i ":$port" -sTCP:LISTEN &>/dev/null
    else
        ! (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -q ":$port "
    fi
}

find_free_port() {
    local port=$1
    local max=$((port + 50))
    while [[ $port -lt $max ]]; do
        if port_available "$port"; then
            echo "$port"
            return 0
        fi
        ((port++))
    done
    return 1
}

propose_port() {
    local label=$1 default=$2 result_var=$3
    local attempts=0
    local port

    port=$(find_free_port "$default") || port=$default

    while [[ $attempts -lt 3 ]]; do
        echo ""
        echo -e "  ${BOLD}$label${NC}: ${CYAN}$port${NC}"
        echo -en "  ${YELLOW}Accept? [Y] / n=next / or type a port: ${NC}"
        read -r answer

        case "$(to_lower "$answer")" in
            ""|y|yes)
                printf -v "$result_var" '%s' "$port"
                return 0
                ;;
            n|no)
                ((attempts++))
                port=$(find_free_port $((port + 1))) || {
                    error "No free ports found"
                    exit 1
                }
                ;;
            *)
                if [[ "$answer" =~ ^[0-9]+$ ]] && [[ "$answer" -ge 1024 ]] && [[ "$answer" -le 65535 ]]; then
                    if port_available "$answer"; then
                        printf -v "$result_var" '%s' "$answer"
                        return 0
                    else
                        warn "Port $answer is already in use"
                        ((attempts++))
                    fi
                else
                    warn "Invalid port number (must be 1024-65535)"
                    ((attempts++))
                fi
                ;;
        esac
    done

    error "Could not configure port for $label after 3 attempts."
    exit 1
}

select_option() {
    local question=$1
    shift
    local options=("$@")
    local total=${#options[@]}

    echo -e "\n${YELLOW}$question${NC}\n"
    for i in "${!options[@]}"; do
        echo -e "  ${CYAN}$((i + 1)))${NC} ${options[$i]}"
    done
    echo ""

    while true; do
        echo -en "${YELLOW}Choice [1-$total]: ${NC}"
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$total" ]]; then
            MENU_SELECTION=$((choice - 1))
            return 0
        fi
        error "Please enter a number between 1 and $total"
    done
}

# ── Dependency Checks ────────────────────────────────────────────────────────

check_docker() {
    step "Checking Docker..."
    if ! command -v docker &>/dev/null; then
        error "Docker is not installed."
        echo -e "  ${DIM}Install: https://docs.docker.com/engine/install/${NC}"
        exit 1
    fi

    if ! docker info &>/dev/null 2>&1; then
        error "Docker daemon is not running."
        echo -e "  ${DIM}Start it with: sudo systemctl start docker${NC}"
        exit 1
    fi

    if ! docker compose version &>/dev/null 2>&1; then
        error "Docker Compose (v2) is not available."
        echo -e "  ${DIM}Install: https://docs.docker.com/compose/install/${NC}"
        exit 1
    fi

    echo -e "  ${OK} Docker $(docker --version | awk '{print $3}' | tr -d ',')"
    echo -e "  ${OK} Docker Compose $(docker compose version --short)"
}

check_ollama() {
    local url="${1:-$DEFAULT_OLLAMA_URL}"
    step "Checking Ollama at ${url}..."

    if ! curl -sf --max-time 3 "${url}/api/tags" > /dev/null 2>&1; then
        warn "Ollama not reachable at ${url}"
        echo -e "  ${DIM}Scans will still work, but AI analysis (Phase 5) will be skipped.${NC}"
        echo -e "  ${DIM}Install Ollama: https://ollama.com/download${NC}"
        return 1
    fi

    local models
    models=$(curl -sf --max-time 5 "${url}/api/tags" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('models', []):
    print(m['name'])
" 2>/dev/null || true)

    echo -e "  ${OK} Ollama is running"

    if [[ -n "$models" ]]; then
        echo -e "  ${DIM}Available models:${NC}"
        while IFS= read -r model; do
            echo -e "    ${DIM}• $model${NC}"
        done <<< "$models"
    fi

    return 0
}

# ── Wizard Steps ─────────────────────────────────────────────────────────────

wizard_network_mode() {
    echo ""
    echo -e "${BOLD}Step 1: Network Mode${NC}"
    echo ""
    echo -e "  ${DIM}BugTraceAI-API needs to reach Ollama (AI) on the host.${NC}"
    echo -e "  ${DIM}Host networking is simpler but exposes ports directly.${NC}"
    echo ""

    select_option "Select Docker network mode:" \
        "Host networking (recommended for Linux — Ollama works out of the box)" \
        "Bridge networking (use if you need port isolation or are on macOS)"

    case $MENU_SELECTION in
        0) NETWORK_MODE="host" ;;
        1) NETWORK_MODE="bridge" ;;
    esac

    success "Network: $NETWORK_MODE"
}

wizard_ports() {
    echo ""
    echo -e "${BOLD}Step 2: Port Configuration${NC}"

    if [[ "$NETWORK_MODE" == "host" ]]; then
        echo -e "  ${DIM}With host networking, ports bind directly to the host interface.${NC}"
    fi

    propose_port "REST API port" $DEFAULT_API_PORT API_PORT
    propose_port "MCP SSE port" $DEFAULT_MCP_PORT MCP_PORT

    success "Ports configured: API=$API_PORT, MCP=$MCP_PORT"
}

wizard_ai_config() {
    echo ""
    echo -e "${BOLD}Step 3: AI Analysis Configuration${NC}"
    echo ""
    echo -e "  ${DIM}BugTraceAI-API can use a local AI model (via Ollama) to${NC}"
    echo -e "  ${DIM}automatically generate PoC exploits for discovered vulnerabilities.${NC}"
    echo -e "  ${DIM}This is optional — scans work perfectly without AI.${NC}"
    echo ""

    select_option "Enable AI-powered PoC generation?" \
        "Yes — Use local Ollama model (requires Ollama installed)" \
        "No  — Run without AI (findings only, no auto-generated PoCs)"

    case $MENU_SELECTION in
        0) APEX_ENABLED="true" ;;
        1) APEX_ENABLED="false" ;;
    esac

    if [[ "$APEX_ENABLED" == "true" ]]; then
        # Ollama URL
        echo ""
        if [[ "$NETWORK_MODE" == "host" ]]; then
            OLLAMA_URL="http://localhost:11434"
            echo -e "  ${DIM}Ollama URL: ${CYAN}$OLLAMA_URL${NC} (host networking → localhost)"
        else
            OLLAMA_URL="http://host.docker.internal:11434"
            echo -e "  ${DIM}Ollama URL: ${CYAN}$OLLAMA_URL${NC} (bridge networking → host.docker.internal)"
        fi

        echo -en "  ${YELLOW}Accept? [Y] or type custom URL: ${NC}"
        read -r answer
        if [[ -n "$answer" && "$(to_lower "$answer")" != "y" && "$(to_lower "$answer")" != "yes" ]]; then
            OLLAMA_URL="$answer"
        fi

        # Check if Ollama is actually reachable
        local ollama_ok=false
        if check_ollama "$OLLAMA_URL"; then
            ollama_ok=true
        fi

        # Model selection
        echo ""
        if $ollama_ok; then
            local models_list
            models_list=$(curl -sf --max-time 5 "${OLLAMA_URL}/api/tags" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('models', []):
    size_gb = m.get('size', 0) / 1073741824
    print(f\"{m['name']} ({size_gb:.1f}GB)\")
" 2>/dev/null || true)

            if [[ -n "$models_list" ]]; then
                echo -e "  ${BOLD}Select AI model:${NC}"
                echo ""

                local model_names=()
                local model_labels=()
                while IFS= read -r line; do
                    local name="${line%% (*}"
                    model_names+=("$name")
                    model_labels+=("$line")
                done <<< "$models_list"

                select_option "Which model to use for PoC generation?" "${model_labels[@]}"
                APEX_MODEL="${model_names[$MENU_SELECTION]}"
            else
                APEX_MODEL="$DEFAULT_APEX_MODEL"
                echo -e "  ${DIM}Using default model: ${CYAN}$APEX_MODEL${NC}"
            fi
        else
            APEX_MODEL="$DEFAULT_APEX_MODEL"
            echo -e "  ${DIM}Using default model: ${CYAN}$APEX_MODEL${NC}"
            echo -e "  ${DIM}(Will be used when Ollama becomes available)${NC}"
        fi

        # Min severity
        echo ""
        select_option "Minimum severity for AI analysis:" \
            "critical — Only analyze CRITICAL findings" \
            "high     — Analyze HIGH and CRITICAL (recommended)" \
            "medium   — Analyze MEDIUM, HIGH, and CRITICAL" \
            "low      — Analyze everything except INFO"

        case $MENU_SELECTION in
            0) APEX_MIN_SEVERITY="critical" ;;
            1) APEX_MIN_SEVERITY="high" ;;
            2) APEX_MIN_SEVERITY="medium" ;;
            3) APEX_MIN_SEVERITY="low" ;;
        esac
    else
        OLLAMA_URL="$DEFAULT_OLLAMA_URL"
        APEX_MODEL="$DEFAULT_APEX_MODEL"
        APEX_MIN_SEVERITY="$DEFAULT_APEX_MIN_SEVERITY"
    fi

    echo ""
    if [[ "$APEX_ENABLED" == "true" ]]; then
        success "AI Analysis: ON (model=$APEX_MODEL, min_severity=$APEX_MIN_SEVERITY)"
    else
        success "AI Analysis: OFF (scan-only mode)"
    fi
}

wizard_show_summary() {
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}         Configuration Summary            ${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Network:      ${CYAN}$NETWORK_MODE${NC}"
    echo -e "  REST API:     ${CYAN}http://localhost:$API_PORT${NC}"
    echo -e "  MCP SSE:      ${CYAN}http://localhost:$MCP_PORT${NC}"
    echo ""
    if [[ "$APEX_ENABLED" == "true" ]]; then
        echo -e "  AI Analysis:  ${GREEN}ENABLED${NC}"
        echo -e "  Ollama URL:   ${CYAN}$OLLAMA_URL${NC}"
        echo -e "  Model:        ${CYAN}$APEX_MODEL${NC}"
        echo -e "  Min Severity: ${CYAN}$APEX_MIN_SEVERITY${NC}"
    else
        echo -e "  AI Analysis:  ${YELLOW}DISABLED${NC}"
    fi
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""

    echo -en "${YELLOW}Proceed with installation? [Y/n]: ${NC}"
    read -r confirm
    if [[ "$(to_lower "${confirm:-y}")" == "n" ]]; then
        warn "Installation cancelled."
        exit 0
    fi
    echo ""
}

# ── Generate Config ──────────────────────────────────────────────────────────

generate_compose() {
    step "Generating docker-compose.yml..."

    local compose="$COMPOSE_FILE"

    cat > "$compose" << EOF
services:
  bugtrace-api:
    build:
      context: .
      dockerfile: Dockerfile
    image: bugtrace-api:latest
    container_name: $CONTAINER_NAME
    restart: unless-stopped
EOF

    if [[ "$NETWORK_MODE" == "host" ]]; then
        cat >> "$compose" << EOF
    # Host networking: ports bind directly, Ollama reachable on localhost
    network_mode: host
EOF
    else
        cat >> "$compose" << EOF
    ports:
      - "${MCP_PORT}:${MCP_PORT}"
      - "${API_PORT}:${API_PORT}"
    extra_hosts:
      - "host.docker.internal:host-gateway"
EOF
    fi

    cat >> "$compose" << EOF
    environment:
      - MCP_PORT=${MCP_PORT}
      - API_PORT=${API_PORT}
      - KR_BIN=/usr/local/bin/kr
      - X8_BIN=/usr/local/bin/x8
      - VULNAPI_BIN=/usr/local/bin/vulnapi
      - WORDLISTS_DIR=/opt/kiterunner/wordlists
      - TEXT_WORDLISTS_DIR=/opt/wordlists
      - PARAMS_DIR=/opt/params
      - REPORTS_DIR=/opt/bugtrace-api/reports
      # AI Analysis
      - APEX_ENABLED=${APEX_ENABLED}
      - OLLAMA_URL=${OLLAMA_URL}
      - APEX_MODEL=${APEX_MODEL}
      - APEX_MIN_SEVERITY=${APEX_MIN_SEVERITY}
    volumes:
      - ./reports:/opt/bugtrace-api/reports
    command: ["mcp", "--sse"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${API_PORT}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
EOF

    success "docker-compose.yml generated"
}

save_config() {
    step "Saving configuration..."

    cat > "$ENV_FILE" << EOF
# BugTraceAI-API Configuration
# Generated by setup wizard on $(date -Iseconds 2>/dev/null || date)
NETWORK_MODE=$NETWORK_MODE
API_PORT=$API_PORT
MCP_PORT=$MCP_PORT
APEX_ENABLED=$APEX_ENABLED
OLLAMA_URL=$OLLAMA_URL
APEX_MODEL=$APEX_MODEL
APEX_MIN_SEVERITY=$APEX_MIN_SEVERITY
EOF

    success "Config saved to .env"
}

# ── Build & Deploy ───────────────────────────────────────────────────────────

build_image() {
    step "Building Docker image (this may take a few minutes)..."
    echo ""

    if ! docker compose -f "$COMPOSE_FILE" build; then
        error "Docker build failed."
        echo -e "  ${DIM}Check the output above for errors.${NC}"
        exit 1
    fi

    echo ""
    success "Docker image built successfully"
}

start_service() {
    step "Starting BugTraceAI-API..."

    docker compose -f "$COMPOSE_FILE" up -d

    # Wait for health
    echo -en "  Waiting for API to be ready"
    local retries=0
    while [[ $retries -lt 20 ]]; do
        if curl -sf --max-time 2 "http://localhost:${API_PORT}/health" > /dev/null 2>&1; then
            echo ""
            success "BugTraceAI-API is running!"
            return 0
        fi
        echo -n "."
        sleep 2
        ((retries++))
    done

    echo ""
    warn "API not responding on port $API_PORT yet (may still be starting)"
    echo -e "  ${DIM}Check logs: ./setup.sh logs${NC}"
}

# ── Deploy ───────────────────────────────────────────────────────────────────

deploy() {
    info "Starting deployment..."
    echo ""

    generate_compose
    save_config
    build_image
    start_service
    show_success
}

show_success() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   BugTraceAI-API installed successfully! 🚀     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}REST API:${NC}   ${CYAN}http://localhost:$API_PORT${NC}"
    echo -e "  ${BOLD}MCP SSE:${NC}    ${CYAN}http://localhost:$MCP_PORT${NC}"

    if [[ "$APEX_ENABLED" == "true" ]]; then
        echo -e "  ${BOLD}AI Model:${NC}   ${CYAN}$APEX_MODEL${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Quick Start:${NC}"
    echo -e "  ${DIM}# Scan an API${NC}"
    echo -e "  curl -X POST http://localhost:$API_PORT/api/scan \\"
    echo -e "    -H 'Content-Type: application/json' \\"
    echo -e "    -d '{\"target\": \"https://api.example.com\"}'"
    echo ""
    echo -e "  ${DIM}# With OpenAPI schema (faster)${NC}"
    echo -e "  curl -X POST http://localhost:$API_PORT/api/scan \\"
    echo -e "    -H 'Content-Type: application/json' \\"
    echo -e "    -d '{\"target\": \"https://api.example.com\", \"schema_url\": \"https://api.example.com/openapi.json\"}'"
    echo ""
    echo -e "  ${DIM}# Check status${NC}"
    echo -e "  curl http://localhost:$API_PORT/api/scan/{scan_id}"
    echo ""
    echo -e "  ${DIM}# Get results (includes AI PoCs if enabled)${NC}"
    echo -e "  curl http://localhost:$API_PORT/api/scan/{scan_id}/results"
    echo ""
    echo -e "  ${DIM}# Or use the shortcut:${NC}"
    echo -e "  ./setup.sh scan https://api.example.com"
    echo ""
    echo -e "  ${BOLD}Management:${NC}"
    echo -e "  ${DIM}./setup.sh status    — Check status${NC}"
    echo -e "  ${DIM}./setup.sh logs      — View live logs${NC}"
    echo -e "  ${DIM}./setup.sh stop      — Stop the engine${NC}"
    echo -e "  ${DIM}./setup.sh restart   — Restart${NC}"
    echo -e "  ${DIM}./setup.sh rebuild   — Rebuild image${NC}"
    echo ""
}

# ── Run Wizard ───────────────────────────────────────────────────────────────

run_wizard() {
    # Restore stdin if piped
    if [ ! -t 0 ] && [ -c /dev/tty ]; then
        exec </dev/tty 2>/dev/null || true
    fi

    show_banner

    # Detect existing installation
    if [[ -f "$ENV_FILE" ]]; then
        warn "BugTraceAI-API is already configured."
        echo ""
        select_option "What would you like to do?" \
            "Reconfigure (run wizard again)" \
            "Rebuild only (keep config, rebuild image)" \
            "Cancel"

        case $MENU_SELECTION in
            0) info "Starting fresh configuration..." ;;
            1) cmd_rebuild; exit 0 ;;
            2) info "Cancelled."; exit 0 ;;
        esac
        echo ""
    fi

    check_docker
    wizard_network_mode
    wizard_ports
    wizard_ai_config
    wizard_show_summary
    deploy
}

# ── Commands ─────────────────────────────────────────────────────────────────

load_config() {
    if [[ -f "$ENV_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$ENV_FILE"
    else
        API_PORT=$DEFAULT_API_PORT
        MCP_PORT=$DEFAULT_MCP_PORT
    fi
}

cmd_status() {
    load_config
    echo ""
    echo -e "${BOLD}BugTraceAI-API Status${NC}"
    echo ""

    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
        local status health
        status=$(docker inspect --format='{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null)
        health=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "N/A")
        echo -e "  Container: ${GREEN}$status${NC} (health: $health)"
        echo -e "  REST API:  ${CYAN}http://localhost:$API_PORT${NC}"
        echo -e "  MCP SSE:   ${CYAN}http://localhost:$MCP_PORT${NC}"

        # Quick API check
        if curl -sf --max-time 2 "http://localhost:${API_PORT}/health" > /dev/null 2>&1; then
            echo -e "  API:       ${GREEN}responding${NC}"
        else
            echo -e "  API:       ${YELLOW}not responding${NC}"
        fi

        # Ollama check
        local ollama_url="${OLLAMA_URL:-$DEFAULT_OLLAMA_URL}"
        if curl -sf --max-time 2 "${ollama_url}/api/tags" > /dev/null 2>&1; then
            echo -e "  Ollama:    ${GREEN}reachable${NC} ($ollama_url)"
        else
            echo -e "  Ollama:    ${YELLOW}not reachable${NC} ($ollama_url)"
        fi
    else
        echo -e "  Container: ${RED}not running${NC}"
        echo -e "  ${DIM}Start with: ./setup.sh start${NC}"
    fi
    echo ""
}

cmd_start() {
    load_config
    info "Starting BugTraceAI-API..."
    docker compose -f "$COMPOSE_FILE" up -d
    success "Started. API at http://localhost:$API_PORT"
}

cmd_stop() {
    info "Stopping BugTraceAI-API..."
    docker compose -f "$COMPOSE_FILE" down
    success "Stopped."
}

cmd_restart() {
    info "Restarting BugTraceAI-API..."
    docker compose -f "$COMPOSE_FILE" down
    docker compose -f "$COMPOSE_FILE" up -d
    success "Restarted. API at http://localhost:${API_PORT:-$DEFAULT_API_PORT}"
}

cmd_logs() {
    docker logs -f "$CONTAINER_NAME" 2>&1
}

cmd_rebuild() {
    info "Rebuilding Docker image..."
    docker compose -f "$COMPOSE_FILE" build --no-cache
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d
    success "Rebuilt and restarted."
}

cmd_scan() {
    load_config
    local target="${1:-}"
    local schema_url="${2:-}"

    if [[ -z "$target" ]]; then
        error "Usage: ./setup.sh scan <target_url> [schema_url]"
        echo -e "  ${DIM}Example: ./setup.sh scan https://api.example.com${NC}"
        echo -e "  ${DIM}Example: ./setup.sh scan https://api.example.com https://api.example.com/openapi.json${NC}"
        exit 1
    fi

    local payload
    if [[ -n "$schema_url" ]]; then
        payload="{\"target\": \"$target\", \"schema_url\": \"$schema_url\"}"
    else
        payload="{\"target\": \"$target\"}"
    fi

    echo -e "${BOLD}Launching scan...${NC}"
    echo ""

    local response
    response=$(curl -sf -X POST "http://localhost:${API_PORT}/api/scan" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1) || {
        error "Failed to connect to API at http://localhost:${API_PORT}"
        echo -e "  ${DIM}Is the engine running? Check: ./setup.sh status${NC}"
        exit 1
    }

    local scan_id
    scan_id=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])" 2>/dev/null)

    echo -e "  ${OK} Scan started"
    echo -e "  ${BOLD}Scan ID:${NC}  ${CYAN}$scan_id${NC}"
    echo -e "  ${BOLD}Target:${NC}   ${CYAN}$target${NC}"
    echo ""
    echo -e "  ${DIM}Track progress:${NC}"
    echo -e "  curl http://localhost:$API_PORT/api/scan/$scan_id"
    echo ""
    echo -e "  ${DIM}Get results:${NC}"
    echo -e "  curl http://localhost:$API_PORT/api/scan/$scan_id/results"
    echo -e "  ${DIM}or:${NC} ./setup.sh results $scan_id"
    echo ""

    # Poll until done
    echo -en "  ${DIM}Waiting for scan to complete"
    while true; do
        sleep 5
        local status
        status=$(curl -sf "http://localhost:${API_PORT}/api/scan/$scan_id" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unknown")

        case "$status" in
            completed)
                echo ""
                echo ""
                success "Scan completed!"
                echo ""
                # Show summary
                curl -sf "http://localhost:${API_PORT}/api/scan/$scan_id/results" | python3 -c "
import sys, json
d = json.load(sys.stdin)
findings = d.get('findings', [])
severity_counts = {}
for f in findings:
    s = (f.get('severity') or 'info').upper()
    severity_counts[s] = severity_counts.get(s, 0) + 1
print(f'  Total findings: {len(findings)}')
for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
    if s in severity_counts:
        print(f'    {s}: {severity_counts[s]}')
ai = d.get('ai_analysis')
if ai and ai.get('pocs_count', 0) > 0:
    print(f'  AI PoCs generated: {ai[\"pocs_count\"]}')
" 2>/dev/null
                echo ""
                echo -e "  ${DIM}Full results: ./setup.sh results $scan_id${NC}"
                return 0
                ;;
            failed|stopped)
                echo ""
                error "Scan $status."
                return 1
                ;;
            *)
                echo -n "."
                ;;
        esac
    done
}

cmd_results() {
    load_config
    local scan_id="${1:-}"

    if [[ -z "$scan_id" ]]; then
        error "Usage: ./setup.sh results <scan_id>"
        exit 1
    fi

    curl -sf "http://localhost:${API_PORT}/api/scan/$scan_id/results" | python3 -m json.tool 2>/dev/null || {
        error "Could not fetch results for scan $scan_id"
        exit 1
    }
}

cmd_uninstall() {
    echo ""
    warn "This will stop the container and remove the Docker image."
    echo -en "${YELLOW}Are you sure? [y/N]: ${NC}"
    read -r confirm
    if [[ "$(to_lower "${confirm:-n}")" != "y" ]]; then
        info "Cancelled."
        exit 0
    fi

    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    docker rmi bugtrace-api:latest 2>/dev/null || true
    rm -f "$ENV_FILE"

    success "BugTraceAI-API removed."
    echo -e "  ${DIM}Source files are still in $SCRIPT_DIR${NC}"
    echo -e "  ${DIM}Reports are still in $SCRIPT_DIR/reports/${NC}"
}

show_help() {
    echo -e "${BOLD}BugTraceAI-API v${VERSION}${NC} — Autonomous API Security Testing Engine"
    echo ""
    echo "Usage: ./setup.sh [command] [args]"
    echo ""
    echo "Commands:"
    echo "  (no args)          Interactive setup wizard"
    echo "  status             Show service status"
    echo "  start              Start the engine"
    echo "  stop               Stop the engine"
    echo "  restart            Restart the engine"
    echo "  logs               View live logs"
    echo "  scan <url> [schema]  Launch a scan and wait for results"
    echo "  results <scan_id>  Get scan results as JSON"
    echo "  rebuild            Rebuild Docker image and restart"
    echo "  uninstall          Remove container and image"
    echo "  help               Show this help"
    echo ""
    echo "Examples:"
    echo "  ./setup.sh                                              # Run wizard"
    echo "  ./setup.sh scan https://api.example.com                 # Quick scan"
    echo "  ./setup.sh scan https://api.example.com /openapi.json   # Scan with schema"
    echo "  ./setup.sh results abc123                               # View results"
    echo ""
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        status)     cmd_status ;;
        start)      cmd_start ;;
        stop)       cmd_stop ;;
        restart)    cmd_restart ;;
        logs)       cmd_logs ;;
        scan)       shift; cmd_scan "$@" ;;
        results)    shift; cmd_results "$@" ;;
        rebuild)    cmd_rebuild ;;
        uninstall)  cmd_uninstall ;;
        help|-h|--help) show_help ;;
        "")         run_wizard ;;
        *)
            error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
