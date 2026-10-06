#!/usr/bin/env bash
# Service commands only. All guided installation lives in the Launcher.
set -euo pipefail
runtime_scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$runtime_scripts/runtime-common.sh"

show_help() {
    printf '%s\n' 'Usage: ./setup.sh [command]' \
        'No arguments: universal Launcher (API-target profile suggested).' \
        'Service commands: status, start, stop, restart, logs, rebuild' \
        'Explicit scan commands: scan <url> [schema_url], results <scan_id>' \
        'Uninstall: uninstall --yes (stops this service; preserves configuration and reports)' \
        'Direct setup: configure .env, then ./scripts/install-runtime.sh.' \
        'Compatibility: ./setup.sh --standalone runs the direct backend; there is no component wizard.'
}

cmd_status() {
    "${COMPOSE[@]}" ps bugtrace-api
    info "REST: http://localhost:$API_PORT"
    info "MCP:  http://localhost:$MCP_PORT/mcp"
}

cmd_scan() {
    local target="${1:-}"
    local schema_url="${2:-}"

    if [[ -z "$target" ]]; then
        error "Usage: ./setup.sh scan <target_url> [schema_url]"
        echo -e "  ${DIM}Example: ./setup.sh scan https://api.example.com${NC}"
        echo -e "  ${DIM}Example: ./setup.sh scan https://api.example.com https://api.example.com/openapi.json${NC}"
        exit 1
    fi

    command -v python3 >/dev/null || { error "python3 is required for scan/result commands."; return 1; }
    local payload
    payload=$(python3 -c 'import json,sys; d={"target":sys.argv[1]}; d.update({"schema_url":sys.argv[2]} if sys.argv[2] else {}); print(json.dumps(d))' "$target" "$schema_url")

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
    command -v python3 >/dev/null || { error "python3 is required for scan/result commands."; return 1; }
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

main() {
    local command="${1:-}"
    case "$command" in
        help|--help|-h) show_help; return 0 ;;
        start|stop|restart|status|logs|rebuild|scan|results|uninstall) shift ;;
        *) error "Unknown service command: $command"; show_help; return 2 ;;
    esac
    case "$command" in
        uninstall) [[ $# -eq 1 && "$1" == --yes ]] || {
            error 'To stop/remove this service, run ./setup.sh uninstall --yes.'
            error 'Configuration, reports, provider settings and volumes will be preserved.'; return 2;
        } ;;
        scan) [[ $# -ge 1 && $# -le 2 ]] || { error 'Usage: ./setup.sh scan <url> [schema_url]'; return 2; } ;;
        results) [[ $# -eq 1 ]] || { error 'Usage: ./setup.sh results <scan_id>'; return 2; } ;;
        *) [[ $# -eq 0 ]] || { error 'This command accepts no extra arguments.'; return 2; } ;;
    esac
    api_prepare_runtime
    case "$command" in
        start|rebuild) exec bash "$runtime_scripts/install-runtime.sh" ;;
        stop) "${COMPOSE[@]}" stop bugtrace-api ;;
        restart)
            "${COMPOSE[@]}" restart bugtrace-api
            api_verify_ready
            success 'BugTraceAI-API restarted and verified.' ;;
        logs) "${COMPOSE[@]}" logs -f bugtrace-api ;;
        status) cmd_status ;;
        scan|results)
            command -v curl >/dev/null || { error 'curl is required.'; return 1; }
            API_PORT=$(api_listener_port "$API_PORT")
            "cmd_$command" "$@" ;;
        uninstall)
            "${COMPOSE[@]}" down
            success 'Service removed. Configuration, reports, images and volumes were preserved.' ;;
    esac
}

main "$@"
