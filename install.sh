#!/usr/bin/env bash
# Single guided entry point. Direct runtime setup is an explicit backend.
set -euo pipefail
installer_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
    '') exec bash "$installer_dir/scripts/launcher-bootstrap.sh" api ;;
    --help|-h|help)
        printf '%s\n' 'Usage: ./install.sh' \
            'Opens the universal Launcher with the API-target engine suggested.' \
            'Direct automation: configure .env, then ./scripts/install-runtime.sh.' \
            'Legacy --standalone delegates to that backend; there is no component wizard.' \
            'Service commands: ./setup.sh --help. See INSTALLATION.md.' ;;
    --standalone)
        shift
        exec bash "$installer_dir/scripts/install-runtime.sh" "$@" ;;
    *) exec bash "$installer_dir/scripts/service.sh" "$@" ;;
esac
