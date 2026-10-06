#!/usr/bin/env bash
# Compatibility alias. Installation opens the Launcher; commands manage this service.
set -euo pipefail
installer_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
    ''|--standalone) exec bash "$installer_dir/install.sh" "$@" ;;
    *) exec bash "$installer_dir/scripts/service.sh" "$@" ;;
esac
