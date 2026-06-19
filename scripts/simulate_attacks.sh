#!/bin/bash
# Backward-compatible entry point for the tracked attack runner.
set -euo pipefail

TARGET_IP="${1:-192.168.64.2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$TARGET_IP" = "--help" ] || [ "$TARGET_IP" = "-h" ]; then
    echo "Usage: $0 <target_ip> [run_attack options]"
    echo "Runs all known scenarios through run_attack.sh so API labels are recorded."
    exit 0
fi

exec "$SCRIPT_DIR/run_attack.sh" "$TARGET_IP" "${@:2}" known
