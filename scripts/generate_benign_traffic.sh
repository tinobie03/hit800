#!/bin/bash
# Continuous ordinary lab-client traffic for baseline capture and validation.
set -euo pipefail

TARGET_IP="${1:-172.20.10.2}"
DURATION="${2:-300}"
API="http://${TARGET_IP}:8000"
END_AT=$(( $(date +%s) + DURATION ))

echo "Generating benign traffic to $TARGET_IP for ${DURATION}s"
while [ "$(date +%s)" -lt "$END_AT" ]; do
    curl -fsS --max-time 3 "$API/api/health" >/dev/null 2>&1 || true
    curl -fsS --max-time 3 "$API/api/stats?hours=24" >/dev/null 2>&1 || true
    curl -fsS --max-time 3 "$API/api/alerts?limit=5&hours=1" >/dev/null 2>&1 || true
    curl -sS --max-time 3 "$API/not-a-real-route" >/dev/null 2>&1 || true
    ping -c 1 -W 1 "$TARGET_IP" >/dev/null 2>&1 || true

    if [ -n "${SSH_USER:-}" ] && [ -n "${SSH_KEY:-}" ] && [ -r "$SSH_KEY" ]; then
        ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=3 \
            -o StrictHostKeyChecking=accept-new "$SSH_USER@$TARGET_IP" true \
            >/dev/null 2>&1 || true
    elif command -v nc >/dev/null; then
        nc -z -w 2 "$TARGET_IP" 22 >/dev/null 2>&1 || true
    fi

    sleep "${NORMAL_DELAY:-3}"
done
echo "Benign traffic run complete"
