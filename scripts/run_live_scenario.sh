#!/bin/bash
# Generate a controlled mixture of ordinary traffic and gradually escalating attacks.
# Run this from a dedicated lab client/attacker VM, never against a public target.
set -euo pipefail

TARGET_IP="${1:-172.20.10.2}"
SCENARIO="${2:-syn}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API="http://${TARGET_IP}:8000"
NORMAL_PID=""

usage() {
    echo "Usage: $0 <lab-target-ip> [syn|ssh|mixed]"
    echo "Environment: BASELINE_SECONDS=30 NORMAL_DELAY=3 SSH_USER=user SSH_KEY=/path/key"
}

if [ "$TARGET_IP" = "-h" ] || [ "$TARGET_IP" = "--help" ]; then
    usage
    exit 0
fi

case "$SCENARIO" in syn|ssh|mixed) ;; *) usage; exit 2 ;; esac

for command in curl ping; do
    command -v "$command" >/dev/null || { echo "Missing required command: $command"; exit 1; }
done

normal_request_cycle() {
    # Successful API reads, a harmless 404, ICMP, and an optional real SSH login.
    curl -fsS --max-time 2 "$API/api/health" >/dev/null 2>&1 || true
    curl -fsS --max-time 2 "$API/api/stats?hours=24" >/dev/null 2>&1 || true
    curl -fsS --max-time 2 "$API/api/alerts?limit=5&hours=1" >/dev/null 2>&1 || true
    curl -sS --max-time 2 "$API/not-a-real-route" >/dev/null 2>&1 || true
    ping -c 1 -W 1 "$TARGET_IP" >/dev/null 2>&1 || true

    if [ -n "${SSH_USER:-}" ] && [ -n "${SSH_KEY:-}" ] && [ -r "$SSH_KEY" ]; then
        ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=2 \
            -o StrictHostKeyChecking=accept-new "$SSH_USER@$TARGET_IP" true \
            >/dev/null 2>&1 || true
    elif command -v nc >/dev/null; then
        nc -z -w 2 "$TARGET_IP" 22 >/dev/null 2>&1 || true
    fi
}

normal_traffic_loop() {
    while true; do
        normal_request_cycle
        sleep "${NORMAL_DELAY:-3}"
    done
}

cleanup() {
    if [ -n "$NORMAL_PID" ]; then
        kill "$NORMAL_PID" >/dev/null 2>&1 || true
        wait "$NORMAL_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "[1/4] Baseline: ordinary HTTP, ICMP, and SSH-handshake traffic"
normal_traffic_loop &
NORMAL_PID=$!
sleep "${BASELINE_SECONDS:-30}"

echo "[2/4] Low-rate suspicious phase; normal traffic continues in parallel"
case "$SCENARIO" in
    syn|mixed) "$SCRIPT_DIR/run_attack.sh" "$TARGET_IP" --light syn ;;
    ssh)       "$SCRIPT_DIR/run_attack.sh" "$TARGET_IP" --light ssh ;;
esac

echo "[3/4] Observation window: inference should accumulate evidence, not block on one event"
sleep 20

echo "[4/4] Escalation phase; repeated evidence may now cross the block policy"
case "$SCENARIO" in
    syn)   "$SCRIPT_DIR/run_attack.sh" "$TARGET_IP" --normal syn || true ;;
    ssh)   "$SCRIPT_DIR/run_attack.sh" "$TARGET_IP" --normal ssh || true ;;
    mixed) "$SCRIPT_DIR/run_attack.sh" "$TARGET_IP" --normal syn udp icmp || true ;;
esac

sleep 15
echo "Scenario complete. Expected stream: BENIGN baseline → ATTACK evidence → BLOCKED after threshold."
echo "If the final API request fails, verify the source in the Blocked IPs panel from another host."
