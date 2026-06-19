#!/bin/bash
# attack_synthetic_unknown.sh
# Generates random/synthetic attack patterns to test detection of novel/unknown attacks
# Combines multiple attack characteristics in non-standard ways
# Usage: ./attack_synthetic_unknown.sh <target_ip> [duration_seconds]

TARGET_IP="${1:-192.168.64.2}"
DURATION="${2:-30}"

echo "=========================================="
echo "Starting Synthetic Unknown Attacks"
echo "Target: $TARGET_IP"
echo "Duration: ${DURATION} seconds"
echo "=========================================="

if ! command -v hping3 &> /dev/null; then
    echo "hping3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y hping3
fi

echo "[*] Generating random attack patterns..."
echo "[*] These attacks blend multiple characteristics to simulate unknown attack types"
echo ""

# Hybrid Attack 1: ACK flood with unusual packet sizes
echo "[Attack 1/5] ACK Flood with variable packet sizes (10 sec)..."
sudo hping3 -A -p 8080 -i u5000 "$TARGET_IP" &
PID1=$!
sleep 10
kill -9 $PID1 2>/dev/null
echo "[✓] Completed"

sleep 2

# Hybrid Attack 2: RST flood (connection reset attacks)
echo "[Attack 2/5] RST Flood - Connection Reset attacks (8 sec)..."
sudo hping3 -R -i u5000 -p 443 "$TARGET_IP" &
PID2=$!
sleep 8
kill -9 $PID2 2>/dev/null
echo "[✓] Completed"

sleep 2

# Hybrid Attack 3: FIN scan variant (slow stealth scan)
echo "[Attack 3/5] FIN Scan variant - Slow stealth detection evasion (12 sec)..."
sudo hping3 -F -p 22,80,443,3306,5432 --interval 100 $TARGET_IP &
PID3=$!
sleep 12
kill -9 $PID3 2>/dev/null
echo "[✓] Completed"

sleep 2

# Hybrid Attack 4: Mixed flag combinations (PSH+URG)
echo "[Attack 4/5] Mixed flag attack - PSH+URG combinations (10 sec)..."
sudo hping3 -P -U -p 9000-9010 -i u5000 "$TARGET_IP" &
PID4=$!
sleep 10
kill -9 $PID4 2>/dev/null
echo "[✓] Completed"

sleep 2

# Hybrid Attack 5: Slow-rate distributed patterns
echo "[Attack 5/5] Slow-rate pattern attack - Mimics botnet behavior (8 sec)..."
for i in {1..40}; do
    sudo hping3 -S -p $((RANDOM % 60000 + 1024)) --interval 200 $TARGET_IP &
done
sleep 8
killall hping3 2>/dev/null
echo "[✓] Completed"

echo ""
echo "=========================================="
echo "Synthetic unknown attacks completed"
echo "Check inference service for detections"
echo "=========================================="
