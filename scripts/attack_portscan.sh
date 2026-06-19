#!/bin/bash
# attack_portscan.sh
# Port scan attack using nmap
# Usage: ./attack_portscan.sh <target_ip>

TARGET_IP="${1:-192.168.64.2}"

echo "=========================================="
echo "Starting Port Scan Attack"
echo "Target: $TARGET_IP"
echo "=========================================="

if ! command -v nmap &> /dev/null; then
    echo "nmap not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y nmap
fi

echo "[*] Scanning all TCP ports on $TARGET_IP..."
nmap -p- -sS $TARGET_IP 2>&1 | tee -a /tmp/attack_log.txt

echo "[*] Scanning common UDP ports..."
nmap -p 53,67,68,123,161,162,500,5353 -sU $TARGET_IP 2>&1 | tee -a /tmp/attack_log.txt

echo "[*] Port scan completed at $(date)"
