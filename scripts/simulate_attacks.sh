#!/bin/bash
# simulate_attacks.sh
# Master attack simulation script
# Runs all 5 attack scenarios sequentially against the target IDS VM
# Usage: ./simulate_attacks.sh <target_ip>

TARGET_IP="${1:-192.168.64.2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         OneMoney IDS Attack Simulation Suite               ║"
echo "║         Target: $TARGET_IP                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if [ -z "$TARGET_IP" ] || [ "$TARGET_IP" == "--help" ] || [ "$TARGET_IP" == "-h" ]; then
    echo "Usage: ./simulate_attacks.sh <target_ip>"
    echo ""
    echo "Example:"
    echo "  ./simulate_attacks.sh 192.168.64.2"
    echo ""
    echo "This script runs 5 attack scenarios in sequence:"
    echo "  1. Port Scan       - nmap scans all ports"
    echo "  2. SYN Flood       - floods port 80 for 15 seconds"
    echo "  3. SSH Brute Force - hydra tries common credentials"
    echo "  4. UDP Flood       - floods port 53 for 10 seconds"
    echo "  5. ICMP Flood      - ping flood for 10 seconds"
    echo ""
    exit 0
fi

# Verify we can reach the target
echo "[*] Verifying connectivity to $TARGET_IP..."
if ! ping -c 1 -W 2 $TARGET_IP &> /dev/null; then
    echo "[!] ERROR: Cannot reach $TARGET_IP"
    echo "[!] Please verify the IP address and network connectivity"
    exit 1
fi
echo "[✓] Target is reachable"
echo ""

# Check if individual attack scripts exist
for attack in attack_portscan attack_syn_flood attack_ssh_brute attack_udp_flood attack_icmp_flood; do
    if [ ! -f "$SCRIPT_DIR/${attack}.sh" ]; then
        echo "[!] ERROR: $SCRIPT_DIR/${attack}.sh not found"
        exit 1
    fi
done

echo "[*] All attack scripts found. Starting simulations..."
echo ""

# ─────────────────────────────────────────────────────────────
# Attack 1: Port Scan
# ─────────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ATTACK 1/5: Port Scan                                     ║"
echo "║  Time: $(date)                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
bash "$SCRIPT_DIR/attack_portscan.sh" $TARGET_IP
echo ""
echo "[*] Waiting 5 seconds before next attack..."
sleep 5

# ─────────────────────────────────────────────────────────────
# Attack 2: SYN Flood
# ─────────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ATTACK 2/5: SYN Flood (Port 80)                           ║"
echo "║  Time: $(date)                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
bash "$SCRIPT_DIR/attack_syn_flood.sh" $TARGET_IP 15
echo ""
echo "[*] Waiting 5 seconds before next attack..."
sleep 5

# ─────────────────────────────────────────────────────────────
# Attack 3: SSH Brute Force
# ─────────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ATTACK 3/5: SSH Brute Force                               ║"
echo "║  Time: $(date)                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
bash "$SCRIPT_DIR/attack_ssh_brute.sh" $TARGET_IP
echo ""
echo "[*] Waiting 5 seconds before next attack..."
sleep 5

# ─────────────────────────────────────────────────────────────
# Attack 4: UDP Flood
# ─────────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ATTACK 4/5: UDP Flood (Port 53)                           ║"
echo "║  Time: $(date)                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
bash "$SCRIPT_DIR/attack_udp_flood.sh" $TARGET_IP 10
echo ""
echo "[*] Waiting 5 seconds before next attack..."
sleep 5

# ─────────────────────────────────────────────────────────────
# Attack 5: ICMP Flood
# ─────────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ATTACK 5/5: ICMP Flood (Ping Flood)                       ║"
echo "║  Time: $(date)                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
bash "$SCRIPT_DIR/attack_icmp_flood.sh" $TARGET_IP 10
echo ""

# ─────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║          All Attacks Completed Successfully                ║"
echo "║  Time: $(date)                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 NEXT STEPS:"
echo "   1. Check the inference service logs on the main VM:"
echo "      tail -f ~/predictive-ids/logs/inference.log"
echo ""
echo "   2. View alerts in Kibana:"
echo "      http://192.168.64.2:5601 → Discover → ids-alerts"
echo ""
echo "   3. Check API stats:"
echo "      curl http://192.168.64.2:8000/api/stats"
echo ""
echo "   4. View blocked IPs:"
echo "      curl http://192.168.64.2:8000/api/blocked"
echo ""
echo "⚠️  NOTE: Some attacks require root privileges (hping3 etc)"
echo "   If you see permission errors, run with sudo or check sudoers"
echo ""
