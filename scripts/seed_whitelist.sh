#!/bin/bash
# Seed critical infrastructure IPs into the whitelist via API
# Run this BEFORE attack simulations to protect SSH and gateway

set -e

API_URL="${1:-http://localhost:8000}"
GATEWAY="${2:-172.20.10.1}"
TARGET="${3:-172.20.10.2}"
MANAGEMENT="${4:-172.20.10.3}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        OneMoney IDS — Critical IP Whitelist Seeder         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Seeding whitelist with critical infrastructure IPs..."
echo "API: $API_URL"
echo ""

# Helper function to add IP to whitelist
whitelist_ip() {
    local ip=$1
    local reason=$2
    echo "  [*] Whitelisting $ip ($reason)..."
    curl -s -X POST "$API_URL/api/whitelist" \
        -H "Content-Type: application/json" \
        -d "{\"ip\": \"$ip\", \"reason\": \"$reason\"}" | jq -r '.message // .detail // "OK"' 2>/dev/null || echo "Added"
}

# Whitelist critical IPs
whitelist_ip "$GATEWAY" "gateway"
whitelist_ip "$TARGET" "protected target - SSH safe"
whitelist_ip "$MANAGEMENT" "management interface"
whitelist_ip "127.0.0.1" "loopback"

echo ""
echo "✓ Whitelist seeded!"
echo ""
echo "These IPs are now immune to auto-blocking:"
echo "  - $GATEWAY (gateway)"
echo "  - $TARGET (target server)"
echo "  - $MANAGEMENT (management)"
echo ""
echo "Safe to run attacks now:"
echo "  sudo bash ./scripts/run_attack.sh $TARGET syn"
echo ""
