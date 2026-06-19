#!/bin/bash
# run_attack.sh - Flexible attack simulator
# Run individual attacks or combinations with configurable intensity
# Usage: ./run_attack.sh <target_ip> [options]

TARGET_IP="${1:-192.168.64.2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTENSITY="${INTENSITY:-normal}"  # light, normal, heavy

show_help() {
    cat << EOF
╔════════════════════════════════════════════════════════════╗
║      OneMoney IDS - Flexible Attack Simulator              ║
╚════════════════════════════════════════════════════════════╝

USAGE: $0 <target_ip> [attack1] [attack2] ...

TARGET IP:
  192.168.64.2  (default: IDS server)

KNOWN ATTACKS (realistic):
  syn       SYN Flood on port 80
  ssh       SSH Brute Force
  udp       UDP Flood on port 53
  icmp      ICMP Ping Flood
  port      Port Scan

UNKNOWN ATTACKS (novel patterns):
  unknown   Run all unknown attack patterns
  ack       ACK Flood
  rst       RST Flood
  fin       FIN Scan
  psh       PSH+URG anomaly
  slow      Slow-rate botnet

GROUPS:
  known     All known attacks (syn ssh udp icmp port)
  all       Every known + unknown attack

INTENSITY / RISK FLAGS:
  --light     Reduced packets
  --normal    Standard packets (default)
  --heavy     Max packets (aggressive)
  --no-block  Detected & shown as attack, but source is NEVER firewalled
  --low-risk  Shortcut for --light + --no-block

EXAMPLES:
  # Run SYN flood only
  $0 192.168.64.2 syn

  # Run multiple known attacks
  $0 192.168.64.2 syn ssh udp

  # Run EVERYTHING (known + unknown)
  $0 192.168.64.2 all

  # Run all known attacks only
  $0 192.168.64.2 known

  # Low-risk: show as attacks on the dashboard but don't block the IP
  $0 192.168.64.2 --low-risk all
  $0 192.168.64.2 --no-block syn udp

  # Heavy intensity (aggressive, will trigger blocking)
  $0 192.168.64.2 --heavy syn udp icmp
EOF
}

# Parse arguments
if [ -z "$TARGET_IP" ] || [ "$TARGET_IP" == "--help" ] || [ "$TARGET_IP" == "-h" ]; then
    show_help
    exit 0
fi

# Parse flags and collect attack names (flags may appear anywhere after target)
NO_BLOCK="false"
ATTACKS=()
for arg in "${@:2}"; do
    case "$arg" in
        --light)    INTENSITY="light" ;;
        --normal)   INTENSITY="normal" ;;
        --heavy)    INTENSITY="heavy" ;;
        --no-block) NO_BLOCK="true" ;;
        --low-risk) INTENSITY="light"; NO_BLOCK="true" ;;  # gentle + never firewalled
        all)        ATTACKS+=(syn ssh udp icmp port unknown) ;;
        known)      ATTACKS+=(syn ssh udp icmp port) ;;
        --*)        echo "[!] Unknown flag: $arg" ;;
        *)          ATTACKS+=("$arg") ;;
    esac
done

if [ ${#ATTACKS[@]} -eq 0 ]; then
    echo "[!] No attacks specified. Use --help for options"
    echo ""
    echo "Quick start:"
    echo "  $0 $TARGET_IP syn               # Single attack"
    echo "  $0 $TARGET_IP syn ssh udp       # Multiple attacks"
    echo "  $0 $TARGET_IP all               # Every known + unknown attack"
    echo "  $0 $TARGET_IP --low-risk all    # All attacks, detected but never blocked"
    exit 1
fi

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         OneMoney IDS Attack Simulation Suite               ║"
echo "║         Target: $TARGET_IP                         ║"
echo "║         Intensity: $INTENSITY                       ║"
echo "║         No-block (low-risk): $NO_BLOCK              ║"
echo "║         Attacks: ${ATTACKS[*]}                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
if [ "$NO_BLOCK" == "true" ]; then
    echo "[*] LOW-RISK mode: attacks will be DETECTED and shown on the dashboard,"
    echo "    but the inference service will NOT firewall the source during this run."
    echo ""
fi

# Verify connectivity
echo "[*] Verifying connectivity to $TARGET_IP..."
if ! ping -c 1 -W 2 $TARGET_IP &> /dev/null; then
    echo "[!] ERROR: Cannot reach $TARGET_IP"
    exit 1
fi
echo "[✓] Target is reachable"
echo ""

# Set intensity parameters
case "$INTENSITY" in
    light)
        SYN_DURATION=8
        UDP_DURATION=5
        ICMP_DURATION=5
        HPING_RATE="u20000"  # 50 pps
        ;;
    normal)
        SYN_DURATION=15
        UDP_DURATION=10
        ICMP_DURATION=10
        HPING_RATE="u10000"  # 100 pps
        ;;
    heavy)
        SYN_DURATION=20
        UDP_DURATION=15
        ICMP_DURATION=15
        HPING_RATE="u5000"   # 200 pps
        ;;
esac

# Helper function to call API
api_call() {
    local endpoint="$1"
    local data="$2"
    curl -s -X POST "http://${TARGET_IP}:8000${endpoint}" \
        -H "Content-Type: application/json" \
        -d "$data" 2>/dev/null || echo "{}"
}

# Run selected attacks
for ATTACK in "${ATTACKS[@]}"; do
    case "$ATTACK" in
        syn)
            ATTACK_TYPE="SYN_FLOOD"
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  SYN Flood (Port 80) - Duration: ${SYN_DURATION}s               ║"
            echo "║  Time: $(date '+%H:%M:%S')                                    ║"
            echo "╚════════════════════════════════════════════════════════════╝"

            # Log attack start
            RESPONSE=$(api_call "/api/attack-start" "{\"attack_type\":\"$ATTACK_TYPE\",\"target_ip\":\"$TARGET_IP\",\"intensity\":\"$INTENSITY\",\"no_block\":$NO_BLOCK}")
            ATTACK_ID=$(echo $RESPONSE | grep -o '"attack_id":[0-9]*' | grep -o '[0-9]*')
            echo "[*] Attack recorded (ID: $ATTACK_ID)"

            echo "[*] Flooding port 80 with SYN packets..."
            PACKET_COUNT=$((SYN_DURATION * 100))
            sudo hping3 -S -i $HPING_RATE -p 80 $TARGET_IP -c $PACKET_COUNT 2>/dev/null | tail -5

            # Log attack end
            api_call "/api/attack-end" "{\"attack_id\":$ATTACK_ID,\"packets_sent\":$PACKET_COUNT}" > /dev/null
            echo "[✓] SYN flood completed and labeled"
            echo ""
            ;;

        ssh)
            ATTACK_TYPE="SSH_BRUTE"
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  SSH Brute Force                                           ║"
            echo "║  Time: $(date '+%H:%M:%S')                                    ║"
            echo "╚════════════════════════════════════════════════════════════╝"

            RESPONSE=$(api_call "/api/attack-start" "{\"attack_type\":\"$ATTACK_TYPE\",\"target_ip\":\"$TARGET_IP\",\"intensity\":\"$INTENSITY\",\"no_block\":$NO_BLOCK}")
            ATTACK_ID=$(echo $RESPONSE | grep -o '"attack_id":[0-9]*' | grep -o '[0-9]*')
            echo "[*] Attack recorded (ID: $ATTACK_ID)"

            echo "[*] Starting SSH brute force..."
            bash "$SCRIPT_DIR/attack_ssh_brute.sh" $TARGET_IP 2>/dev/null | grep -E "valid|completed"

            api_call "/api/attack-end" "{\"attack_id\":$ATTACK_ID,\"packets_sent\":84}" > /dev/null
            echo "[✓] SSH brute force completed and labeled"
            echo ""
            ;;

        udp)
            ATTACK_TYPE="UDP_FLOOD"
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  UDP Flood (Port 53) - Duration: ${UDP_DURATION}s               ║"
            echo "║  Time: $(date '+%H:%M:%S')                                    ║"
            echo "╚════════════════════════════════════════════════════════════╝"

            RESPONSE=$(api_call "/api/attack-start" "{\"attack_type\":\"$ATTACK_TYPE\",\"target_ip\":\"$TARGET_IP\",\"intensity\":\"$INTENSITY\",\"no_block\":$NO_BLOCK}")
            ATTACK_ID=$(echo $RESPONSE | grep -o '"attack_id":[0-9]*' | grep -o '[0-9]*')
            echo "[*] Attack recorded (ID: $ATTACK_ID)"

            echo "[*] Flooding port 53 with UDP packets..."
            PACKET_COUNT=$((UDP_DURATION * 100))
            sudo hping3 -2 -i $HPING_RATE -p 53 $TARGET_IP -c $PACKET_COUNT 2>/dev/null | tail -5

            api_call "/api/attack-end" "{\"attack_id\":$ATTACK_ID,\"packets_sent\":$PACKET_COUNT}" > /dev/null
            echo "[✓] UDP flood completed and labeled"
            echo ""
            ;;

        icmp)
            ATTACK_TYPE="ICMP_FLOOD"
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  ICMP Flood (Ping) - Duration: ${ICMP_DURATION}s               ║"
            echo "║  Time: $(date '+%H:%M:%S')                                    ║"
            echo "╚════════════════════════════════════════════════════════════╝"

            RESPONSE=$(api_call "/api/attack-start" "{\"attack_type\":\"$ATTACK_TYPE\",\"target_ip\":\"$TARGET_IP\",\"intensity\":\"$INTENSITY\",\"no_block\":$NO_BLOCK}")
            ATTACK_ID=$(echo $RESPONSE | grep -o '"attack_id":[0-9]*' | grep -o '[0-9]*')
            echo "[*] Attack recorded (ID: $ATTACK_ID)"

            echo "[*] Flooding with ICMP packets..."
            PACKET_COUNT=$((ICMP_DURATION * 100))
            sudo hping3 -1 -i $HPING_RATE $TARGET_IP -c $PACKET_COUNT 2>/dev/null | tail -5

            api_call "/api/attack-end" "{\"attack_id\":$ATTACK_ID,\"packets_sent\":$PACKET_COUNT}" > /dev/null
            echo "[✓] ICMP flood completed and labeled"
            echo ""
            ;;

        port)
            ATTACK_TYPE="PORT_SCAN"
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  Port Scan                                                 ║"
            echo "║  Time: $(date '+%H:%M:%S')                                    ║"
            echo "╚════════════════════════════════════════════════════════════╝"

            RESPONSE=$(api_call "/api/attack-start" "{\"attack_type\":\"$ATTACK_TYPE\",\"target_ip\":\"$TARGET_IP\",\"intensity\":\"$INTENSITY\",\"no_block\":$NO_BLOCK}")
            ATTACK_ID=$(echo $RESPONSE | grep -o '"attack_id":[0-9]*' | grep -o '[0-9]*')
            echo "[*] Attack recorded (ID: $ATTACK_ID)"

            echo "[*] Running port scan..."
            bash "$SCRIPT_DIR/attack_portscan.sh" $TARGET_IP 2>/dev/null | grep -E "scan|completed"

            api_call "/api/attack-end" "{\"attack_id\":$ATTACK_ID,\"packets_sent\":1000}" > /dev/null
            echo "[✓] Port scan completed and labeled"
            echo ""
            ;;

        unknown)
            ATTACK_TYPE="UNKNOWN_NOVEL"
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  Unknown Attacks (Novel Patterns)                          ║"
            echo "║  Time: $(date '+%H:%M:%S')                                    ║"
            echo "╚════════════════════════════════════════════════════════════╝"

            RESPONSE=$(api_call "/api/attack-start" "{\"attack_type\":\"$ATTACK_TYPE\",\"target_ip\":\"$TARGET_IP\",\"intensity\":\"$INTENSITY\",\"no_block\":$NO_BLOCK}")
            ATTACK_ID=$(echo $RESPONSE | grep -o '"attack_id":[0-9]*' | grep -o '[0-9]*')
            echo "[*] Attack recorded (ID: $ATTACK_ID)"

            echo "[*] Running unknown attack patterns..."
            if [ -f "$SCRIPT_DIR/attack_synthetic_unknown.sh" ]; then
                bash "$SCRIPT_DIR/attack_synthetic_unknown.sh" $TARGET_IP 2>/dev/null | tail -10
            else
                echo "[!] Unknown attacks script not found"
            fi

            api_call "/api/attack-end" "{\"attack_id\":$ATTACK_ID,\"packets_sent\":5000}" > /dev/null
            echo "[✓] Unknown attacks completed and labeled"
            echo ""
            ;;

        *)
            echo "[!] Unknown attack: $ATTACK"
            echo "Run with --help for valid attacks"
            ;;
    esac

    # Wait between attacks
    if [ "$ATTACK" != "${ATTACKS[-1]}" ]; then
        echo "[*] Waiting 3 seconds before next attack..."
        sleep 3
    fi
done

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║     All Selected Attacks Completed Successfully            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "✓ Attacks sent! Check the dashboard for detections:"
echo "  http://localhost:5173 → Flow Predictor → Live Stream"
echo ""
