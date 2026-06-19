# Attack Simulation Scripts

This directory contains scripts for simulating network attacks against the IDS. Use these to test the detection capabilities of the system.

## Quick Start

Run all 5 attacks sequentially:

```bash
# On the ATTACKER VM
cd ~/predictive-ids
chmod +x scripts/*.sh
./scripts/simulate_attacks.sh 192.168.64.2
```

Replace `192.168.64.2` with your main IDS VM's IP address.

## Individual Attack Scripts

Each attack can also be run independently:

### 1. Port Scan (`attack_portscan.sh`)
**What it does:** Scans all TCP and UDP ports on the target

```bash
./scripts/attack_portscan.sh 192.168.64.2
```

**Tools:** nmap  
**Duration:** ~2-3 minutes  
**Target ports:** All TCP ports + common UDP ports  
**Detection:** Port scan activity in network logs  

---

### 2. SYN Flood (`attack_syn_flood.sh`)
**What it does:** Floods port 80 with SYN packets (simulates DDoS)

```bash
./scripts/attack_syn_flood.sh 192.168.64.2 15
```

**Parameters:**
- `192.168.64.2` — Target IP
- `15` — Duration in seconds (default: 15)

**Tools:** hping3  
**Duration:** Configurable (default 15 seconds)  
**Target port:** 80 (HTTP)  
**Detection:** High rate of SYN packets, abnormal packet ratios  

---

### 3. SSH Brute Force (`attack_ssh_brute.sh`)
**What it does:** Attempts SSH login with common usernames/passwords

```bash
./scripts/attack_ssh_brute.sh 192.168.64.2
```

**Tools:** hydra  
**Duration:** ~30 seconds - 2 minutes depending on response  
**Target port:** 22 (SSH)  
**Credentials tried:**
- Users: root, admin, ubuntu, bella, attacker, test
- Passwords: password, 123456, admin, letmein, welcome, qwerty, root, toor, test, ubuntu, bella, attacker, pass123, pass

**Detection:** Multiple failed SSH login attempts, high connection attempts  

---

### 4. UDP Flood (`attack_udp_flood.sh`)
**What it does:** Floods DNS port with UDP packets (simulates DNS amplification attack)

```bash
./scripts/attack_udp_flood.sh 192.168.64.2 10
```

**Parameters:**
- `192.168.64.2` — Target IP
- `10` — Duration in seconds (default: 10)

**Tools:** hping3  
**Duration:** Configurable (default 10 seconds)  
**Target port:** 53 (DNS)  
**Detection:** High volume of UDP traffic, abnormal packet size/rate patterns  

---

### 5. ICMP Flood (`attack_icmp_flood.sh`)
**What it does:** Floods target with ICMP echo requests (ping flood)

```bash
./scripts/attack_icmp_flood.sh 192.168.64.2 10
```

**Parameters:**
- `192.168.64.2` — Target IP
- `10` — Duration in seconds (default: 10)

**Tools:** hping3  
**Duration:** Configurable (default 10 seconds)  
**Detection:** High rate of ICMP packets, abnormal ICMP/Echo ratios  

---

## Unknown/Synthetic Attacks

### 6. Synthetic Unknown Attacks (`attack_synthetic_unknown.sh`)
**What it does:** Generates random attack patterns that blend multiple characteristics to simulate novel/zero-day attacks

```bash
./scripts/attack_synthetic_unknown.sh 192.168.64.2 30
```

**Parameters:**
- `192.168.64.2` — Target IP
- `30` — Duration in seconds (default: 30)

**Attack patterns:**
1. **ACK Flood with variable sizes** — Connection exhaustion
2. **RST Flood** — Connection reset attacks
3. **FIN Scan variant** — Stealth/evasion attempt
4. **Mixed flag combinations** — PSH+URG patterns
5. **Slow-rate botnet pattern** — Distributed attack simulation

**Tools:** hping3  
**Detection:** Novel flag combinations, unusual timing patterns, unknown attack signatures  

---

### 7. Inject Unknown Logs (`inject_unknown_logs.py`)
**What it does:** Generates synthetic network flow logs with completely random/unknown attack characteristics and injects them directly into SQLite

```bash
# Generate and inject 100 unknown attack logs
python3 inject_unknown_logs.py 100 /data/ids.db

# Or generate 50 logs
python3 inject_unknown_logs.py 50 /data/ids.db
```

**Novel attack patterns generated:**
1. **Extreme Variance** — High packet rate + low variability (unusual)
2. **Impossible Flags** — All TCP flags set simultaneously (never normal)
3. **Asymmetric Flow** — Extreme up/down stream imbalance
4. **Timing Anomaly** — Micro-bursts with macro-level gaps
5. **Protocol Confusion** — Mixed characteristics (novel combinations)

**Tools:** Python (no external tools needed)  
**Duration:** Instant (logs injected directly to SQLite)  
**Detection:** Tests CNN's ability to detect zero-day/novel patterns the model was never trained on  

---

## Master Script: `simulate_attacks.sh`

Runs all 5 standard attacks in sequence with proper timing and logging.

```bash
# Run all attacks with 5-second gaps between each
./scripts/simulate_attacks.sh 192.168.64.2
```

**Sequence:**
1. Port Scan (2-3 min)
2. Wait 5 seconds
3. SYN Flood (15 sec)
4. Wait 5 seconds
5. SSH Brute Force (30 sec - 2 min)
6. Wait 5 seconds
7. UDP Flood (10 sec)
8. Wait 5 seconds
9. ICMP Flood (10 sec)

**Total estimated time:** 5-7 minutes

---

## Prerequisites

The scripts will auto-install required tools, but you may need:

```bash
sudo apt update
sudo apt install -y nmap hping3 hydra netcat-openbsd
```

For scripts to work with `sudo`, you may need to add these to your sudoers:

```bash
sudo visudo
# Add these lines (no password required):
# attacker ALL=(ALL) NOPASSWD: /usr/sbin/hping3
# attacker ALL=(ALL) NOPASSWD: /sbin/iptables
```

---

## Monitoring Detection

While attacks run, monitor detection on the **MAIN VM**:

### Terminal 1: Watch inference service logs
```bash
# For the new SQLite-based service
tail -f ~/predictive-ids/logs/service.log

# Or for older Elasticsearch-based inference
tail -f ~/predictive-ids/logs/inference.log
```

Expected output when attacks occur:
```
Fetched 312 new log entries from SQLite
Classified 312 entries | ATTACK: 47 | BENIGN: 265 | Total attacks: 47
SQLite: 47 alerts inserted
```

### Terminal 2: Check API stats (queries SQLite)
```bash
watch -n 2 'curl -s http://localhost:8000/api/stats | jq .'
```

Example response:
```json
{
  "period_hours": 24,
  "total_alerts": 47,
  "blocked_ips": 3,
  "severity_counts": {
    "CRITICAL": 12,
    "HIGH": 18,
    "MEDIUM": 15,
    "LOW": 2
  },
  "top_attackers": [
    {"ip": "192.168.64.3", "count": 47}
  ],
  "threshold": 0.4
}
```

### Terminal 3: View SQLite alerts directly
```bash
# Query the SQLite database directly
sqlite3 /data/ids.db "SELECT timestamp, source_ip, prediction, severity, attack_prob FROM alerts ORDER BY timestamp DESC LIMIT 20;"
```

### Terminal 4: View Kibana alerts (if ELK stack is running)
Open in browser: `http://192.168.64.2:5601`
- Click **Discover** → Select **ids-alerts** index
- Watch new alerts appear in real-time

---

## Expected Detection Results

| Attack Type | Expected Detections | Severity |
|-------------|-------------------|----------|
| Port Scan | Multiple flag combinations (SYN, ACK variations) | MEDIUM-HIGH |
| SYN Flood | Very high SYN packet rate, abnormal packet ratios | CRITICAL |
| SSH Brute Force | Multiple failed auth attempts, high connection rate | HIGH |
| UDP Flood | High UDP packet rate, abnormal traffic patterns | CRITICAL |
| ICMP Flood | High ICMP packet rate, ping flood patterns | HIGH |
| Synthetic Unknown | Novel flag combinations, unusual patterns | VARIABLE |
| Injected Unknown | Zero-day patterns, asymmetric flows, timing anomalies | MEDIUM-CRITICAL |

---

## Troubleshooting

### "Permission denied" when running hping3
Solution: Use sudo or configure sudoers
```bash
sudo ./scripts/attack_syn_flood.sh 192.168.64.2 15
```

### "Cannot reach target" error
- Verify target IP is correct: `ping 192.168.64.2`
- Check both VMs are on same network (Host Only mode in UTM)
- Verify firewall allows ICMP pings

### Tools not found
Scripts auto-install, but if issues occur:
```bash
sudo apt update && sudo apt install -y nmap hping3 hydra netcat-openbsd
```

### No detections appearing in SQLite
1. Check inference service is running: `tail -f ~/predictive-ids/logs/service.log`
2. Verify SQLite database exists: `ls -lh /data/ids.db`
3. Check alerts table has records: `sqlite3 /data/ids.db "SELECT COUNT(*) FROM alerts;"`
4. Verify API can read alerts: `curl http://localhost:8000/api/stats`
5. Check model is loaded: `curl http://localhost:8000/` (should see model path in response)

---

## Safety Notes

⚠️ **These scripts are for lab testing only:**
- Run only in your own private VM network
- Never run against systems you don't own
- Use Host Only networking (not bridged) to prevent traffic leaving your machine
- Each attack creates legitimate-looking traffic for IDS testing

For production pentesting, use professional tools like Metasploit, Cobalt Strike, or hired penetration testers.

---

## References

- nmap: https://nmap.org/
- hping3: http://www.hping.org/
- hydra: https://github.com/vanhauser-thc/thc-hydra
- CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
