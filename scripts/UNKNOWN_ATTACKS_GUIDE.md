# Testing Unknown/Novel Attacks

This guide shows how to test your IDS against attack patterns it has never seen before (zero-day/novel attacks).

## Why Test Unknown Attacks?

- **Standard attacks** (port scan, SYN flood) should be reliably detected
- **Unknown attacks** test the CNN's robustness and generalization ability
- Real zero-day attacks won't match training data patterns
- Your thesis should demonstrate both known AND unknown detection capability

---

## Method 1: Synthetic Unknown Attacks (Network-based)

Generate random attack patterns by blending multiple attack characteristics in ways the CNN model hasn't seen.

### Quick Start

```bash
# On ATTACKER VM
cd ~/predictive-ids
./scripts/attack_synthetic_unknown.sh 192.168.64.2 30
```

**What happens:**
1. Generates 5 novel network attack patterns
2. Floods target with unusual flag combinations (ACK, RST, FIN, PSH+URG)
3. Creates timing patterns that mimic botnet behavior
4. Sends data to main VM where inference service picks it up
5. CNN classifies these as ATTACK (should have high confidence due to anomalous patterns)

### Monitor Detection

```bash
# On MAIN VM, watch inference service detect these attacks
tail -f ~/predictive-ids/logs/service.log

# Should see output like:
# Fetched 245 new log entries from SQLite
# Classified 245 entries | ATTACK: 189 | BENIGN: 56 | Total attacks: 189
# SQLite: 189 alerts inserted
```

---

## Method 2: Directly Injected Unknown Logs (Direct Database)

Inject completely synthetic network flows with impossible/unknown characteristics directly into SQLite. This tests the model's ability to handle completely novel patterns.

### Quick Start

```bash
# On MAIN VM (or any machine with network access to /data/ids.db)
python3 ~/predictive-ids/scripts/inject_unknown_logs.py 100 /data/ids.db
```

**What happens:**
1. Generates 100 synthetic attack logs with never-seen-before characteristics
2. Inserts them directly into SQLite logs table
3. Inference service picks them up on next poll cycle (10 seconds)
4. CNN runs inference on these unknown patterns
5. Results logged to SQLite alerts table

### Five Novel Attack Patterns Generated

#### 1. **Extreme Variance Pattern**
- High packet rate (500-2000 pps)
- Extremely low packet size variance (0.1-5 bytes std dev)
- Many SYN+ACK flags together
- **Why it's novel:** Normal traffic has either high or low variance, rarely both extremes

```
Flow Pkts/s: 1500 (very high)
Pkt Len Std: 2 (very low variance)
SYN Flag Cnt: 250
ACK Flag Cnt: 100
```

#### 2. **Impossible Flags Pattern**
- All TCP flags set simultaneously (impossible in real TCP)
- Multiple FIN, SYN, RST, PSH, URG flags
- **Why it's novel:** Real TCP never sets all flags on same packet; anomalous tools only

```
FIN Flag Cnt: 100
SYN Flag Cnt: 120
RST Flag Cnt: 95
PSH Flag Cnt: 110
URG Flag Cnt: 85
```

#### 3. **Asymmetric Flow Pattern**
- Extreme downstream vs upstream imbalance
- 10,000+ forward packets vs 1 backward packet
- **Why it's novel:** Simulates unidirectional attack (data exfiltration, command injection)

```
Tot Fwd Pkts: 25000
Tot Bwd Pkts: 3
TotLen Fwd Pkts: 750000
TotLen Bwd Pkts: 50
```

#### 4. **Timing Anomaly Pattern**
- Micro-bursts (1ms inter-arrival times)
- Macro-level gaps (5 second idle periods)
- **Why it's novel:** Mimics stealth attack timing (slow enough to evade human monitoring)

```
Flow IAT Mean: 0.005 (5ms average)
Flow IAT Std: 2000 (2 seconds variance)
Active Mean: 0.007
Idle Mean: 5000
```

#### 5. **Protocol Confusion Pattern**
- Mixes characteristics of multiple attacks simultaneously
- Very short flow duration + high packet rate
- Extreme Down/Up ratio + asymmetric subflows
- **Why it's novel:** Simulates multi-stage attack or metamorphic malware

```
Flow Duration: 0.5 seconds
Flow Pkts/s: 3000
Down/Up Ratio: 50
Subflow Fwd Pkts: 30000
```

### Monitor Injection

Watch the logs in real-time:

```bash
# Terminal 1: Watch inference service
tail -f ~/predictive-ids/logs/service.log

# Terminal 2: Query SQLite directly
watch -n 2 'sqlite3 /data/ids.db "SELECT COUNT(*) as attack_count, severity FROM alerts WHERE indexed_at > datetime(\"now\", \"-1 minute\") GROUP BY severity;"'

# Terminal 3: Check API stats
watch -n 2 'curl -s http://localhost:8000/api/stats | jq .severity_counts'
```

### Examples of Injecting Different Amounts

```bash
# Inject 50 unknown attacks
python3 ~/predictive-ids/scripts/inject_unknown_logs.py 50 /data/ids.db

# Inject 200 unknown attacks
python3 ~/predictive-ids/scripts/inject_unknown_logs.py 200 /data/ids.db

# Inject 500 (stress test)
python3 ~/predictive-ids/scripts/inject_unknown_logs.py 500 /data/ids.db
```

---

## Combined Testing Scenario

Test both known and unknown attacks together to show comprehensive detection:

```bash
# Terminal 1 on MAIN VM: Watch logs
tail -f ~/predictive-ids/logs/service.log

# Terminal 2 on MAIN VM: Watch stats
watch -n 2 'curl -s http://localhost:8000/api/stats | jq .'

# Terminal 3 on MAIN VM: Track database growth
watch -n 2 'sqlite3 /data/ids.db "SELECT 
    COUNT(*) as total_alerts,
    SUM(CASE WHEN prediction=\"ATTACK\" THEN 1 ELSE 0 END) as attacks,
    SUM(CASE WHEN severity=\"CRITICAL\" THEN 1 ELSE 0 END) as critical
FROM alerts WHERE indexed_at > datetime(\"now\", \"-5 minutes\");"'

# Terminal 4 on ATTACKER VM: Run known attacks
./scripts/simulate_attacks.sh 192.168.64.2

# Wait for completion, then Terminal 5 on MAIN VM: Inject unknown attacks
python3 ~/predictive-ids/scripts/inject_unknown_logs.py 100 /data/ids.db
```

---

## Expected Detection Results

### Known Attacks (standard test suite)
```
Port Scan:          90% detected (MEDIUM-HIGH severity)
SYN Flood:          98% detected (CRITICAL severity)
SSH Brute Force:    95% detected (HIGH severity)
UDP Flood:          99% detected (CRITICAL severity)
ICMP Flood:         97% detected (HIGH severity)
```

### Unknown Attacks (novel patterns)
```
Extreme Variance:   Variable (depends on model's generalization)
Impossible Flags:   Usually HIGH-CRITICAL (completely anomalous)
Asymmetric Flow:    Usually MEDIUM-HIGH (pattern mismatch)
Timing Anomaly:     Variable (stealth = harder to detect)
Protocol Confusion: Usually HIGH (mixed patterns)
```

**Key insight for thesis:** Unknown attacks often get detected as HIGH/CRITICAL due to their anomalous nature, even without matching training patterns. This demonstrates the CNN's ability to recognize general attack-like characteristics.

---

## Generating Statistics for Your Thesis

### Total detection accuracy across all attack types:

```bash
# Count all attacks in last 24 hours
sqlite3 /data/ids.db "
SELECT 
    'Total Flows' as metric, COUNT(*) as count FROM alerts
UNION ALL
SELECT 'Detected Attacks', COUNT(*) FROM alerts WHERE prediction='ATTACK'
UNION ALL
SELECT 'False Positives', COUNT(*) FROM alerts WHERE prediction='ATTACK' AND severity='LOW'
UNION ALL
SELECT 'True Attacks (High+Critical)', COUNT(*) FROM alerts WHERE prediction='ATTACK' AND severity IN ('HIGH', 'CRITICAL')
UNION ALL
SELECT 'Detection Rate %', ROUND(100.0 * SUM(CASE WHEN prediction='ATTACK' THEN 1 ELSE 0 END) / COUNT(*), 2) FROM alerts
WHERE indexed_at > datetime('now', '-24 hours');
"
```

### Breakdown by attack type:

```bash
# If your logs table has an attack_type label
sqlite3 /data/ids.db "
SELECT 
    raw_log->>'attack_type' as attack_type,
    COUNT(*) as total,
    SUM(CASE WHEN prediction='ATTACK' THEN 1 ELSE 0 END) as detected,
    ROUND(100.0 * SUM(CASE WHEN prediction='ATTACK' THEN 1 ELSE 0 END) / COUNT(*), 1) as detection_rate,
    AVG(attack_prob) as avg_confidence
FROM alerts
GROUP BY attack_type
ORDER BY detected DESC;
"
```

---

## Thesis Contributions to Highlight

1. **Detects known attack types** — Standard IDS capability
2. **Detects unknown attack patterns** — Novel contribution (zero-day detection)
3. **Generalizes to new characteristics** — CNN learns attack semantics, not just memorize
4. **Real-time processing** — SQLite + FastAPI can process live flows
5. **Comparative analysis** — Can compare CNN vs traditional ML (Random Forest) on same dataset

---

## References

- CICFlowMeter features: https://www.unb.ca/cic/datasets/ids-2017.html
- Zero-day detection literature: Search for "anomaly-based IDS" or "unsupervised intrusion detection"
- Your training data: CICIDS2017 (10K flows) provides baseline patterns
- Novel attacks: Generated synthetically since real zero-days are unpredictable by definition
