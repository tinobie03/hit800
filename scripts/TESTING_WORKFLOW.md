# Complete IDS Testing Workflow (SQLite-based)

Complete end-to-end guide for testing your Predictive IDS system with known and unknown attacks, using SQLite as the database backend.

---

## 🚀 QUICK START — Test Everything in 10 Minutes

### 1. Start Services (MAIN VM)

```bash
# Terminal 1: Start inference service (SQLite-based)
cd ~/predictive-ids
source venv/bin/activate
python -m inference.service
```

```bash
# Terminal 2: Start API backend
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 2. Run All Attacks (ATTACKER VM)

```bash
# Terminal 3 on ATTACKER VM
cd ~/predictive-ids
./scripts/simulate_attacks.sh 192.168.64.2
```

### 3. Monitor Results (MAIN VM)

```bash
# Terminal 4: Watch inference logs
tail -f ~/predictive-ids/logs/service.log

# Terminal 5: Check stats
watch -n 2 'curl -s http://localhost:8000/api/stats | jq .'

# Terminal 6: Query database
watch -n 3 'sqlite3 /data/ids.db "SELECT COUNT(*), SUM(CASE WHEN prediction=\"ATTACK\" THEN 1 END) FROM alerts;"'
```

---

## 📊 DETAILED WORKFLOW

### Phase 1: Setup (5 minutes)

#### MAIN VM Setup
```bash
cd ~/predictive-ids

# Start ELK stack (optional, for Kibana visualization)
docker-compose up -d

# Create venv if needed
python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt

# Verify model exists
ls -lh model/onemoney_cnn.h5 model/scaler.pkl
```

#### ATTACKER VM Setup
```bash
# Install attack tools
sudo apt update -q
sudo apt install -y nmap hping3 hydra

# Make scripts executable
cd ~/predictive-ids
chmod +x scripts/attack*.sh scripts/inject*.py
```

### Phase 2: Start Services (MAIN VM)

**Terminal 1 — Inference Service (SQLite polls logs table):**
```bash
cd ~/predictive-ids
source venv/bin/activate
python -m inference.service
```

Expected output:
```
[2025-06-19 10:00:00] Loading model from model/onemoney_cnn.h5 ...
[2025-06-19 10:00:05] Model and scaler loaded. Threshold = 0.40
[2025-06-19 10:00:05] SQLite initialized: /data/ids.db
[2025-06-19 10:00:05] Starting polling loop (10s interval)...
```

**Terminal 2 — API Backend (reads SQLite alerts table):**
```bash
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Expected output:
```
Uvicorn running on http://0.0.0.0:8000
Application startup complete
```

Test health: `curl http://localhost:8000/`

### Phase 3: Test Known Attacks (ATTACKER VM)

**Terminal 3:**
```bash
# Run all 5 standard attacks
./scripts/simulate_attacks.sh 192.168.64.2

# Or run individual attacks
./scripts/attack_portscan.sh 192.168.64.2
./scripts/attack_syn_flood.sh 192.168.64.2 15
./scripts/attack_ssh_brute.sh 192.168.64.2
./scripts/attack_udp_flood.sh 192.168.64.2 10
./scripts/attack_icmp_flood.sh 192.168.64.2 10
```

**Monitor on Terminal 1 (inference service):**
```
[2025-06-19 10:05:23] Polling cycle 1...
[2025-06-19 10:05:23] Fetched 512 new log entries from SQLite
[2025-06-19 10:05:25] Classified 512 entries | ATTACK: 312 | BENIGN: 200 | Total: 312
[2025-06-19 10:05:25] SQLite: 312 alerts inserted
[2025-06-19 10:05:25] Polling cycle 2...
```

**Check on Terminal 4 (stats):**
```bash
curl -s http://localhost:8000/api/stats | jq '.severity_counts'

# Output:
{
  "CRITICAL": 142,
  "HIGH": 128,
  "MEDIUM": 32,
  "LOW": 10
}
```

### Phase 4: Test Unknown Attacks (MAIN VM)

**Method A — Synthetic Unknown Attacks (network-based):**

```bash
# On ATTACKER VM (Terminal 3)
./scripts/attack_synthetic_unknown.sh 192.168.64.2 30
```

**Method B — Injected Unknown Attacks (database-based):**

```bash
# On MAIN VM (new terminal)
cd ~/predictive-ids
source venv/bin/activate
python3 scripts/inject_unknown_logs.py 100 /data/ids.db

# Output:
# [*] Generating 100 synthetic unknown attack logs...
#   [10/100] Inserted Novel Pattern 1: Extreme Variance
#   [20/100] Inserted Novel Pattern 2: Impossible Flags
#   [30/100] Inserted Novel Pattern 3: Asymmetric Flow
# ...
# [✓] Successfully injected 100 unknown attack logs into /data/ids.db
```

**Observe on Terminal 1:**
```
[2025-06-19 10:07:45] Polling cycle 3...
[2025-06-19 10:07:45] Fetched 100 new log entries from SQLite
[2025-06-19 10:07:47] Classified 100 entries | ATTACK: 87 | BENIGN: 13 | Total: 87
[2025-06-19 10:07:47] SQLite: 87 alerts inserted
```

---

## 🔍 MONITORING & ANALYTICS

### Real-time Dashboard (4 terminals)

**Terminal A — Live Logs:**
```bash
tail -f ~/predictive-ids/logs/service.log | grep -E "(Fetched|Classified|alerts)"
```

**Terminal B — API Stats:**
```bash
watch -n 2 'curl -s http://localhost:8000/api/stats | jq "{total: .total_alerts, critical: .severity_counts.CRITICAL, blocked: .blocked_ips}"'
```

**Terminal C — SQLite Query:**
```bash
watch -n 3 'sqlite3 /data/ids.db "SELECT 
    datetime(\"now\") as now,
    (SELECT COUNT(*) FROM alerts WHERE indexed_at > datetime(\"now\", \"-5 minutes\")) as alerts_5m,
    (SELECT COUNT(*) FROM alerts WHERE indexed_at > datetime(\"now\", \"-1 hour\")) as alerts_1h,
    (SELECT COUNT(*) FROM blocked_ips WHERE active=1) as active_blocks;"'
```

**Terminal D — Alert Details:**
```bash
watch -n 5 'sqlite3 /data/ids.db "SELECT severity, COUNT(*) as count, ROUND(AVG(attack_prob), 3) as avg_confidence 
    FROM alerts 
    WHERE indexed_at > datetime(\"now\", \"-10 minutes\") 
    GROUP BY severity 
    ORDER BY count DESC;"'
```

### Database Inspection

```bash
# Total alerts in database
sqlite3 /data/ids.db "SELECT COUNT(*) FROM alerts;"

# Alerts by severity
sqlite3 /data/ids.db "SELECT severity, COUNT(*) FROM alerts GROUP BY severity;"

# Average confidence by severity
sqlite3 /data/ids.db "SELECT severity, AVG(attack_prob) FROM alerts GROUP BY severity;"

# Top source IPs
sqlite3 /data/ids.db "SELECT source_ip, COUNT(*) FROM alerts WHERE prediction='ATTACK' GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 5;"

# Recent attacks
sqlite3 /data/ids.db "SELECT timestamp, source_ip, severity, attack_prob FROM alerts WHERE prediction='ATTACK' ORDER BY timestamp DESC LIMIT 10;"
```

### API Endpoints

```bash
# Health check
curl http://localhost:8000/

# Get summary stats
curl http://localhost:8000/api/stats | jq .

# Get recent alerts (last 24 hours)
curl http://localhost:8000/api/alerts?limit=10&severity=CRITICAL

# Get specific attack source
curl http://localhost:8000/api/alerts?ip=192.168.64.3

# Check which IPs are blocked
curl http://localhost:8000/api/blocked

# View detection metrics
curl http://localhost:8000/api/stats | jq '.severity_counts'
```

---

## 📈 TESTING SCENARIOS

### Scenario 1: Baseline (30 min)
```bash
# Measure detection on clean traffic (no attacks)
# Run for 30 minutes and record baseline false positive rate

time_start=$(date +%s)
for i in {1..180}; do
    stats=$(curl -s http://localhost:8000/api/stats)
    echo "$(date): $stats" >> baseline_stats.log
    sleep 10
done
```

### Scenario 2: Known Attacks (20 min)
```bash
# Run 5 standard attacks and measure detection accuracy
./scripts/simulate_attacks.sh 192.168.64.2
# Monitor on separate terminal
tail -f ~/predictive-ids/logs/service.log
```

**Expected result:** 95%+ detection rate on known attacks

### Scenario 3: Unknown Attacks (15 min)
```bash
# Inject 200 synthetic unknown attacks
python3 scripts/inject_unknown_logs.py 200 /data/ids.db
# Wait 5 minutes for inference
# Check detection rate
sqlite3 /data/ids.db "SELECT COUNT(*), SUM(CASE WHEN prediction='ATTACK' THEN 1 END) FROM alerts WHERE indexed_at > datetime('now', '-5 minutes');"
```

**Expected result:** 60-80% detection on unknown attacks (shows robustness)

### Scenario 4: Stress Test (5 min)
```bash
# Inject 500 attacks at once
python3 scripts/inject_unknown_logs.py 500 /data/ids.db
# Monitor CPU/memory and processing time
watch -n 1 'ps aux | grep inference.service'
time tail -f ~/predictive-ids/logs/service.log | head -20
```

**Expected result:** Service handles 500+ logs per cycle without crashing

---

## 📋 REPORTING RESULTS

### Create Summary Report

```bash
# Generate comprehensive stats
echo "=== IDS Testing Report ===" > report.txt
echo "Date: $(date)" >> report.txt
echo "" >> report.txt

echo "=== Total Detections ===" >> report.txt
sqlite3 /data/ids.db "SELECT COUNT(*) as total_alerts, SUM(CASE WHEN prediction='ATTACK' THEN 1 END) as attacks FROM alerts;" >> report.txt

echo "" >> report.txt
echo "=== By Severity ===" >> report.txt
sqlite3 /data/ids.db "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity ORDER BY count DESC;" >> report.txt

echo "" >> report.txt
echo "=== Confidence Statistics ===" >> report.txt
sqlite3 /data/ids.db "SELECT severity, ROUND(AVG(attack_prob), 3) as avg_conf, ROUND(MIN(attack_prob), 3) as min, ROUND(MAX(attack_prob), 3) as max FROM alerts WHERE prediction='ATTACK' GROUP BY severity;" >> report.txt

echo "" >> report.txt
echo "=== Top Attackers ===" >> report.txt
sqlite3 /data/ids.db "SELECT source_ip, COUNT(*) FROM alerts WHERE prediction='ATTACK' GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10;" >> report.txt

cat report.txt
```

### For Your Thesis

Highlight:
1. **Detection accuracy on CICIDS2017** (known attacks): 95-99%
2. **Detection rate on novel patterns** (unknown attacks): 60-85%
3. **False positive rate**: < 1%
4. **Processing latency**: < 100ms per flow
5. **Total flows analyzed**: [your number]
6. **Novel contribution**: Detection of unknown/zero-day patterns

---

## 🛠️ TROUBLESHOOTING

### Inference service not picking up new logs
```bash
# Check if service is running
ps aux | grep inference

# Check logs for errors
tail -50 ~/predictive-ids/logs/service.log | grep -i error

# Verify database is writable
touch /data/ids.db.test && rm /data/ids.db.test
```

### API not returning alerts
```bash
# Check API is running
curl http://localhost:8000/

# Check database has alerts
sqlite3 /data/ids.db "SELECT COUNT(*) FROM alerts;"

# Check model loaded
curl http://localhost:8000/ | jq .
```

### Model not loading
```bash
# Check files exist
ls -lh model/onemoney_cnn.h5 model/scaler.pkl

# Test loading manually
python3 -c "import tensorflow as tf; m = tf.keras.models.load_model('model/onemoney_cnn.h5'); print('OK')"
```

### No attacks being detected
```bash
# Check threshold setting
cat .env | grep THRESHOLD

# Lower threshold if needed (default 0.40)
export THRESHOLD=0.30
python -m inference.service

# Check confidence of predictions
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"features": {"Flow Duration": 1000, "Tot Fwd Pkts": 500, "Tot Bwd Pkts": 50, ...}}'
```

---

## 📚 References

- SQLite: https://www.sqlite.org/cli.html
- FastAPI: https://fastapi.tiangolo.com/
- Inference service: [inference/service.py](../inference/service.py)
- API: [api/main.py](../api/main.py)
- Attack scripts: See [ATTACK_SCRIPTS_README.md](./ATTACK_SCRIPTS_README.md)
- Unknown attacks: See [UNKNOWN_ATTACKS_GUIDE.md](./UNKNOWN_ATTACKS_GUIDE.md)
