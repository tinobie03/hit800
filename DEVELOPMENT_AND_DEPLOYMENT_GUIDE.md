# Complete Development & Deployment Guide
## From VS Code → UTM VMs → Live Demonstration

---

## **ARCHITECTURE OVERVIEW**

```
YOUR DEVELOPMENT ENVIRONMENT (Mac)
┌────────────────────────────────────────┐
│ VS Code                                │
│ ├─ Edit code                           │
│ ├─ Commit to git                       │
│ └─ Push to local git repo              │
└────────────┬───────────────────────────┘
             │ (git clone / file sync)
             ↓
┌────────────────────────────────────────────────────────────────┐
│ UTM / QEMU (Mac virtualization)                                │
│                                                                │
│ ┌────────────────────┐    ┌────────────────────┐              │
│ │ IDS-Lab VM         │    │ Attacker VM        │              │
│ │ (Ubuntu 24.04 ARM) │    │ (Ubuntu 24.04 ARM) │              │
│ │                    │    │                    │              │
│ │ IP: 192.168.64.4   │    │ IP: 192.168.64.5   │              │
│ │                    │    │                    │              │
│ │ Running:           │    │ Running:           │              │
│ │ ├─ docker-compose │    │ ├─ nmap             │              │
│ │ │ ├─ Elasticsearch│    │ ├─ hydra            │              │
│ │ │ ├─ Logstash     │    │ ├─ hping3           │              │
│ │ │ ├─ Kibana       │    │ ├─ netcat           │              │
│ │ │ ├─ MongoDB      │    │ ├─ custom Python    │              │
│ │ │ ├─ Inference    │    │ │  attack scripts    │              │
│ │ │ └─ API (FastAPI)│    │ └─ curl             │              │
│ │ ├─ React dev srv  │    │                    │              │
│ │ └─ Mock MFS svc   │    │ Generates:         │              │
│ │                   │    │ ├─ Benign traffic  │              │
│ │ Ports:           │    │ ├─ Known attacks   │              │
│ │ ├─ 8000 (API)    │    │ └─ Zero-days       │              │
│ │ ├─ 3000 (React)  │    │                    │              │
│ │ ├─ 9000 (MFS)    │    │                    │              │
│ │ ├─ 5601 (Kibana) │    │                    │              │
│ │ └─ 9200 (ES)     │    │                    │              │
│ └────────────────────┘    └────────────────────┘              │
│          │ (network traffic)        │                         │
│          ├────────────────────────→ │                         │
│          │ (benign + attacks)      │                         │
│          ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                         │
│          │ (iptables blocks)       │                         │
└────────────────────────────────────────────────────────────────┘
```

---

## **STEP-BY-STEP WORKFLOW**

### **STEP 1: DEVELOPMENT (in VS Code on your Mac)**

```
Your local Mac
└─ ~/Documents/Playground/predictive-ids/

   ├─ api/
   │  ├─ main.py            ← FastAPI backend
   │  ├─ requirements.txt
   │  └─ Dockerfile
   │
   ├─ inference/
   │  ├─ service.py         ← CNN inference loop
   │  ├─ requirements.txt
   │  └─ Dockerfile
   │
   ├─ dashboard/            ← React frontend
   │  ├─ src/
   │  │  ├─ components/
   │  │  ├─ pages/
   │  │  └─ App.tsx
   │  ├─ package.json
   │  └─ Dockerfile
   │
   ├─ model/
   │  ├─ onemoney_cnn.h5    ← Pre-trained CNN (from training)
   │  └─ scaler.pkl         ← Pre-fitted StandardScaler
   │
   ├─ data/
   │  ├─ raw/
   │  │  └─ OneMoney_Training_v3_10k.csv  (training data)
   │  └─ processed/
   │      ├─ X_train.npy, X_val.npy, X_test.npy
   │      ├─ y_train.npy, y_val.npy, y_test.npy
   │      └─ feature_names.txt (76 feature names)
   │
   ├─ docker-compose.yml    ← Orchestrates all services
   │
   └─ config/
      └─ logstash.conf      ← Pipeline for log processing
```

**What you do in VS Code:**
1. Edit code (e.g., fix API endpoints, adjust threshold, change dashboard)
2. Test locally if possible
3. Commit changes: `git add . && git commit -m "..."`
4. Files are synced to VMs via:
   - Option A: git clone into VM
   - Option B: Shared folder / file sync
   - Option C: Copy files directly via `scp`

---

### **STEP 2: BUILD & DEPLOY (on IDS-Lab VM)**

```bash
# On IDS-Lab VM (192.168.64.4), run:

# 1. Navigate to project
cd ~/predictive-ids

# 2. Build Docker images (first time only)
docker-compose build

# 3. Start all services
docker-compose up -d

# 4. Verify services are running
docker-compose ps

# Output should show:
# CONTAINER ID   IMAGE           STATUS
# xyz123        ids-elasticsearch  Up (healthy)
# xyz124        ids-logstash       Up
# xyz125        ids-kibana         Up
# xyz126        ids-mongodb        Up
# xyz127        ids-inference      Up
# xyz128        ids-api            Up

# 5. Test connectivity
curl http://localhost:8000/          # FastAPI health check
curl http://localhost:3000/          # React dashboard
curl http://localhost:5601/          # Kibana (optional)
```

**What's happening:**

```
docker-compose.yml specifies:
└─ Elasticsearch (port 9200)
   └─ Image: elasticsearch:8.13.0
   └─ Volume: es_data (persists indices)
   
└─ Logstash (port 5044)
   └─ Reads: config/logstash.conf
   └─ Inputs: TCP (port 5044) or watches syslog
   └─ Outputs: Elasticsearch (logs-* index)
   
└─ MongoDB (port 27017)
   └─ Collections: alerts, blocked_ips
   
└─ Inference Service (no external port)
   └─ Polling loop (every 10s):
      1. Query ES for new flows: es.search(index="logs-*")
      2. Load pre-trained model: load_model("model/onemoney_cnn.h5")
      3. Extract 76 features from each flow
      4. Scale features using: scaler.pkl
      5. Run CNN: model.predict(X_scaled)
      6. If attack_prob >= 0.40: block IP via iptables
      7. Store alert in MongoDB + Elasticsearch
   
└─ FastAPI (port 8000)
   └─ Endpoints:
      GET  /api/alerts        → fetch from MongoDB
      GET  /api/stats         → aggregations from MongoDB
      POST /api/predict       → run CNN on single flow
      POST /api/block         → manual IP blocking
      DELETE /api/unblock/:ip → remove block
   
└─ React Dashboard (port 3000)
   └─ Fetches from: localhost:8000/api/*
   └─ Displays: alerts, blocked IPs, stats, graphs
```

---

### **STEP 3: GENERATE LIVE TRAFFIC (from Attacker VM)**

On **Attacker VM** (192.168.64.5):

```bash
# Background: Benign traffic (simulates legitimate users)
# Creates: Normal login, balance checks, transfers
cat > benign_traffic.sh << 'EOF'
#!/bin/bash
TARGET="192.168.64.4"

while true; do
  curl -s http://$TARGET:9000/balance      # Normal API call
  curl -s http://$TARGET:9000/login?user=alice  # Normal login
  curl -s http://$TARGET:9000/transfer?amt=500  # Normal transfer
  sleep 2
done
EOF

chmod +x benign_traffic.sh
./benign_traffic.sh &    # Run in background

# Now run attacks while benign traffic continues
cat > attack.sh << 'EOF'
#!/bin/bash
TARGET="192.168.64.4"

# Known attacks (Objective 1 baseline)
echo "[KNOWN] Port scan..."
nmap -p 1-1000 $TARGET

echo "[KNOWN] Brute force..."
hydra -l admin -P wordlist.txt http://$TARGET:9000

echo "[KNOWN] SYN flood..."
hping3 -S -p 9000 --flood $TARGET

# Unknown/zero-day attacks (Objective 1 main)
echo "[UNKNOWN] Fragmented SYN..."
hping3 -f -S -p 9000 --flood $TARGET

echo "[UNKNOWN] Randomized port scan..."
for port in 8001 5432 3306 4000 9001; do
  nc -zv -w 1 $TARGET $port
done

echo "[UNKNOWN] Slow brute force..."
for i in {1..20}; do
  curl -s http://$TARGET:9000/login?user=admin&pass=guess$i
  sleep 0.5
done
EOF

chmod +x attack.sh
./attack.sh
```

**What happens:**

```
Traffic flow:

Attacker VM (192.168.64.5)
└─ Sends: HTTP requests, TCP packets, scans
   └─ To: IDS-Lab VM (192.168.64.4:9000 and other ports)

IDS-Lab VM (192.168.64.4)
└─ Network interface captures packets
   └─ Logstash processes them
      └─ Extracts: source_ip, dest_ip, flow_duration, 
                   packet_counts, flags, etc.
      └─ Creates: 76 CICFlowMeter features
      └─ Sends to: Elasticsearch (logs-* index)

Elasticsearch (port 9200)
└─ Stores: Log entries with 76 features
   └─ Example document:
      {
        "@timestamp": "2026-06-16T18:29:20Z",
        "source_ip": "192.168.64.5",
        "dest_ip": "192.168.64.4",
        "flow_duration": 5.2,
        "Tot Fwd Pkts": 450,
        "Tot Bwd Pkts": 12,
        "Fwd Pkt Len Max": 1500,
        ... (72 more features)
      }

Inference Service (polling loop)
└─ Every 10 seconds:
   1. Query ES: {"range": {"@timestamp": {"gt": last_timestamp}}}
   2. Get 500 new flows
   3. Extract 76 features per flow
   4. Apply StandardScaler (using scaler.pkl)
   5. Reshape: (500, 76) → (500, 1, 76) for CNN
   6. CNN.predict(X_scaled)
      └─ Output: (500, 2) array
      └─ Each row: [P(BENIGN), P(ATTACK)]
   7. For each flow:
      - If P(ATTACK) >= 0.40:
        └─ Mark as ATTACK
        └─ Create alert record
        └─ Block source IP via iptables
        └─ Store in MongoDB
   8. Push alerts to ES (ids-alerts index)

MongoDB
└─ alerts collection:
   {
     "source_ip": "192.168.64.5",
     "prediction": "ATTACK",
     "attack_prob": 0.91,
     "severity": "HIGH",
     "blocked": true,
     "indexed_at": "2026-06-16T18:29:20Z"
   }
└─ blocked_ips collection:
   {
     "ip": "192.168.64.5",
     "reason": "CNN inference",
     "blocked_at": "2026-06-16T18:29:20Z",
     "active": true
   }

iptables (kernel level)
└─ Rules added:
   iptables -I INPUT -s 192.168.64.5 -j DROP
   iptables -I OUTPUT -d 192.168.64.5 -j DROP
   └─ Result: All packets from 192.168.64.5 are dropped

React Dashboard (localhost:3000)
└─ Fetches every 10s:
   GET http://localhost:8000/api/stats
   GET http://localhost:8000/api/alerts
   GET http://localhost:8000/api/blocked
└─ Displays:
   - Total alerts: 25
   - Blocked IPs: 1 (192.168.64.5)
   - CNN confidence: 85.7%
   - Live alerts feed
   - Attack timeline graph
```

---

### **STEP 4: VERIFY BLOCKING (on IDS-Lab VM)**

```bash
# Check iptables rules
sudo iptables -L -n | grep 192.168.64.5

# Output:
# DROP  all  --  192.168.64.5  0.0.0.0/0
# DROP  all  --  192.168.64.5  0.0.0.0/0

# Check MongoDB
docker exec ids-mongodb mongosh ids_db
> db.blocked_ips.find({active: true})

# Output:
# {
#   "_id": ObjectId(...),
#   "ip": "192.168.64.5",
#   "reason": "CNN inference",
#   "blocked_at": "2026-06-16T18:29:20.000Z",
#   "active": true
# }
```

---

### **STEP 5: LIVE DEMONSTRATION (5-10 minutes)**

```bash
# On Mac: Open browser
http://localhost:3000    # React dashboard
http://localhost:5601    # Kibana (optional, for ES exploration)

# Terminal 1 (IDS-Lab VM): Monitor logs
docker logs -f ids-inference | grep -E "ATTACK|BLOCKED"

# Terminal 2 (Attacker VM): Run attack
./benign_traffic.sh &    # Background benign traffic
sleep 30
./attack.sh              # Launch attacks

# Watch dashboard in real-time
# ✓ Alerts spike from 0 to 25
# ✓ Blocked IPs: 0 → 1 (192.168.64.5)
# ✓ CNN confidence: 85-95%
# ✓ Status: GREEN → DANGER → (after blocking) CONTROLLED
```

---

## **FILE FLOW DIAGRAM**

```
TRAINING (one-time, already done):
data/raw/OneMoney_Training_v3_10k.csv
  ↓ preprocessing/preprocess.py
  ↓
data/processed/
├─ X_train.npy, X_val.npy, X_test.npy
├─ y_train.npy, y_val.npy, y_test.npy
├─ scaler.pkl (fitted on training data)
└─ feature_names.txt (76 feature names)
  ↓ train.py
  ↓
model/
├─ onemoney_cnn.h5 (trained weights)
└─ scaler.pkl (used during inference)


INFERENCE (daily, during demo):
Live Network Traffic (from Attacker VM)
  ↓ Logstash (config/logstash.conf)
  ↓
Elasticsearch (logs-* index with 76 features)
  ↓ Inference Service (inference/service.py)
     └─ Loads: model/onemoney_cnn.h5
     └─ Loads: model/scaler.pkl
     └─ Loads: data/processed/feature_names.txt
     └─ Runs CNN on 500 flows every 10s
  ↓
MongoDB (alerts + blocked_ips)
  ↓
FastAPI (api/main.py)
  ↓
React Dashboard (dashboard/src/App.tsx)
  ↓
Browser (localhost:3000)
```

---

## **QUICK REFERENCE: PORTS & SERVICES**

| Port | Service | URL | Purpose |
|------|---------|-----|---------|
| 3000 | React Dashboard | http://localhost:3000 | Live monitoring UI |
| 8000 | FastAPI | http://localhost:8000 | API endpoints |
| 9000 | Mock MFS | http://localhost:9000 | Test target |
| 5601 | Kibana | http://localhost:5601 | Log exploration (optional) |
| 9200 | Elasticsearch | http://localhost:9200 | Log storage |
| 27017 | MongoDB | localhost:27017 | Alert storage |

---

## **TROUBLESHOOTING CHECKLIST**

```bash
# Services not starting?
docker-compose logs

# Elasticsearch unhealthy?
docker logs ids-elasticsearch | tail -20

# Inference not running?
docker logs ids-inference | grep -i error

# Can't reach dashboard?
curl http://localhost:3000

# Logstash not capturing traffic?
# Check: config/logstash.conf has correct input/output

# iptables rules not applying?
# Check: inference service has privileged + host network mode
# Verify: sudo iptables -L -n

# No alerts appearing?
# Check:
#   1. Traffic is reaching IDS-Lab (tcpdump -i eth0)
#   2. Logstash is parsing (docker logs ids-logstash)
#   3. ES has logs (curl http://localhost:9200/logs-*/_count)
#   4. Inference is running (docker logs ids-inference)
```

---

## **SUMMARY**

```
Your Development Machine (Mac)
         ↓ (edit code in VS Code)
Code Files (api/, inference/, dashboard/, model/, docker-compose.yml)
         ↓ (copy/sync to VM)
IDS-Lab VM (192.168.64.4)
         ↓ (docker-compose up)
Services Running (ES, Logstash, MongoDB, Inference, API, React)
         ↓ (listens for traffic)
Attacker VM (192.168.64.5)
         ↓ (sends benign + attack traffic)
Live Network Flows
         ↓ (captured by Logstash, stored in ES with 76 features)
CNN Inference Service
         ↓ (loads trained model + scaler, classifies flows)
Alerts + IP Blocks
         ↓ (stored in MongoDB + Elasticsearch)
React Dashboard
         ↓ (displays real-time alerts, blocked IPs, metrics)
Browser (localhost:3000)
         ↓ (you see live demonstration of all objectives)
✅ Demo Complete - Thesis Validated
```
