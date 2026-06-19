# API Usage Guide — Understanding `/api/predict` and Dashboard Flow

This guide explains how the API endpoints are used and when the `/api/predict` endpoint is actually used.

---

## 🔄 **Complete Data Flow**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ACTUAL PRODUCTION FLOW                          │
│                        (Used during normal operation)                     │
└─────────────────────────────────────────────────────────────────────────┘

Real Network Traffic
        ↓
    Logstash (parses logs) or direct logs
        ↓
    Elasticsearch (logs-* index) OR SQLite logs table
        ↓
Inference Service (polls every 10 seconds)
    - Fetches new logs
    - Loads CNN model
    - Calls model.predict() on BATCH of flows
    - Stores results in SQLite alerts table
        ↓
FastAPI Backend (api/main.py)
    - /api/stats         → queries SQLite for summary
    - /api/alerts        → queries SQLite for recent alerts
    - /api/blocked       → queries SQLite for blocked IPs
    - /api/block         → adds to blocked_ips table
        ↓
React Dashboard (dashboard/)
    - Polls /api/stats every 10 seconds
    - Polls /api/alerts every 10 seconds
    - Polls /api/blocked every 10 seconds
    - Shows real-time alerts visually


┌─────────────────────────────────────────────────────────────────────────┐
│                      AD-HOC TESTING FLOW                                 │
│              (Used when manually testing a single flow)                   │
└─────────────────────────────────────────────────────────────────────────┘

Manual Request (from terminal or external tool)
    ↓
POST /api/predict
    {
        "features": {
            "Flow Duration": 1000,
            "Tot Fwd Pkts": 50,
            "Tot Bwd Pkts": 5,
            ...all 76 features...
        }
    }
        ↓
FastAPI Handler (api/main.py line 179)
    - Extracts 76 features
    - Loads model & scaler
    - Calls model.predict() on SINGLE flow
    - Returns prediction
        ↓
Response
    {
        "prediction": "ATTACK",
        "attack_prob": 0.85,
        "severity": "HIGH",
        "threshold": 0.40,
        "probabilities": {
            "BENIGN": 0.15,
            "ATTACK": 0.85
        }
    }
```

---

## 🎯 **Key Insight**

| Component | Purpose | Uses `/api/predict`? | When? |
|-----------|---------|:---:|---------|
| **Inference Service** | Continuously monitors logs 24/7 | ❌ NO | Every 10 seconds, processes 500+ flows at once |
| **Dashboard** | Real-time visualization | ❌ NO | Polls `/api/stats` & `/api/alerts` every 10 seconds |
| **Ad-hoc Testing** | Manual testing of single flows | ✅ YES | When you curl it manually or write test scripts |
| **API Users** | External tools/scripts | ✅ YES | For real-time single-flow predictions |

---

## 📡 **API Endpoints Explained**

### **1. GET `/` — Health Check**

```bash
curl http://localhost:8000/
```

**Response:**
```json
{
  "status": "running",
  "service": "OneMoney Predictive IDS API",
  "version": "2.0.0",
  "threshold": 0.4,
  "time": "2025-06-19T10:00:00+00:00"
}
```

**Used by:** Dashboard health check, service verification

---

### **2. POST `/api/predict` — Classify Single Flow (AD-HOC)**

**This is for manual/testing purposes only** — NOT used in production.

```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "Flow Duration": 1000,
      "Tot Fwd Pkts": 50,
      "Tot Bwd Pkts": 5,
      "TotLen Fwd Pkts": 5000,
      "TotLen Bwd Pkts": 500,
      ... (all 76 features required)
    }
  }'
```

**Response:**
```json
{
  "prediction": "ATTACK",
  "attack_prob": 0.85,
  "severity": "HIGH",
  "threshold": 0.4,
  "probabilities": {
    "BENIGN": 0.15,
    "ATTACK": 0.85
  }
}
```

**When used:**
- ✅ Testing the model manually
- ✅ Integration tests
- ✅ Debugging model predictions
- ✅ External systems integrating with IDS
- ❌ NOT used by dashboard
- ❌ NOT used by inference service

**Key difference from inference service:**
- `/api/predict`: Takes 1 flow, returns 1 prediction (slow)
- Inference service: Takes 500+ flows, returns 500+ predictions (fast, batched)

---

### **3. GET `/api/alerts` — Fetch Recent Alerts (USED BY DASHBOARD)**

```bash
# Get last 50 alerts from last 24 hours
curl 'http://localhost:8000/api/alerts?limit=50&hours=24'

# Filter by severity
curl 'http://localhost:8000/api/alerts?severity=CRITICAL'

# Filter by source IP
curl 'http://localhost:8000/api/alerts?ip=192.168.64.3'

# Paginate
curl 'http://localhost:8000/api/alerts?limit=20&skip=40'
```

**Response:**
```json
{
  "total": 312,
  "limit": 50,
  "skip": 0,
  "alerts": [
    {
      "timestamp": "2025-06-19T10:05:23",
      "source_host": "unknown",
      "source_ip": "192.168.64.3",
      "prediction": "ATTACK",
      "severity": "CRITICAL",
      "attack_prob": 0.98,
      "blocked": false,
      "indexed_at": "2025-06-19T10:05:25"
    },
    ...
  ]
}
```

**Used by:** 
- ✅ Dashboard (polls every 10 seconds)
- ✅ Real-time alert display
- ✅ Filtering by severity/IP/time

---

### **4. GET `/api/stats` — Summary Statistics (USED BY DASHBOARD)**

```bash
# Get stats for last 24 hours
curl 'http://localhost:8000/api/stats?hours=24'

# Get stats for last 1 hour
curl 'http://localhost:8000/api/stats?hours=1'
```

**Response:**
```json
{
  "period_hours": 24,
  "total_alerts": 312,
  "blocked_ips": 5,
  "severity_counts": {
    "CRITICAL": 142,
    "HIGH": 128,
    "MEDIUM": 32,
    "LOW": 10
  },
  "top_attackers": [
    {"ip": "192.168.64.3", "count": 142},
    {"ip": "192.168.64.5", "count": 89},
    ...
  ],
  "threshold": 0.4
}
```

**Used by:**
- ✅ Dashboard (polls every 10 seconds)
- ✅ Summary pie charts
- ✅ Statistics display
- ✅ Top attackers ranking

---

### **5. GET `/api/blocked` — List Blocked IPs (USED BY DASHBOARD)**

```bash
curl http://localhost:8000/api/blocked
```

**Response:**
```json
[
  {
    "ip": "192.168.64.3",
    "reason": "CNN detection",
    "blocked_at": "2025-06-19T10:02:15+00:00",
    "active": true
  },
  {
    "ip": "192.168.64.5",
    "reason": "manual",
    "blocked_at": "2025-06-19T09:55:00+00:00",
    "active": true
  }
]
```

**Used by:**
- ✅ Dashboard blocked IPs panel
- ✅ Managing active blocks

---

### **6. POST `/api/block` — Block an IP (USED BY DASHBOARD)**

```bash
curl -X POST http://localhost:8000/api/block \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.64.99",
    "reason": "suspicious activity detected"
  }'
```

**Response:**
```json
{
  "ip": "192.168.64.99",
  "reason": "suspicious activity detected",
  "blocked_at": "2025-06-19T10:05:30+00:00",
  "active": true
}
```

**Used by:**
- ✅ Dashboard "Block IP" button
- ✅ Manual blocking of suspicious IPs
- ✅ Triggers iptables rules + SQLite insert

---

### **7. DELETE `/api/unblock/{ip}` — Unblock an IP (USED BY DASHBOARD)**

```bash
curl -X DELETE http://localhost:8000/api/unblock/192.168.64.99
```

**Response:**
```json
{
  "status": "unblocked",
  "ip": "192.168.64.99"
}
```

**Used by:**
- ✅ Dashboard unblock button
- ✅ Removes iptables rule + marks inactive in SQLite

---

## 📊 **Dashboard Usage Pattern**

The dashboard does **NOT** use `/api/predict`. Instead, it follows this pattern:

```javascript
// From dashboard/src/hooks/useIDS.js (lines 23-35)

const poll = useCallback(async () => {
  try {
    const [h, s, a, b] = await Promise.allSettled([
      fetchHealth(),              // GET /
      fetchStats(hours),          // GET /api/stats
      fetchAlerts(20, hours),     // GET /api/alerts
      fetchBlocked(),             // GET /api/blocked
    ])
    
    // Update UI with results
    setHealth(h.value)
    setStats(s.value)
    setAlerts(a.value)
    setBlocked(b.value)
  }
}, [hours])

// Poll every 10 seconds
setInterval(poll, 10_000)
```

**What happens:**
1. Dashboard polls `/api/stats` every 10 seconds
2. Gets summary: total alerts, severity breakdown, top attackers
3. Polls `/api/alerts` for detailed list
4. Polls `/api/blocked` for current blocks
5. Never calls `/api/predict`

---

## ✅ **When to Use `/api/predict`**

### **Use Case 1: Manual Testing**
```bash
# Test the model on a specific flow
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"features": {...76 features...}}'
```

### **Use Case 2: External Integration**
```python
# Python script integrating with IDS
import requests

flow = {
    "Flow Duration": 1000,
    "Tot Fwd Pkts": 50,
    # ... all 76 features
}

response = requests.post(
    "http://localhost:8000/api/predict",
    json={"features": flow}
)

if response.json()["attack_prob"] > 0.8:
    print("ALERT: Potential attack detected!")
```

### **Use Case 3: Debugging Model Predictions**
```bash
# Understand why a specific flow was classified as ATTACK
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "Flow Duration": 0.5,
      "Tot Fwd Pkts": 25000,
      ... (the flow that triggered an alert)
    }
  }' | jq .
```

---

## 🚫 **What `/api/predict` is NOT Used For**

| Use Case | Tool Used Instead | Why |
|----------|------------------|-----|
| Continuous monitoring | Inference service | Batches 500+ flows, more efficient |
| Dashboard display | `/api/stats` & `/api/alerts` | Real-time + queryable results |
| Performance analysis | SQLite direct query | Faster than API |
| Stress testing | `inject_unknown_logs.py` | Bypasses API overhead |

---

## 🔍 **Tracing a Single Alert**

Let's trace what happens when an attack is detected:

### **Step 1: Inference Service Runs (every 10 sec)**
```
SQLite logs table → Inference service → model.predict(batch)
```

Code: [inference/service.py](../inference/service.py)
```python
# Fetch new logs
logs = fetch_logs_from_sqlite()  # 500+ flows

# Classify all at once (batched)
X_scaled = scaler.transform(logs)
predictions = model.predict(X_scaled)  # ← Uses TensorFlow batching

# Store in SQLite
for pred in predictions:
    insert_into_alerts_table(pred)
```

### **Step 2: Dashboard Polls API**
```
Dashboard → GET /api/alerts → queries SQLite alerts table
```

Code: [dashboard/src/hooks/useIDS.js](../dashboard/src/hooks/useIDS.js)
```javascript
const alerts = await fetchAlerts(20, 24)  // Last 20 from 24h
```

### **Step 3: Dashboard Displays Results**
```
API response → React state → UI update
```

**The `/api/predict` endpoint is never called in this flow.**

---

## 📈 **Performance Comparison**

| Method | Throughput | Latency | Used For |
|--------|-----------|---------|----------|
| **Inference Service** | 500+ flows/10sec | ~50ms batch | Production |
| **`/api/predict`** | 1 flow/request | ~100ms | Ad-hoc testing |
| **`/api/alerts` query** | Instant (cached) | <10ms | Dashboard |
| **Direct SQLite** | All results | <5ms | Reporting |

---

## 🛠️ **Practical Examples**

### **Example 1: Test a Specific Flow**
```bash
python3 << 'EOF'
import requests
import json

# A suspicious flow
suspicious_flow = {
    "Flow Duration": 0.5,
    "Tot Fwd Pkts": 50000,
    "Tot Bwd Pkts": 10,
    "TotLen Fwd Pkts": 500000,
    "TotLen Bwd Pkts": 100,
    # ... add all 76 features ...
}

response = requests.post(
    "http://localhost:8000/api/predict",
    json={"features": suspicious_flow}
)

result = response.json()
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['attack_prob']:.2%}")
print(f"Severity: {result['severity']}")
EOF
```

### **Example 2: Get Recent Alerts from API**
```bash
# Show last 5 CRITICAL alerts
curl -s 'http://localhost:8000/api/alerts?limit=5&severity=CRITICAL' | jq '.alerts[] | {timestamp, source_ip, attack_prob}'
```

### **Example 3: Monitor Dashboard Stats**
```bash
# Watch stats update every 10 seconds
watch -n 1 'curl -s http://localhost:8000/api/stats | jq "{total: .total_alerts, critical: .severity_counts.CRITICAL}"'
```

---

## 📋 **Summary Table**

| Endpoint | Method | Used By | Frequency | Purpose |
|----------|--------|---------|-----------|---------|
| `/` | GET | Dashboard | On load | Health check |
| `/api/predict` | POST | Manual testing | Ad-hoc | Single flow classification |
| `/api/alerts` | GET | Dashboard | Every 10s | Fetch recent alerts |
| `/api/stats` | GET | Dashboard | Every 10s | Fetch summary stats |
| `/api/blocked` | GET | Dashboard | Every 10s | Fetch blocked IPs |
| `/api/block` | POST | Dashboard | Manual | Block an IP |
| `/api/unblock/{ip}` | DELETE | Dashboard | Manual | Unblock an IP |

---

## 🎓 **For Your Thesis**

When documenting your system, clarify:
1. **Inference service** = continuous background monitoring (uses batched predict)
2. **API endpoints** = serve cached/queryable results to dashboard
3. **`/api/predict`** = ad-hoc testing endpoint (NOT used in production)
4. **Dashboard** = real-time visualization of alerts (never calls `/api/predict`)

This shows a **proper separation of concerns**:
- Production inference: efficient batched processing
- API layer: queryable results for visualization
- Manual testing: single-flow endpoint for debugging
