# OneMoney Predictive IDS/IPS Architecture

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                  OneMoney Predictive IDS/IPS Architecture                     ║
║                  (1D-CNN IDS for VMware Mobile Financial Services)            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│                          Network Traffic Layer                               │
│                                                                               │
│  Attacker VM                        │      IDS-Lab VM (OneMoney)             │
│  ┌──────────────────┐               │      ┌────────────────────────┐       │
│  │  Simulated Attacks                       │   CICFlowMeter Traffic │       │
│  │  (nmap, hping3,  │───attack traffic──→  │   Logs Generated       │       │
│  │   hydra, netcat) │                       └────────────────────────┘       │
│  └──────────────────┘                                   │                    │
│                                                          ↓                    │
│                                               ┌──────────────────┐           │
│                                               │   Logstash       │           │
│                                               │  (Log Pipeline)  │           │
│                                               └──────────────────┘           │
│                                                          │                    │
│                                                          ↓                    │
└──────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    Data & Inference Processing Layer                         │
│                                                                               │
│   ┌─────────────────────────────────────────────────────────────┐            │
│   │          Docker Compose Network (ids-network)               │            │
│   │                                                               │            │
│   │  ┌──────────────┐         ┌──────────────┐                 │            │
│   │  │              │         │              │                 │            │
│   │  │Elasticsearch │◄─────────│  Logstash   │  (indexed_logs) │            │
│   │  │(logs-*)      │         │              │                 │            │
│   │  │              │         └──────────────┘                 │            │
│   │  └──────────────┘                                           │            │
│   │       ▲                                                      │            │
│   │       │                                                      │            │
│   │       │ (polls every 10s)    ┌──────────────┐              │            │
│   │       └──────────────────────→  Inference   │              │            │
│   │                              │  Service     │              │            │
│   │                              │  (CNN IDS)   │              │            │
│   │                              └──────────────┘              │            │
│   │                                     │                      │            │
│   │                              ┌──────┴──────┐              │            │
│   │                              │             │              │            │
│   │                    ┌──────────────┐  ┌──────────────┐    │            │
│   │                    │ Keras 1D-CNN │  │    iptables  │    │            │
│   │                    │  (76 features)  │ (IP blocking)    │            │
│   │                    │ threshold:0.40  │                  │            │
│   │                    └──────────────┘  └──────────────┘    │            │
│   │                              │             │              │            │
│   │                              ↓             ↓              │            │
│   │                    ┌──────────────────────────┐          │            │
│   │                    │      MongoDB              │          │            │
│   │                    │  (alerts + blocked_ips)  │          │            │
│   │                    └──────────────────────────┘          │            │
│   │                              ▲                           │            │
│   │                              │                           │            │
│   │  ┌──────────────┐  (alert_index)  ┌──────────────┐     │            │
│   │  │   Kibana     │◄─────────────────│ Elasticsearch│    │            │
│   │  │ (Dashboard)  │                 │  (ids-alerts)│    │            │
│   │  └──────────────┘                 └──────────────┘     │            │
│   │                                                           │            │
│   └─────────────────────────────────────────────────────────┘            │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         API & Frontend Layer                                │
│                                                                               │
│                    ┌────────────────────────┐                               │
│                    │    FastAPI Backend     │                               │
│                    │   (REST API Server)    │                               │
│                    │  ┌──────────────────┐  │                               │
│                    │  │ GET  /           │  │                               │
│                    │  │ POST /api/predict│  │  (host network mode)           │
│                    │  │ GET  /api/alerts │  │  port 8000                    │
│                    │  │ GET  /api/stats  │  │                               │
│                    │  │ GET  /api/blocked│  │  Queries:                     │
│                    │  │ POST /api/block  │  │  ├→ MongoDB (alerts)          │
│                    │  │ DEL  /api/unblock│  │  └→ Elasticsearch (metrics)   │
│                    │  │                  │  │                               │
│                    │  └──────────────────┘  │                               │
│                    └────────────────────────┘                               │
│                              ▲                                              │
│                              │                                              │
│                    ┌─────────────────────┐                                 │
│                    │  React Dashboard    │                                 │
│                    │  (Web UI)           │                                 │
│                    │                     │                                 │
│                    │ • Alert Monitoring  │                                 │
│                    │ • IP Blocking       │                                 │
│                    │ • Statistics        │                                 │
│                    │ • Severity Tracking │                                 │
│                    └─────────────────────┘                                 │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                        ML Model Layer                                        │
│                                                                               │
│    ┌──────────────────────────────────────────────────────────┐             │
│    │  1D-CNN Model (onemoney_cnn.h5)                          │             │
│    │                                                            │             │
│    │  Input: 76 CICFlowMeter Features                         │             │
│    │  ├─ Flow statistics (duration, packets, bytes)           │             │
│    │  ├─ Packet lengths, rates, flags                         │             │
│    │  ├─ Inter-arrival times (IAT)                            │             │
│    │  └─ TCP flags, subflows, window sizes                    │             │
│    │                                                            │             │
│    │  Architecture:                                            │             │
│    │  Conv1D(64) → BN → Conv1D(128) → BN → MaxPool →          │             │
│    │  Dropout → Flatten → Dense(128) → Dropout → Dense(2, softmax)         │             │
│    │                                                            │             │
│    │  Output: [P(BENIGN), P(ATTACK)]                           │             │
│    │  Decision: ATTACK if P(ATTACK) >= 0.40 (threshold)       │             │
│    │                                                            │             │
│    │  Scaler: StandardScaler (fitted on training data)        │             │
│    │                                                            │             │
│    └──────────────────────────────────────────────────────────┘             │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘

Data Flow Summary
═════════════════
1. Network Traffic → Logstash → Elasticsearch (logs-*)
2. Inference Service polls Elasticsearch every 10 seconds
3. Extracts 76 CICFlowMeter features from log entries
4. Standardizes features using fitted scaler
5. Runs 1D-CNN inference → prediction + attack probability
6. If attack detected:
   ├→ Block attacker IP via iptables (INPUT/OUTPUT rules)
   ├→ Record block in MongoDB (blocked_ips collection)
   └→ Store alert in Elasticsearch (ids-alerts index) + MongoDB (alerts collection)
7. FastAPI reads alerts from MongoDB/ES and severity-based stats
8. React dashboard displays real-time alerts, top attackers, block status

Technology Stack
════════════════
• Language: Python 3.8+
• ML Framework: TensorFlow/Keras
• APIs: FastAPI, Elasticsearch, PyMongo
• Logging: ELK Stack (Elasticsearch, Logstash, Kibana)
• Database: MongoDB
• Containerization: Docker Compose
• Networking: iptables (IPS blocking)
• Frontend: React.js
```
