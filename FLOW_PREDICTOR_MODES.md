# Flow Predictor — Two Operating Modes

The dashboard now includes an enhanced Flow Predictor with **two distinct modes**: automatic live streaming or manual ad-hoc testing.

---

## 🎯 **Quick Comparison**

| Feature | 🔴 Live Stream Mode | 📝 Manual Test Mode |
|---------|---|---|
| **How** | Automatically polls `/api/alerts` | You paste JSON & click |
| **Input** | None (automatic) | Manual flow JSON |
| **Frequency** | Every 5 seconds | On-demand |
| **Shows** | Real detections from inference service | Your test predictions |
| **Use Case** | Watch real attacks as they happen | Debug/test specific flows |
| **Requires** | Running inference service | Any flow data |

---

## 🔴 **MODE 1: LIVE STREAM (Automatic)**

### **What It Does**

Continuously monitors your **real network traffic** by automatically polling the inference service's detection results.

```
Inference Service (background)
  ↓ (every 10 seconds)
SQLite alerts table
  ↓ (you don't need to do anything)
Dashboard fetches /api/alerts
  ↓ (every 5 seconds)
Live Stream panel updates
  ↓
You see attacks appearing in REAL-TIME 🔴
```

### **How to Use**

1. Open dashboard at `http://localhost:3000`
2. Scroll to **"Flow Predictor"** section
3. Make sure **"🔴 Live Stream"** tab is selected
4. Click **"▶ Resume Stream"** if paused
5. Watch predictions appear automatically

### **What You See**

Real detections from your network:

```
ATTACK    10:05:23    CRITICAL
IP: 192.168.64.3
Confidence: 98.5%

ATTACK    10:05:18    HIGH
IP: 192.168.64.5
Confidence: 87.2%

BENIGN    10:05:12    NONE
IP: 192.168.64.10
Confidence: 12.3%
```

### **Key Features**

- ✅ **No manual input** — completely automatic
- ✅ **Real-time updates** — refreshes every 5 seconds
- ✅ **Live indicator** — green pulsing dot shows connection
- ✅ **Pause/Resume** — stop watching if you want
- ✅ **Clear history** — clean up old predictions
- ✅ **Source data** — directly from inference service

### **What Triggers Updates**

Updates appear when:
1. Inference service detects an attack
2. Results stored in SQLite alerts table
3. Dashboard polls `/api/alerts`
4. New alert appears in the stream

### **Prerequisites**

- ✅ Inference service running
- ✅ CNN model loaded
- ✅ Real network traffic (or simulated attacks)

### **Example Workflow**

```bash
# Terminal 1: Start inference service
python -m inference.service

# Terminal 2: Start API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 3: Start dashboard
cd dashboard && npm start

# Terminal 4: Open browser
open http://localhost:3000

# Terminal 5: Simulate attacks
cd ~/predictive-ids
./scripts/simulate_attacks.sh 192.168.64.2

# Now watch the Live Stream panel update in REAL-TIME! 🔴
```

---

## 📝 **MODE 2: MANUAL TEST (Ad-hoc)**

### **What It Does**

Lets you test the CNN model on **specific flows** of your choice.

```
You create/paste flow JSON
          ↓
Click "Test Flow"
          ↓
POST /api/predict with single flow
          ↓
CNN classifies 1 flow immediately
          ↓
Result displayed in dashboard
          ↓
NOT saved to database
```

### **How to Use**

1. Open dashboard
2. Scroll to **"Flow Predictor"** section
3. Switch to **"📝 Manual Test"** tab
4. Click **"Benign Sample"** or **"Attack Sample"** OR paste your own JSON
5. Click **"Test Flow"**
6. See result immediately

### **What You See**

Single prediction with full details:

```
ATTACK    10:05:25
Confidence: 85.0%
Severity: HIGH

---

BENIGN    10:04:30
Confidence: 8.5%
Severity: NONE
```

### **Key Features**

- ✅ **Manual control** — you decide what to test
- ✅ **Instant results** — no waiting for background polling
- ✅ **Sample flows** — quick testing with pre-made samples
- ✅ **Custom JSON** — test any flow you have
- ✅ **History** — keeps recent test results
- ✅ **No storage** — results not saved to database

### **Example Inputs**

**Test benign HTTP flow:**
```json
{
  "Flow Duration": 5000,
  "Tot Fwd Pkts": 20,
  "Tot Bwd Pkts": 18,
  ...
}
```

**Test SYN flood:**
```json
{
  "Flow Duration": 0.5,
  "Tot Fwd Pkts": 50000,
  "SYN Flag Cnt": 50000,
  ...
}
```

**Test unknown attack pattern:**
```json
{
  "Flow Duration": 0.1,
  "Tot Fwd Pkts": 25000,
  "Pkt Len Std": 2,  ← Very low variance
  ...
}
```

### **Use Cases**

1. **Debug**: "Why was this flow detected?"
2. **Learn**: "How sensitive is the model to this feature?"
3. **Validate**: "Does the model detect this attack type?"
4. **Research**: "What happens if I change this value?"
5. **Test**: "Will my custom flow trigger an alert?"

---

## 🔄 **When to Use Each Mode**

### **Use Live Stream When:**
- ✅ Running attack simulations (watching real detections)
- ✅ Testing the inference service
- ✅ Monitoring live network traffic
- ✅ Creating thesis demo (show attacks as they happen)
- ✅ Demonstrating IDS in action
- ✅ Building real-time dashboards

### **Use Manual Test When:**
- ✅ Understanding individual flow classification
- ✅ Debugging edge cases
- ✅ Testing specific attack patterns
- ✅ Learning how the model works
- ✅ Validating predictions before analysis
- ✅ Creating test cases for thesis
- ✅ Comparing similar flows

---

## 💡 **Complete Workflow Example**

### **Scenario: Testing a New Attack**

```
Step 1: Create attack flow JSON
  └─ Maybe you found an unusual flow pattern

Step 2: Manual Test it
  └─ Switch to "📝 Manual Test"
  └─ Paste your JSON
  └─ Click "Test Flow"
  └─ See if CNN detects it

Step 3: Understand the result
  └─ Check confidence level
  └─ Check severity
  └─ Modify features to see what matters

Step 4: (Optional) Add to production
  └─ If confident in your flow
  └─ Run simulation script or inject logs
  └─ Switch to "🔴 Live Stream"
  └─ Watch real detections appear

Step 5: Document for thesis
  └─ Screenshot results
  └─ Note confidence, severity
  └─ Explain why detection happened
```

---

## 📊 **Data Flow Comparison**

### **Live Stream Mode**

```
Real Traffic → Logstash/SQLite logs
           → Inference Service polls (10s)
           → Classifies 500+ flows
           → Stores in SQLite alerts
           → Dashboard polls /api/alerts (5s)
           → Live Stream displays results
           
Flow: Automatic, continuous, batch processing
```

### **Manual Test Mode**

```
You input flow → Click "Test Flow"
             → Dashboard calls /api/predict (single)
             → API loads model, classifies 1 flow
             → Returns result
             → Display in panel
             
Flow: Manual, on-demand, single processing
```

---

## ⚙️ **Technical Details**

### **Live Stream**
- Calls: `fetchAlerts(limit, hours)` every 5 seconds
- Source: SQLite alerts table
- Data: Predictions from inference service
- Update: Only new alerts show
- Storage: Persisted in database

### **Manual Test**
- Calls: `predict(features)` on button click
- Source: You (paste JSON)
- Data: Single prediction for your flow
- Update: Immediate, adds to history
- Storage: Local browser history only

---

## 🎓 **For Your Thesis**

### **Live Stream is ideal for:**
- Demonstrating the IDS in action
- Showing real-time alert generation
- Proving the inference service works
- Creating a visual demo section

### **Manual Test is ideal for:**
- Analyzing specific detections
- Understanding feature importance
- Testing edge cases
- Creating test case documentation
- Validating model behavior

---

## 🚀 **Testing Scenarios**

### **Scenario 1: Quick Demo (5 minutes)**

```bash
# Setup
cd ~/predictive-ids

# Terminal 1
python -m inference.service

# Terminal 2
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 3
cd dashboard && npm start

# Terminal 4
open http://localhost:3000

# Terminal 5: Simulate attacks
./scripts/simulate_attacks.sh 192.168.64.2

# Now: Switch to Live Stream mode in dashboard
# Watch attacks appear in real-time 🔴
```

### **Scenario 2: Understanding Model (15 minutes)**

```bash
# Same setup as Scenario 1

# Manual Test workflow:
# 1. Load "Benign Sample" → Test → See attack_prob ≈ 0.15
# 2. Load "Attack Sample" → Test → See attack_prob ≈ 0.98
# 3. Modify attack sample (reduce SYN Flag Cnt) → Test
# 4. Observe how confidence changes
# 5. Document findings
```

### **Scenario 3: Thesis Research (1 hour)**

```bash
# Setup inference + API + dashboard

# Create test cases:
# 1. Normal HTTP flow → Test
# 2. FTP flow → Test
# 3. SSH brute force → Test
# 4. Port scan → Test
# 5. DDoS → Test
# 6. Unknown pattern → Test

# Document each:
# - Input features
# - Prediction
# - Confidence
# - Why detected (or why not)

# Use for thesis:
# - Table of test results
# - CNN accuracy analysis
# - Feature importance findings
```

---

## 📖 **Code Reference**

### **Files**

- [LiveFlowPredictor.jsx](dashboard/src/components/LiveFlowPredictor.jsx) — React component
- [api.js](dashboard/src/utils/api.js) — API functions
- [App.jsx](dashboard/src/App.jsx) — Integration

### **API Endpoints Used**

**Live Stream:**
```javascript
fetchAlerts(limit, hours)  // GET /api/alerts
// Polls every 5 seconds
```

**Manual Test:**
```javascript
predict(features)  // POST /api/predict
// Calls on button click
```

---

## ⚡ **Quick Tips**

- 💡 **Live mode slow?** Check if inference service is running
- 💡 **No predictions?** Make sure you're simulating attacks or injecting logs
- 💡 **Manual mode frozen?** Check API is running on port 8000
- 💡 **Need more samples?** Use `inject_unknown_logs.py` script
- 💡 **Documenting?** Take screenshots of both modes for thesis

---

## Summary

| Aspect | Live Stream | Manual Test |
|--------|---|---|
| **Setup needed** | Inference + API | API only |
| **User action** | Just watch | Paste JSON + click |
| **Frequency** | Automatic (5s) | On-demand |
| **Scope** | Production traffic | Test flows |
| **Saved?** | Yes (database) | No |
| **Best for** | Real monitoring | Testing/understanding |
