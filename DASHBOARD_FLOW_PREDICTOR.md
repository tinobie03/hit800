# Dashboard Flow Predictor — Real-time Manual Prediction

This guide explains the new **Flow Predictor** component integrated into the dashboard for real-time ad-hoc flow prediction and testing.

---

## 🎯 **What is the Flow Predictor?**

A built-in tool in the dashboard that allows you to:
- ✅ Test the CNN model on individual network flows
- ✅ Manually input 76 CICFlowMeter features
- ✅ Get instant predictions with confidence scores
- ✅ See severity levels and probabilities
- ✅ Keep a history of recent predictions
- ✅ Load sample benign/attack flows for testing

**Location:** Bottom of the dashboard (after alerts and blocked IPs sections)

---

## 📊 **How It Works**

```
You input flow data (JSON or form)
         ↓
Dashboard calls POST /api/predict
         ↓
FastAPI loads model + scaler
         ↓
Model classifies single flow
         ↓
Returns: {
   prediction: "ATTACK" | "BENIGN",
   attack_prob: 0.0-1.0,
   severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
   probabilities: {BENIGN: 0.0-1.0, ATTACK: 0.0-1.0}
}
         ↓
Dashboard displays result with visual indicators
```

---

## 🚀 **Quick Start**

### **Option 1: Load a Sample**

1. Open the dashboard at `http://192.168.64.2:3000`
2. Scroll to the bottom → **Flow Predictor** section
3. Click **"Load Benign Sample"** or **"Load Attack Sample"**
4. Click **"Predict Flow"**
5. See the result with confidence percentage

### **Option 2: Paste JSON**

1. Copy your CICFlowMeter flow data (76 features) as JSON
2. Paste into the text area
3. Click **"Predict Flow"**
4. View prediction with severity level

### **Option 3: Use Form**

1. Switch to **"Form Input"** tab
2. Edit the 76 input fields (pre-filled with benign sample)
3. Click **"Predict Flow"**
4. Get instant prediction

### **Option 4: Upload JSON File**

1. Click **"Upload JSON"** button
2. Select a JSON file with 76 features
3. Click **"Predict Flow"**

---

## 📁 **Input Format**

The Flow Predictor expects a JSON object with all **76 CICFlowMeter features**:

```json
{
  "Flow Duration": 1000,
  "Tot Fwd Pkts": 50,
  "Tot Bwd Pkts": 45,
  "TotLen Fwd Pkts": 5000,
  "TotLen Bwd Pkts": 4500,
  ... (all 76 features)
  "Idle Max": 1000,
  "Idle Min": 100
}
```

### **Complete Feature List (76 total)**

```
Time Features:
  Flow Duration, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min
  Fwd IAT Tot, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min
  Bwd IAT Tot, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min
  Active Mean, Active Std, Active Max, Active Min
  Idle Mean, Idle Std, Idle Max, Idle Min

Packet Count & Length:
  Tot Fwd Pkts, Tot Bwd Pkts
  TotLen Fwd Pkts, TotLen Bwd Pkts
  Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Fwd Pkt Len Std
  Bwd Pkt Len Max, Bwd Pkt Len Min, Bwd Pkt Len Mean, Bwd Pkt Len Std
  Pkt Len Min, Pkt Len Max, Pkt Len Mean, Pkt Len Std, Pkt Len Var
  Pkt Size Avg

Rate Features:
  Flow Byts/s, Flow Pkts/s
  Fwd Pkts/s, Bwd Pkts/s
  Fwd Byts/b Avg, Fwd Pkts/b Avg, Fwd Blk Rate Avg
  Bwd Byts/b Avg, Bwd Pkts/b Avg, Bwd Blk Rate Avg

Flags:
  Fwd PSH Flags, Bwd PSH Flags
  Fwd URG Flags, Bwd URG Flags
  FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt
  PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt
  CWE Flag Count, ECE Flag Cnt

Other:
  Fwd Header Len, Bwd Header Len
  Fwd Seg Size Avg, Bwd Seg Size Avg
  Subflow Fwd Pkts, Subflow Fwd Byts, Subflow Bwd Pkts, Subflow Bwd Byts
  Init Fwd Win Byts, Init Bwd Win Byts
  Fwd Act Data Pkts, Fwd Seg Size Min
  Down/Up Ratio
```

---

## 📤 **Output & Interpretation**

### **Prediction Response**

```json
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

### **What Each Field Means**

| Field | Example | Meaning |
|-------|---------|---------|
| **prediction** | "ATTACK" \| "BENIGN" | Final classification result |
| **attack_prob** | 0.85 | CNN confidence that flow is attack (0.0-1.0) |
| **severity** | "HIGH" | Threat level based on confidence |
| **threshold** | 0.40 | Decision boundary (attack_prob >= threshold) |
| **probabilities.BENIGN** | 0.15 | Probability flow is normal |
| **probabilities.ATTACK** | 0.85 | Probability flow is attack |

### **Severity Mapping**

| Severity | attack_prob Range | Explanation |
|----------|------------------|-------------|
| **CRITICAL** | ≥ 0.95 | Nearly certain attack |
| **HIGH** | 0.80 - 0.94 | Strong evidence of attack |
| **MEDIUM** | 0.60 - 0.79 | Likely attack |
| **LOW** | 0.40 - 0.59 | Possible attack (above threshold) |
| **NONE** | < 0.40 | Benign (below threshold) |

---

## 💡 **Use Cases**

### **Use Case 1: Test Detection on Manual Flows**

```bash
# Create a JSON file with a suspicious flow
cat > suspicious_flow.json << 'EOF'
{
  "Flow Duration": 0.5,
  "Tot Fwd Pkts": 50000,
  "Tot Bwd Pkts": 5,
  ... (more fields)
}
EOF

# Upload to dashboard and click "Predict Flow"
# Dashboard calls /api/predict
# See if CNN detects it as attack
```

### **Use Case 2: Debug Model Predictions**

```
Question: Why is this flow classified as ATTACK?

Answer: Use Flow Predictor to see:
  1. Confidence score
  2. Probability breakdown
  3. Severity level
  4. Keep testing similar flows to understand patterns
```

### **Use Case 3: Test Different Attack Patterns**

```
1. Load sample benign flow → Predict
2. Load sample attack flow → Predict
3. Modify fields to understand what triggers detection
4. Test edge cases
5. Keep history of predictions for analysis
```

### **Use Case 4: Integration Testing**

```
When adding new flows to the system:
1. Parse flow features
2. Use dashboard Flow Predictor to test
3. Verify prediction matches expected behavior
4. Then add to logs for inference service
```

---

## 🔄 **Differences: Flow Predictor vs Inference Service**

| Feature | Flow Predictor | Inference Service |
|---------|-----------------|------------------|
| **How** | Manual input | Auto reads logs |
| **Speed** | ~100ms per flow | ~50ms per 500 flows |
| **Scale** | 1 flow at a time | 500+ flows per poll |
| **Storage** | No (display only) | Yes (saves to SQLite) |
| **Use Case** | Testing/debugging | Production monitoring |
| **History** | Last 10 predictions | All alerts in SQLite |
| **When Used** | On-demand | Every 10 seconds |

---

## 🎮 **Dashboard Features**

### **Input Modes**

**JSON Input:**
- Paste CICFlowMeter JSON with 76 features
- Click "Predict Flow"
- Ideal for testing specific captured flows
- Can upload JSON files

**Form Input:**
- Edit 76 input fields individually
- Better for fine-tuning individual features
- Slower but more control
- Good for learning which features matter

### **Sample Flows**

**"Load Benign Sample"**
- Realistic normal traffic flow
- Should predict as BENIGN
- attack_prob ≈ 0.15

**"Load Attack Sample"**
- Realistic attack traffic (SYN flood)
- Should predict as ATTACK
- attack_prob ≈ 0.98

### **Result Visualization**

```
┌─────────────────────────┐
│      ATTACK             │  ← Prediction
├─────────────────────────┤
│ Confidence: 85.0%       │  ← attack_prob
│ [████████░░░░░░░░] ←── │  ← Visual bar
├─────────────────────────┤
│ Severity: HIGH          │  ← Severity
├─────────────────────────┤
│ BENIGN:  15.00%         │
│ ATTACK:  85.00%         │
│ Threshold: 0.40         │
└─────────────────────────┘
```

### **History Tracking**

- Shows last 10 predictions
- Each entry shows: prediction, timestamp, confidence
- Color-coded (red for ATTACK, green for BENIGN)
- Useful for spotting patterns

---

## 🔧 **Examples**

### **Example 1: Test a Normal HTTP Flow**

```json
{
  "Flow Duration": 5000,
  "Tot Fwd Pkts": 20,
  "Tot Bwd Pkts": 18,
  "TotLen Fwd Pkts": 10000,
  "TotLen Bwd Pkts": 8000,
  "Fwd Pkt Len Max": 1500,
  "Fwd Pkt Len Min": 50,
  "Fwd Pkt Len Mean": 500,
  ... (fill remaining fields with typical values)
}
```

**Expected Result:** BENIGN (attack_prob < 0.40)

---

### **Example 2: Test a SYN Flood**

```json
{
  "Flow Duration": 0.5,
  "Tot Fwd Pkts": 50000,
  "Tot Bwd Pkts": 10,
  "TotLen Fwd Pkts": 500000,
  "TotLen Bwd Pkts": 100,
  "SYN Flag Cnt": 50000,
  "ACK Flag Cnt": 5,
  "Flow Pkts/s": 100000,
  ... (remaining fields)
}
```

**Expected Result:** ATTACK (attack_prob > 0.95, CRITICAL)

---

### **Example 3: Test an Edge Case**

```json
{
  "Flow Duration": 0.1,
  "Tot Fwd Pkts": 1000,
  "Tot Bwd Pkts": 50,
  ... (modify fields to test unknown pattern)
}
```

**Purpose:** See how model handles novel patterns
**Result:** May be ATTACK due to anomaly, or BENIGN if pattern matches training

---

## 📊 **Practical Workflow**

### **Testing Phase (Development)**

1. **Create test flows** in JSON format
2. **Predict each** using Flow Predictor
3. **Verify results** match expected behavior
4. **Document findings** for thesis
5. **Store flows** for regression testing

### **Analysis Phase (Thesis Research)**

1. **Load sample flows** (benign + attack)
2. **Test variations** of each
3. **Track confidence** changes as you modify features
4. **Identify key features** that drive predictions
5. **Export results** for your paper

### **Integration Phase (Production)**

1. **Test new flows** via Flow Predictor first
2. **Verify prediction** matches manual analysis
3. **If correct**, add flow to logs
4. **Let inference service** pick up from there
5. **Track result** in alerts

---

## ⚠️ **Important Notes**

### **Flow Predictor is NOT**

- ❌ Real-time monitoring (use inference service for that)
- ❌ Streaming predictions (ad-hoc only)
- ❌ For high-volume testing (batch via `inject_unknown_logs.py`)
- ❌ Persistent (doesn't save predictions to database)

### **Flow Predictor IS**

- ✅ For manual testing and debugging
- ✅ For understanding model behavior
- ✅ For verifying single flows
- ✅ For integration testing
- ✅ For thesis research and analysis

---

## 🚀 **Testing Workflow Example**

```bash
# Terminal 1: Start inference service
python -m inference.service

# Terminal 2: Start API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 3: Start dashboard
cd dashboard && npm start

# Terminal 4: Access dashboard
open http://localhost:3000

# Now use Flow Predictor in the dashboard UI:
# 1. Load "Benign Sample" → Click Predict
# 2. Load "Attack Sample" → Click Predict
# 3. Modify attack sample fields → Test variations
# 4. Try impossible flag combinations → See how model reacts
# 5. View history → Understand patterns
```

---

## 📈 **Integrating with Your Thesis**

### **Document:**
1. CNN model validation using Flow Predictor
2. Sensitivity analysis (which features matter most)
3. Edge case testing (impossible flag combinations)
4. Comparison: predicted vs actual detections
5. Confusion matrix: tested flows vs predictions

### **Metrics to Track:**
- Accuracy on test flows
- Confidence distribution
- False positive rate
- Detection latency per flow
- Feature importance analysis

---

## 🐛 **Troubleshooting**

### **"Invalid JSON" Error**
- Check JSON is valid (use `jq` to validate)
- Ensure all 76 features are present
- Numbers should not be strings (no quotes around values)

### **Model Not Loading**
- Check API is running: `curl http://localhost:8000/`
- Check model file exists: `ls -lh model/onemoney_cnn.h5`
- Check scaler exists: `ls -lh model/scaler.pkl`

### **Slow Predictions**
- Model loading takes ~2 seconds first time
- Subsequent predictions are fast (~100ms)
- If timeout, restart API backend

### **History Not Showing**
- History is local to browser (not persistent)
- Refresh page clears history
- Use SQLite to query persistent alerts from inference service

---

## 💻 **Code Reference**

### **Component Files**

- [FlowPredictor.jsx](dashboard/src/components/FlowPredictor.jsx) — React component
- [api.js](dashboard/src/utils/api.js) — API fetch wrapper
- [api/main.py](api/main.py#L178) — Backend `/api/predict` endpoint

### **Key Functions**

```javascript
// JavaScript (dashboard)
await predict(features)  // Call /api/predict

// Python (API)
@app.post("/api/predict")
def predict(entry: PredictRequest):
  # Loads model, scaler
  # Classifies single flow
  # Returns prediction
```

---

## 📚 **Related Documentation**

- [API_USAGE_GUIDE.md](API_USAGE_GUIDE.md) — API endpoints explained
- [UNKNOWN_ATTACKS_GUIDE.md](scripts/UNKNOWN_ATTACKS_GUIDE.md) — Testing novel attacks
- [README.md](README.md) — Project overview
