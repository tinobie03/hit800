# Troubleshooting Guide

Common issues and solutions for the OneMoney IDS project.

---

## 🔴 API Errors

### **Issue: POST /api/predict returns 500 error**

#### **Error Messages**
```
ModuleNotFoundError: No module named 'sklearn'
AttributeError: 'NoneType' object has no attribute 'transform'
```

#### **Root Cause**
The scaler.pkl file was saved with scikit-learn's StandardScaler, but the API environment doesn't have scikit-learn installed.

#### **Solution**

```bash
# Install scikit-learn
pip install scikit-learn==1.4.2

# Or reinstall API dependencies
cd ~/predictive-ids
pip install -r api/requirements.txt

# Restart the API
# Kill the old process and restart
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

#### **In Docker**
If running in Docker:
```bash
# Rebuild the image with updated requirements
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

### **Issue: 404 Not Found on /api/health**

#### **Error**
```
GET /api/health HTTP/1.1" 404 Not Found
```

#### **Root Cause**
The endpoint is `/` (root), not `/api/health`. The dashboard tries `/api/health` first, then falls back to `/`.

#### **Solution**
This is normal behavior. The dashboard handles the fallback automatically. No action needed.

#### **To fix it properly**, add the health endpoint to api/main.py:
```python
@app.get("/api/health")
def health():
    return {
        "status": "running",
        "service": "OneMoney Predictive IDS API",
        "version": "2.0.0",
        "threshold": THRESHOLD,
        "time": datetime.now(timezone.utc).isoformat(),
    }
```

---

## 🟡 Dashboard Issues

### **Issue: Live Stream not updating**

#### **Symptoms**
- "Waiting for predictions..." message stays
- No alerts appear in Live Stream panel
- Manual test mode works fine

#### **Solutions**

**Check 1: Is inference service running?**
```bash
ps aux | grep inference.service
# Should see: python -m inference.service
```

If not:
```bash
cd ~/predictive-ids && python -m inference.service
```

**Check 2: Are there any alerts in the database?**
```bash
sqlite3 /data/ids.db "SELECT COUNT(*) FROM alerts;"
# Should return a number > 0
```

If 0, you need to:
- Run attacks: `./scripts/simulate_attacks.sh 192.168.64.2`
- Or inject logs: `python3 scripts/inject_unknown_logs.py 100 /data/ids.db`

**Check 3: Is API responding?**
```bash
curl http://localhost:8000/api/alerts
# Should return JSON with alerts
```

**Check 4: Is dashboard connecting?**
- Open browser DevTools (F12)
- Go to Network tab
- Refresh dashboard
- Look for `/api/alerts` requests
- Check if they return 200 (success) or error

---

### **Issue: Manual Test returns error**

#### **Symptoms**
- "Invalid JSON" error when clicking "Test Flow"
- API returns 500 error

#### **Solutions**

**Check 1: Is JSON valid?**
```bash
# Paste your JSON and check validity
echo 'YOUR_JSON_HERE' | jq .
# Should not show syntax errors
```

**Check 2: Do you have all 76 features?**
```bash
echo 'YOUR_JSON_HERE' | jq 'keys | length'
# Should return 76
```

**Check 3: Are values numeric (not strings)?**
```json
// ❌ WRONG (strings)
{"Flow Duration": "1000"}

// ✅ CORRECT (numbers)
{"Flow Duration": 1000}
```

**Check 4: Is API running?**
```bash
curl http://localhost:8000/
# Should return JSON response
```

---

## 🟠 Inference Service Issues

### **Issue: Inference service crashes at startup**

#### **Error**
```
FileNotFoundError: [Errno 2] No such file or directory: 'model/onemoney_cnn.h5'
```

#### **Root Cause**
The model file doesn't exist.

#### **Solution**

**Check 1: Does model exist?**
```bash
ls -lh model/onemoney_cnn.h5
ls -lh model/scaler.pkl
# Both should exist and have reasonable size
```

**Check 2: Is there an alternative model location?**
```bash
find . -name "*.h5" -o -name "cnn*"
```

**Check 3: Do you need to train the model?**
```bash
# First, preprocess data
python -m preprocessing.preprocess

# Then train
python -m model.train

# This creates the model and scaler files
```

---

### **Issue: Inference service stuck or slow**

#### **Symptoms**
- Service runs but doesn't seem to be processing
- Inference logs show no updates
- High CPU usage

#### **Solutions**

**Check 1: Is the service actually running?**
```bash
ps aux | grep inference.service
tail -f ~/predictive-ids/logs/service.log
```

**Check 2: Check database for locks**
```bash
# SQLite might be locked
lsof /data/ids.db
# Kill any stuck processes if needed
```

**Check 3: Restart the service**
```bash
# Kill old process
pkill -f "inference.service"

# Restart
cd ~/predictive-ids && python -m inference.service
```

**Check 4: Check if there are logs to process**
```bash
sqlite3 /data/ids.db "SELECT COUNT(*) FROM logs;"
# Should be > 0 to have something to classify
```

---

## 🔵 Database Issues

### **Issue: "database is locked" error**

#### **Cause**
Multiple processes trying to access SQLite simultaneously.

#### **Solution**

**Option 1: Restart everything**
```bash
# Stop all services
pkill -f "inference.service"
pkill -f "uvicorn"
pkill -f "npm"

# Wait 5 seconds
sleep 5

# Restart
python -m inference.service &
uvicorn api.main:app --host 0.0.0.0 --port 8000 &
cd dashboard && npm start &
```

**Option 2: Check what has the lock**
```bash
lsof /data/ids.db
# Shows which processes have the database open
```

**Option 3: Backup and reset**
```bash
# Backup current database
cp /data/ids.db /data/ids.db.backup

# Reset database
rm /data/ids.db

# Inference service will recreate it
python -m inference.service
```

---

### **Issue: No alerts in database**

#### **Cause**
Inference service hasn't run, or there are no logs to process.

#### **Solution**

**Check 1: Does inference service exist?**
```bash
grep -r "sqlite3" inference/
# Should find references to SQLite
```

**Check 2: Does the service create tables?**
```bash
# Check logs
tail -50 ~/predictive-ids/logs/service.log | grep -i "table\|create"
```

**Check 3: Run the service manually**
```bash
cd ~/predictive-ids
python -m inference.service
# Watch the logs for table creation
```

**Check 4: Inject some test data**
```bash
python3 scripts/inject_unknown_logs.py 10 /data/ids.db
# This creates logs that the service will classify
```

---

## 🟢 Quick Fix Checklist

When something breaks, try this order:

```
1. ✅ Check all services running
   ps aux | grep -E "(inference|uvicorn|npm)"

2. ✅ Check API is responsive
   curl http://localhost:8000/

3. ✅ Check database exists
   ls -lh /data/ids.db

4. ✅ Check model files exist
   ls -lh model/*.{h5,pkl}

5. ✅ Check dependencies installed
   pip list | grep -E "(scikit|tensorflow|fastapi)"

6. ✅ Restart all services
   pkill -f "inference|uvicorn"
   # Start them again

7. ✅ Check logs for errors
   tail -100 ~/predictive-ids/logs/*.log
```

---

## 📝 Common Commands

### **Check Service Status**
```bash
# All services
ps aux | grep -E "(inference|uvicorn|npm)" | grep -v grep

# Inference
ps aux | grep inference.service

# API
ps aux | grep uvicorn

# Dashboard
ps aux | grep npm
```

### **View Logs**
```bash
# Inference service
tail -f ~/predictive-ids/logs/service.log

# API (from terminal where you started it)
# Just look at the terminal output

# Dashboard (from terminal where you started it)
# Just look at the terminal output
```

### **Check Database**
```bash
# Total alerts
sqlite3 /data/ids.db "SELECT COUNT(*) FROM alerts;"

# Recent attacks
sqlite3 /data/ids.db "SELECT timestamp, source_ip, severity FROM alerts LIMIT 10;"

# Database info
sqlite3 /data/ids.db ".tables"
sqlite3 /data/ids.db ".schema alerts"
```

### **Test API**
```bash
# Health
curl http://localhost:8000/

# Get stats
curl http://localhost:8000/api/stats

# Get alerts
curl http://localhost:8000/api/alerts?limit=5

# Get blocked IPs
curl http://localhost:8000/api/blocked

# Test prediction
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"features": {"Flow Duration": 1000, ...}}'
```

---

## 🆘 Still Stuck?

### **Debug Steps**

1. **Isolate the problem**
   - Is it the inference service? API? Dashboard? Database?
   - Test each independently

2. **Check logs**
   ```bash
   tail -100 ~/predictive-ids/logs/service.log
   tail -100 ~/predictive-ids/logs/inference.log
   ```

3. **Check dependencies**
   ```bash
   pip show scikit-learn tensorflow joblib
   ```

4. **Nuclear option: Fresh start**
   ```bash
   # Kill everything
   pkill -f "inference|uvicorn|npm"
   
   # Clear database
   rm /data/ids.db
   
   # Reinstall dependencies
   pip install -r requirements.txt
   
   # Start fresh
   python -m inference.service &
   uvicorn api.main:app --host 0.0.0.0 --port 8000 &
   cd dashboard && npm start &
   ```

---

## 📊 Issue Reference

| Issue | Error Message | Fix |
|-------|---|---|
| Missing sklearn | `ModuleNotFoundError: No module named 'sklearn'` | `pip install scikit-learn` |
| Missing model | `FileNotFoundError: model/onemoney_cnn.h5` | Train model or check path |
| DB locked | `database is locked` | Restart services |
| No alerts | Dashboard shows "Waiting..." | Run attacks or inject logs |
| /api/health 404 | `GET /api/health 404` | Normal - dashboard falls back to `/` |
| Slow predictions | Takes >5 seconds | First call loads model; others are fast |
| Dashboard not connecting | `API unreachable` | Check if API is running on 8000 |

---

**Last Updated:** 2026-06-19
