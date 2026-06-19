# Quick Start: Whitelist & Attack Simulation

## 🚀 Safe Attack Testing in 3 Steps

### 1️⃣ Start Services
```bash
docker-compose down -v
docker-compose build
docker-compose --profile packet-capture up -d
sleep 5
```

### 2️⃣ Protect Critical IPs (Required!)
```bash
chmod +x ./scripts/seed_whitelist.sh
./scripts/seed_whitelist.sh
```

✅ **Whitelisted:**
- `172.20.10.1` (gateway)
- `172.20.10.2` (target — SSH protected!)
- `172.20.10.3` (your Mac)

### 3️⃣ Run Attacks Safely
```bash
sudo bash ./scripts/run_attack.sh 172.20.10.2 all
```

Visit dashboard: http://localhost:5173

---

## ⚠️ If You Get Locked Out

1. **Open UTM console** (direct VM terminal, not SSH)
2. **Run**:
   ```bash
   sudo iptables -F
   sudo systemctl restart ssh
   sudo docker-compose down
   ```
3. **Start fresh with whitelisting**:
   ```bash
   docker-compose up -d
   ./scripts/seed_whitelist.sh
   ```

---

## 📋 Common Tasks

| Task | Command |
|------|---------|
| View whitelist | `curl http://localhost:8000/api/whitelist \| jq` |
| Add IP to whitelist | `curl -X POST http://localhost:8000/api/whitelist -H "Content-Type: application/json" -d '{"ip":"1.2.3.4","reason":"test"}'` |
| Remove IP | `curl -X DELETE http://localhost:8000/api/whitelist/1.2.3.4` |
| View blocked IPs | Dashboard → Blocked IPs |
| Clear all blocks | Dashboard → Flow Predictor → Clear DB |

---

## 🎯 Attack Examples

```bash
# Single attack
sudo bash ./scripts/run_attack.sh 172.20.10.2 syn

# All known attacks
sudo bash ./scripts/run_attack.sh 172.20.10.2 known

# All attacks (known + unknown)
sudo bash ./scripts/run_attack.sh 172.20.10.2 all

# Low-risk (detected but never blocked)
sudo bash ./scripts/run_attack.sh 172.20.10.2 --low-risk all

# Heavy intensity
sudo bash ./scripts/run_attack.sh 172.20.10.2 --heavy syn udp icmp
```

---

## 🔑 Key Points

✅ **Always whitelist before attacking** — critical IPs immune to auto-block  
✅ **Dashboard shows real-time alerts** — watch detection happen live  
✅ **CSV export includes all alerts** — Dashboard → Export CSV  
✅ **Multi-source correlation** — network CNN + auth-log anomalies  
✅ **Low-risk mode** — test detection without blocking  

---

For detailed documentation, see: [docs/WHITELIST_AND_BLOCKING.md](docs/WHITELIST_AND_BLOCKING.md)
