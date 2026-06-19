# IP Whitelist & Auto-Blocking System

## Overview

The OneMoney IDS has two complementary protection mechanisms:

1. **Whitelist** — IPs that are explicitly protected and can never be auto-blocked
2. **Auto-Block** — automatic firewall rules that block detected attackers

This document explains both systems and how to safely manage them during attack simulations.

---

## Critical Issue: Auto-Blocking Can Lock You Out

⚠️ **The inference service has `AUTO_BLOCK=true` by default.** This means:

- When the CNN detects an attack from an IP, it automatically adds `iptables DROP` rules
- If you don't whitelist critical IPs first, you can block yourself from:
  - SSH access to the target server
  - API access to the IDS
  - Network connectivity entirely

### What Gets Blocked?

Once blocked via `iptables`, an IP is dropped at the kernel level:
- **INPUT chain** — packets from the source IP are dropped
- **OUTPUT chain** — packets to the destination IP are dropped  
- **FORWARD chain** — routed traffic is dropped

This blocks SSH, HTTP, DNS, everything.

---

## Solution: Whitelist Critical IPs Before Attacks

### Step 1: Start Services

```bash
docker-compose down -v
docker-compose build
docker-compose --profile packet-capture up -d
```

Wait 3-5 seconds for all services to initialize.

### Step 2: Seed the Whitelist

**Before running ANY attacks**, protect critical infrastructure:

```bash
chmod +x ./scripts/seed_whitelist.sh
./scripts/seed_whitelist.sh
```

This adds to the whitelist:
- `172.20.10.1` — your gateway
- `172.20.10.2` — the target server (SSH protected!)
- `172.20.10.3` — your management machine (Mac)
- `127.0.0.1` — loopback

**Whitelisted IPs are immune to auto-blocking**, even if the CNN detects them as attacks.

### Step 3: Run Attacks Safely

```bash
sudo bash ./scripts/run_attack.sh 172.20.10.2 syn
```

Your IPs are protected. The attacker IP (e.g., `172.20.10.4`) will be blocked instead.

---

## How Whitelist Works

### At Inference Time

The inference service (`inference/service.py`) loads the whitelist on startup:

```python
def load_runtime_lists():
    with connect(DB_PATH) as conn:
        _whitelist_cache = {row[0] for row in conn.execute(
            "SELECT ip FROM whitelist WHERE active = 1"
        )}
```

When classifying flows, whitelisted IPs are marked **BENIGN** with 0% confidence:

```python
if is_whitelisted(ip):
    # Skip blocking even if CNN says attack
    return BENIGN_ALERT
```

### At Dashboard Time

The dashboard has a **Whitelist Management** panel where you can:
- **View** all whitelisted IPs and their reasons
- **Add** new IPs (manual protection)
- **Remove** IPs (lift protection)

Changes take effect on the next inference poll (~10 seconds).

---

## Database Schema

The `whitelist` table:

```sql
CREATE TABLE whitelist (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    added_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
);
```

Example rows:

| ip | reason | added_at | active |
|----|--------|----------|--------|
| 172.20.10.1 | gateway | 2026-06-19T15:10:00+00:00 | 1 |
| 172.20.10.2 | protected target | 2026-06-19T15:10:05+00:00 | 1 |
| 172.20.10.4 | testing flow | 2026-06-19T15:15:30+00:00 | 1 |

---

## API Endpoints

### GET /api/whitelist

Retrieve all whitelisted IPs:

```bash
curl http://localhost:8000/api/whitelist
```

Response:

```json
{
  "total": 3,
  "whitelist": [
    {
      "ip": "172.20.10.1",
      "reason": "gateway",
      "added_at": "2026-06-19T15:10:00+00:00",
      "active": true
    }
  ]
}
```

### POST /api/whitelist

Add an IP to the whitelist:

```bash
curl -X POST http://localhost:8000/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "lab machine"}'
```

### DELETE /api/whitelist/{ip}

Remove an IP from the whitelist:

```bash
curl -X DELETE http://localhost:8000/api/whitelist/192.168.1.100
```

---

## Auto-Blocking Details

### Configuration

In `docker-compose.yml`:

```yaml
inference:
  environment:
    - AUTO_BLOCK=true              # Enable auto-blocking
    - PROTECTED_NETWORKS=127.0.0.0/8  # Never block loopback
    - THRESHOLD=0.50               # CNN confidence threshold for blocking
```

### How It Works

When an alert is classified as **ATTACK** with `confidence >= THRESHOLD`:

1. **Check if whitelisted** → if yes, skip blocking
2. **Check if protected** → if yes, skip blocking  
3. **Call iptables** to add DROP rules:
   ```bash
   iptables -A INPUT -s <ip> -j DROP
   iptables -A OUTPUT -d <ip> -j DROP
   iptables -A FORWARD -s <ip> -j DROP
   iptables -A FORWARD -d <ip> -j DROP
   ```
4. **Record in database** → `blocked_ips` table
5. **Persist on restart** → rules are restored from database

### Checking Active Blocks

From the target server console:

```bash
sudo iptables -S | grep DROP
```

From the dashboard:

Dashboard → **Blocked IPs** panel shows all active blocks.

---

## Recovery: If You Get Locked Out

If SSH stops working because an IP was blocked:

1. **Access the server via UTM console** (direct VM terminal, not SSH)
2. **Clear all iptables rules**:
   ```bash
   sudo iptables -F
   sudo iptables -X
   sudo iptables -P INPUT ACCEPT
   sudo iptables -P OUTPUT ACCEPT
   sudo iptables -P FORWARD ACCEPT
   ```
3. **Restart SSH**:
   ```bash
   sudo systemctl restart ssh
   ```
4. **Stop Docker** to prevent re-blocking:
   ```bash
   sudo docker-compose down
   ```
5. **Start fresh with whitelisting**:
   ```bash
   docker-compose up -d
   ./scripts/seed_whitelist.sh
   ```

---

## Best Practices

### Before Each Test Session

1. **Whitelist your infrastructure first**:
   ```bash
   ./scripts/seed_whitelist.sh
   ```

2. **Verify it worked** (dashboard → Whitelist panel, or):
   ```bash
   curl http://localhost:8000/api/whitelist | jq .
   ```

3. **Then run attacks**:
   ```bash
   sudo bash ./scripts/run_attack.sh 172.20.10.2 all
   ```

### Managing Dynamic IPs

If you're testing from a machine with a changing IP:

1. **Add the new IP to whitelist** before running attacks:
   ```bash
   curl -X POST http://localhost:8000/api/whitelist \
     -H "Content-Type: application/json" \
     -d '{"ip": "192.168.1.50", "reason": "test machine"}'
   ```

2. **Or use the dashboard** → Whitelist panel → Add IP

### Monitoring Blocks

Watch real-time blocks:

```bash
watch 'curl -s http://localhost:8000/api/blocked | jq ".total"'
```

Clear all blocks via dashboard:

Dashboard → Flow Predictor → **Clear DB** button (also clears alerts)

---

## Troubleshooting

### "Can't SSH to target — operation timed out"

**Cause:** Your IP was auto-blocked.

**Fix:**
1. Access via UTM console
2. Run `sudo iptables -F` (clears all rules)
3. Stop Docker: `sudo docker-compose down`
4. Restart with whitelisting: `docker-compose up -d && ./scripts/seed_whitelist.sh`

### "Whitelist endpoint returns 404"

**Cause:** API service didn't start (likely import error).

**Fix:**
```bash
docker-compose logs ids-api
```

Check for `ModuleNotFoundError` or other errors. Rebuild if needed:
```bash
docker-compose build --no-cache
docker-compose up -d
```

### "Whitelisted IP still got blocked"

**Cause:** Whitelist changes take ~10 seconds to take effect (next inference poll).

**Fix:** Wait 10 seconds, then check dashboard. If still blocked, manually unblock via:

```bash
curl -X DELETE http://localhost:8000/api/whitelist/<ip>
```

---

## Summary

| Task | Command |
|------|---------|
| Protect critical IPs | `./scripts/seed_whitelist.sh` |
| View whitelist | `curl http://localhost:8000/api/whitelist` |
| Add IP manually | `curl -X POST http://localhost:8000/api/whitelist -d '{"ip":"...","reason":"..."}'` |
| Remove IP | `curl -X DELETE http://localhost:8000/api/whitelist/<ip>` |
| View blocked IPs | Dashboard → Blocked IPs |
| Unblock manually | Dashboard → Blocked IPs → Unblock |
| Clear all blocks | Dashboard → Flow Predictor → Clear DB |
| Emergency unlock (locked out) | UTM console → `sudo iptables -F` |

**Remember:** Always whitelist before running attacks.
