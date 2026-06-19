# Attack Tuning Guide

How to adjust attack parameters to avoid crashing the target VM while still triggering IDS detection.

---

## 🎯 **Problem: Attacks Are Too Aggressive**

### **Symptoms**
- Target VM becomes unreachable ("No route to host")
- SSH connections time out
- Network completely saturated
- VM hangs or crashes
- hping3 process gets killed

### **Root Cause**
The `--flood` flag sends **unlimited packets as fast as possible**, which can:
- Overwhelm the target network interface
- Exhaust VM memory
- Trigger kernel panic
- Cause VM to hang or reset

---

## ✅ **Solution: Use Rate Limiting**

Instead of `--flood`, use the `-i` parameter to control packet rate.

### **hping3 Parameters**

```bash
# ❌ UNLIMITED (crashes target)
hping3 -S --flood -p 80 TARGET

# ✅ CONTROLLED (detectable but not crashing)
hping3 -S -i u10000 -p 80 TARGET
```

### **What `-i u10000` means**
- `-i u10000` = send 1 packet every 10,000 microseconds
- 10,000 μs = 10 ms = 100 packets per second (100 pps)
- 100 pps is **detectable** but **not destructive**

---

## 📊 **Recommended Packet Rates**

| Rate | Parameter | Packets/Sec | Effect |
|------|-----------|------------|--------|
| **Stealth** | `-i u100000` | 10 pps | Slow, hard to detect |
| **Moderate** | `-i u50000` | 20 pps | Balanced |
| **Aggressive** | `-i u10000` | 100 pps | Detectable, safe |
| **Very Aggressive** | `-i u1000` | 1,000 pps | ⚠️ May cause issues |
| **Unlimited** | `--flood` | 100,000+ pps | 🔴 CRASHES TARGET |

---

## 🔧 **Current Attack Parameters**

### **Modified Attack Scripts**

**SYN Flood:**
```bash
sudo hping3 -S -i u10000 -p 80 $TARGET_IP
# 100 packets/sec to port 80 for 15 seconds
# Total: ~1,500 SYN packets
```

**UDP Flood:**
```bash
sudo hping3 -2 -i u10000 -p 53 $TARGET_IP
# 100 packets/sec to port 53 for 10 seconds
# Total: ~1,000 UDP packets
```

**ICMP Flood:**
```bash
sudo hping3 -1 -i u10000 $TARGET_IP
# 100 packets/sec ICMP for 10 seconds
# Total: ~1,000 ICMP packets
```

---

## 🚀 **Tuning for Your Environment**

### **If attacks still crash the target:**

**Reduce rate further:**
```bash
# Even more conservative
hping3 -S -i u50000 -p 80 $TARGET_IP  # 20 pps

# Ultra-conservative
hping3 -S -i u100000 -p 80 $TARGET_IP  # 10 pps
```

### **If attacks aren't detected:**

**Increase rate:**
```bash
# More aggressive but still safe
hping3 -S -i u5000 -p 80 $TARGET_IP   # 200 pps

# Very aggressive
hping3 -S -i u1000 -p 80 $TARGET_IP   # 1000 pps
# ⚠️ Test this carefully!
```

---

## 📝 **Modify Attack Scripts**

Edit each script to adjust the `-i` parameter:

### **attack_syn_flood.sh**
```bash
# Current (safe, moderate)
sudo hping3 -S -i u10000 -p 80 $TARGET_IP

# Adjust here:
# u5000  = 200 pps (more aggressive)
# u10000 = 100 pps (current)
# u20000 = 50 pps (less aggressive)
```

### **attack_udp_flood.sh**
```bash
# Current (safe, moderate)
sudo hping3 -2 -i u10000 -p 53 $TARGET_IP
```

### **attack_icmp_flood.sh**
```bash
# Current (safe, moderate)
sudo hping3 -1 -i u10000 $TARGET_IP
```

---

## 🧪 **Testing Strategy**

### **Stage 1: Verify Connectivity**
```bash
ping -c 3 TARGET_IP
# Should get responses
```

### **Stage 2: Test with Very Conservative Rate**
```bash
# 10 packets per second (very safe)
sudo hping3 -S -i u100000 -p 80 TARGET_IP &
sleep 10
pkill hping3

# Check target is still alive
ping -c 3 TARGET_IP
# Should still respond
```

### **Stage 3: Gradually Increase**
```bash
# Try 20 pps
sudo hping3 -S -i u50000 -p 80 TARGET_IP &
sleep 10
pkill hping3
ping -c 3 TARGET_IP

# Try 50 pps
sudo hping3 -S -i u20000 -p 80 TARGET_IP &
sleep 10
pkill hping3
ping -c 3 TARGET_IP

# Try 100 pps (current default)
sudo hping3 -S -i u10000 -p 80 TARGET_IP &
sleep 10
pkill hping3
ping -c 3 TARGET_IP
```

### **Stage 4: Run Full Simulation**
```bash
./scripts/simulate_attacks.sh TARGET_IP
```

---

## 🎓 **For Your Thesis**

Document the attack parameters:

```
Table: Attack Parameters Used

Attack Type | Rate (pps) | Duration (s) | Total Packets | Effect
SYN Flood   | 100        | 15           | 1,500         | Detectable
UDP Flood   | 100        | 10           | 1,000         | Detectable
ICMP Flood  | 100        | 10           | 1,000         | Detectable

Note: Attacks use controlled rates (-i parameter) to avoid overwhelming
the target while remaining detectable by the IDS. This demonstrates
the IDS's ability to detect distributed, rate-limited attacks that
mimic real-world attack patterns.
```

---

## 🔬 **Advanced: Multi-Stage Attacks**

Create attacks that gradually escalate:

```bash
# Slow start (stealth)
# Then ramp up (gradual increase)
# Then peak (detection)

# Stage 1: Slow (20 pps for 30s)
sudo hping3 -S -i u50000 -p 80 $TARGET_IP &
sleep 30
pkill hping3

# Stage 2: Medium (100 pps for 30s)
sudo hping3 -S -i u10000 -p 80 $TARGET_IP &
sleep 30
pkill hping3

# Stage 3: Fast (500 pps for 10s)
sudo hping3 -S -i u2000 -p 80 $TARGET_IP &
sleep 10
pkill hping3
```

This shows **progressive attack detection** in your thesis!

---

## ⚠️ **Safety Precautions**

### **Always Have an Escape Plan**

```bash
# If things go wrong, kill all hping3 processes immediately
pkill -9 hping3

# If VM is unresponsive, restart it
docker-compose restart ids-main

# Monitor target during attacks
ping -c 100 TARGET_IP &
# Stop pinging if target stops responding
```

### **Resource Monitoring**

```bash
# On target VM, monitor in another terminal
watch -n 1 'ps aux | head -20'
watch -n 1 'free -h'
watch -n 1 'netstat -an | grep ESTABLISHED | wc -l'
```

---

## 📊 **Comparison: Before vs After**

### **Before (--flood)**
```
Attack: hping3 -S --flood -p 80 TARGET
Packet Rate: Unlimited (100,000+ pps)
Result: Target crashes, unresponsive
Logs: None generated (VM down)
Usefulness: Bad (proves IDS doesn't work)
```

### **After (-i u10000)**
```
Attack: hping3 -S -i u10000 -p 80 TARGET
Packet Rate: Controlled (100 pps)
Result: Target stays up, logs generated
Logs: Thousands of SYN packets detected
Usefulness: Good (proves IDS works)
```

---

## 🎯 **Quick Reference**

```bash
# SAFE (start here)
hping3 -S -i u50000 -p 80 TARGET    # 20 pps

# MODERATE (recommended for demos)
hping3 -S -i u10000 -p 80 TARGET    # 100 pps

# AGGRESSIVE (test carefully)
hping3 -S -i u5000 -p 80 TARGET     # 200 pps

# VERY AGGRESSIVE (⚠️ may cause issues)
hping3 -S -i u1000 -p 80 TARGET     # 1000 pps

# ❌ DO NOT USE
hping3 -S --flood -p 80 TARGET      # UNLIMITED - crashes target
```

---

## 🧠 **Understanding hping3 Parameters**

```bash
hping3 [options] TARGET

# Common options:
-S              SYN flag (TCP)
-2              UDP mode
-1              ICMP mode
-p PORT         Target port
-i INTERVAL     Interval between packets
-c COUNT        Number of packets to send

# Interval format:
-i u1000       1000 microseconds = 1 ms = 1000 pps
-i u10000      10000 microseconds = 10 ms = 100 pps
-i u100000     100000 microseconds = 100 ms = 10 pps
-i u1000000    1000000 microseconds = 1 s = 1 pps

--flood         Unlimited (DON'T USE - crashes target)
```

---

## Summary

| Aspect | Value |
|--------|-------|
| **Recommended rate** | 100 pps (-i u10000) |
| **Safe range** | 10-200 pps |
| **Danger zone** | >500 pps |
| **Avoid** | --flood (unlimited) |
| **Detection** | 50+ pps usually detectable |
| **Duration** | 10-30 seconds per attack |

The current scripts use **safe, detectable parameters** that won't crash your target VM! 🎉
