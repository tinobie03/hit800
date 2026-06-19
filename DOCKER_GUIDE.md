# Docker Setup for Packet Capture & IDS

How the packet capture system works in Docker and how to run it.

---

## 🐳 **Docker Basics: Network & Capabilities**

### The Challenge

Normal Docker containers are isolated from the host:
- Can't see other containers' traffic
- Can't sniff packets from the host network
- Don't have permissions to access raw sockets

### The Solution

Two special Docker configurations enable packet capture:

| Setting | Purpose | Why Needed |
|---------|---------|-----------|
| `--net host` | Container shares host's network namespace | Can see ALL packets on host interface |
| `--privileged true` | Container gets all Linux capabilities | Grants CAP_NET_RAW and CAP_NET_ADMIN |

---

## 📋 **Our Docker Setup**

### Services

```yaml
# Packet Capture Service (NEW)
packet-capture:
  - Runs: python -m inference.packet_capture
  - Networking: --net host (sees all host traffic)
  - Privileges: privileged: true (can sniff packets)
  - Profile: packet-capture (optional, only runs on demand)

# Inference Service (EXISTING)
inference:
  - Runs: python -m inference.service
  - Networking: --net host (can use iptables)
  - Privileges: privileged: true (for IP blocking)

# API Service (EXISTING)
api:
  - Runs: FastAPI
  - Networking: --net host (port 8000 on host)
  - Privileges: privileged: true
```

### Shared Volumes

All services share:
- `/data` → SQLite database (`ids.db`)
- `./logs` → Log files
- `./model` → Pre-trained CNN model
- `./data/processed` → Feature metadata

---

## 🚀 **How to Run with Docker**

### Option 1: Run Everything with Docker Compose (Simplest)

```bash
cd ~/predictive-ids

# Build the images
docker-compose build

# Start all services (inference, api, WITHOUT packet capture)
docker-compose up -d inference api

# OR: Start with packet capture included
docker-compose --profile packet-capture up -d
```

### Option 2: Run Packet Capture Only (with Inference & API)

```bash
# Start in order:
docker-compose up -d packet-capture
docker-compose up -d inference
docker-compose up -d api

# Verify they're running
docker-compose ps
```

### Option 3: Run Individual Services

```bash
# Just packet capture
docker-compose run --rm packet-capture

# Just inference
docker-compose run --rm inference

# Just API
docker-compose run --rm api
```

---

## 🔍 **Understanding Docker Networking for Packet Capture**

### Standard Docker Networking (Doesn't Work)

```
Host Network Interface (eth0)
        ↓
Packets from attacker (192.168.64.3)
        ↓
[X] Container (isolated in docker0 bridge network)
    └─ Can't see host traffic
    └─ Can't sniff packets
```

### Host Network Mode (Works)

```
Host Network Interface (eth0)
        ↓
Packets from attacker (192.168.64.3)
        ↓
[✓] Container (shares host network namespace)
    └─ network_mode: host
    └─ Can see ALL traffic
    └─ Can sniff packets with scapy
```

### Linux Capabilities

```
Default container: (no CAP_NET_RAW, no CAP_NET_ADMIN)
    └─ scapy.sniff() → PermissionError

privileged: true:
    ├─ CAP_NET_RAW       ✓ (raw sockets)
    ├─ CAP_NET_ADMIN     ✓ (network admin)
    ├─ CAP_SYS_ADMIN     ✓ (system admin)
    └─ ... (all capabilities)
```

---

## 📊 **Docker Data Flow**

```
Attacker VM (192.168.64.3)
        ↓
Network packets (on eth0)
        ↓
[Docker] packet-capture container
├─ --net host (sees eth0)
├─ --privileged (can sniff)
├─ scapy.sniff() on eth0
└─ Writes to /data/ids.db
        ↓
[Docker] inference container
├─ Reads /data/ids.db (shared volume)
├─ Classifies with CNN
├─ Writes alerts to /data/ids.db
└─ Logs to ./logs/service.log
        ↓
[Docker] api container
├─ Reads /data/ids.db
├─ Serves /api/alerts
└─ Listens on port 8000
        ↓
Web Browser
└─ Connects to http://host:8000/
└─ Displays dashboard
```

---

## ⚙️ **Docker Compose Configuration Explained**

### Packet Capture Service

```yaml
packet-capture:
  build:
    context: .
    dockerfile: inference/Dockerfile
  container_name: ids-packet-capture
  
  # CRITICAL: Share host network to sniff packets
  network_mode: host
  
  # CRITICAL: Grant capabilities for raw socket access
  privileged: true
  
  # Keep running if it crashes
  restart: unless-stopped
  
  # Environment variables for configuration
  environment:
    - DB_PATH=/data/ids.db           # Where to write logs
    - CAPTURE_INTERFACE=eth0          # Which interface to sniff
  
  # Shared storage with other services
  volumes:
    - ./logs:/app/logs                # Log output
    - ./data:/data                    # SQLite database
  
  # Override default command
  command: ["python", "-m", "inference.packet_capture"]
  
  # Optional: only run when explicitly requested
  profiles:
    - packet-capture
```

---

## 🎯 **Running the Full System with Docker**

### Complete Workflow

**Step 1: Build images**
```bash
docker-compose build
```

**Step 2: Start all services**
```bash
# With packet capture
docker-compose --profile packet-capture up -d

# OR without (if testing with manual log injection)
docker-compose up -d inference api
```

**Step 3: Verify all containers are running**
```bash
docker-compose ps

# Output:
# NAME                 STATUS
# ids-packet-capture   Up (healthy)
# ids-inference        Up (healthy)
# ids-api              Up
```

**Step 4: Check logs**
```bash
# Packet capture logs
docker-compose logs -f packet-capture

# Inference logs
docker-compose logs -f inference

# API logs
docker-compose logs -f api
```

**Step 5: Run attacks**
```bash
# On attacker VM
./scripts/simulate_attacks.sh 192.168.64.2
```

**Step 6: Watch detection in real-time**
```bash
# Terminal 1: Watch packet capture
docker-compose logs -f packet-capture
# Output: "Flushed 45 flows to SQLite"

# Terminal 2: Watch inference
docker-compose logs -f inference
# Output: "Classified 45 entries | ATTACK: 28 | BENIGN: 17"

# Terminal 3: Open dashboard
open http://localhost:3000
# Go to Flow Predictor → Live Stream
# Watch alerts appear!
```

---

## 🛠️ **Dockerfile Changes**

The `inference/Dockerfile` now includes:
```dockerfile
RUN apt-get install -y --no-install-recommends \
    iptables iproute2 curl libpcap-dev
```

**Why?**
- `libpcap-dev`: Required by scapy for packet capture
- `iptables`: For IP blocking (inference service)
- `iproute2`: For network configuration
- `curl`: For health checks

---

## 📝 **Docker Profiles Explained**

```yaml
profiles:
  - packet-capture
```

This means:
- Service is **optional** by default
- Only runs when explicitly requested: `docker-compose --profile packet-capture up`
- Prevents accidentally starting packet capture when not needed
- Cleaner for multiple environments

```bash
# Start without packet capture
docker-compose up -d inference api
# → Only inference + api run

# Start with packet capture
docker-compose --profile packet-capture up -d
# → All three services (packet-capture, inference, api) run
```

---

## 🚨 **Common Issues & Solutions**

### Issue: "Permission denied" in packet-capture container

**Cause**: Missing `privileged: true` or `--net host`

**Solution**: Verify docker-compose.yml has:
```yaml
privileged: true
network_mode: host
```

### Issue: Packet capture not seeing traffic

**Cause**: Wrong interface name (eth0 vs enp0s1 vs docker0)

**Solution**: Check your interface and update:
```bash
# Find your interface
ip addr show

# Update environment variable
environment:
  - CAPTURE_INTERFACE=enp0s1  # Use your actual interface
```

### Issue: Container can't write to /data

**Cause**: Missing volume mount

**Solution**: Verify docker-compose.yml has:
```yaml
volumes:
  - ./data:/data
```

### Issue: "Address already in use" for port 8000

**Cause**: API service conflicts with existing service

**Solution**: Either stop the conflicting service or change the port:
```yaml
ports:
  - "8000:8000"  # Change first number to different port
```

---

## 📈 **Performance in Docker**

### Resource Usage

```
Packet Capture:    10-20% CPU (packet sniffing)
Inference:         10-15% CPU (CNN inference)
API:               <1% CPU
Memory:            ~500MB total (model + buffers)
```

### Networking Overhead

- `--net host`: ~0% overhead (no veth bridge)
- `--privileged`: ~0% overhead (just capability bits)

### Disk Usage

```
Image size: ~2.5GB (python:3.11 + dependencies)
Database: ~500MB-1GB (depends on traffic volume)
Logs: ~100MB
```

---

## 🔄 **Docker Restart Policy**

```yaml
restart: unless-stopped
```

This means:
- Container auto-restarts if it crashes ✓
- Container won't restart if you stop it manually ✓
- Container starts when docker daemon restarts ✓

```bash
# Start all services (with restart policy)
docker-compose up -d

# Stop all services (won't auto-restart)
docker-compose down

# Force stop a container (will auto-restart)
docker-compose kill packet-capture
```

---

## 📚 **Docker vs Bare Metal**

### Docker Approach (Recommended)
```
✓ Isolated environments
✓ Easy deployment
✓ Reproducible everywhere
✓ Clean logs
✗ Slightly more overhead
```

### Bare Metal Approach
```
✓ Maximum performance
✓ Direct host access
✗ System dependencies
✗ Harder to reproduce
```

### For This Project
**Use Docker** because:
1. Isolation prevents accidentally breaking host
2. Easy to restart services
3. Reproducible for thesis/demo
4. Works the same on Mac/Linux/Windows with Docker Desktop

---

## ✅ **Quick Start with Docker**

```bash
# 1. Build
docker-compose build

# 2. Start everything
docker-compose --profile packet-capture up -d

# 3. Verify
docker-compose ps

# 4. Check logs
docker-compose logs -f

# 5. Run attacks (from attacker VM)
./scripts/simulate_attacks.sh 192.168.64.2

# 6. Open dashboard
open http://localhost:3000
```

---

## 📖 **Docker Compose Reference**

```bash
# View running containers
docker-compose ps

# View logs (all or specific)
docker-compose logs              # All
docker-compose logs -f           # Follow (live)
docker-compose logs packet-capture   # One service

# Stop/start services
docker-compose up -d SERVICE     # Start
docker-compose stop SERVICE      # Stop
docker-compose restart SERVICE   # Restart

# Remove everything
docker-compose down              # Stop containers
docker-compose down -v           # Stop + remove volumes

# Execute command in running container
docker-compose exec SERVICE bash # Shell into container
docker-compose exec SERVICE ls /data  # List files
```

---

This setup ensures your IDS runs reliably in Docker with full packet capture capabilities! 🎯
