#!/bin/bash
# ============================================================
# setup_vm.sh
# Run this on your MAIN Ubuntu VM (inside UTM) to install
# all dependencies and start services.
#
# Usage:
#   chmod +x scripts/setup_vm.sh
#   ./scripts/setup_vm.sh
# ============================================================

set -e   # exit on any error
echo "============================================"
echo " Predictive IDS - VM Setup Script"
echo " Ubuntu 24.04 LTS | CNN + ELK Stack"
echo "============================================"

# ── 1. System update ─────────────────────────────────────
echo "[1/8] Updating system packages..."
sudo apt update -y && sudo apt upgrade -y

# ── 2. Core tools ────────────────────────────────────────
echo "[2/8] Installing core tools..."
sudo apt install -y \
  python3 python3-pip python3-venv \
  git curl wget unzip gnupg \
  wireshark tcpdump \
  net-tools nmap \
  docker.io docker-compose

# Add current user to docker group (no sudo needed after logout/login)
sudo usermod -aG docker "$USER"

# ── 2b. Install MongoDB (requires its own repository on Ubuntu 24.04) ──
echo "[2b] Adding MongoDB 7.0 repository and installing..."
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
  sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
  sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list

sudo apt update -y
sudo apt install -y mongodb-org

sudo systemctl start mongod
sudo systemctl enable mongod
echo "MongoDB installed and running."

# ── 3. Python virtual environment ────────────────────────
echo "[3/8] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# ── 4. Python dependencies ───────────────────────────────
echo "[4/8] Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# ── 5. Create required directories ───────────────────────
echo "[5/8] Creating project directories..."
mkdir -p data/raw data/processed data/models logs

# ── 6. Start ELK + MongoDB via Docker ───────────────────
echo "[6/8] Starting ELK Stack + MongoDB with Docker..."
docker-compose up -d

echo "Waiting for Elasticsearch to be ready..."
until curl -s http://localhost:9200/_cluster/health | grep -q '"status"'; do
  echo "  ... still waiting ..."
  sleep 5
done
echo "Elasticsearch is up!"

# ── 7. Install Filebeat ──────────────────────────────────
echo "[7/8] Installing Filebeat..."
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.0-amd64.deb
sudo dpkg -i filebeat-8.13.0-amd64.deb
rm filebeat-8.13.0-amd64.deb

# Copy config
sudo cp config/filebeat.yml /etc/filebeat/filebeat.yml
sudo systemctl enable filebeat
sudo systemctl start filebeat

# ── 8. Summary ───────────────────────────────────────────
echo "[8/8] Setup complete!"
echo ""
echo "============================================"
echo " Services running:"
echo "  Elasticsearch : http://localhost:9200"
echo "  Kibana        : http://localhost:5601"
echo "  Logstash      : localhost:5044 (Beats input)"
echo "  MongoDB       : localhost:27017"
echo ""
echo " Next steps:"
echo "  1. Download CICIDS2017 CSVs → data/raw/"
echo "  2. source venv/bin/activate"
echo "  3. python -m preprocessing.preprocess"
echo "  4. python -m model.train"
echo "  5. python -m model.evaluate"
echo "  6. python -m inference.inference_service &"
echo "  7. uvicorn api.main:app --host 0.0.0.0 --port 8000 &"
echo "============================================"