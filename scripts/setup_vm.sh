#!/bin/bash
set -euo pipefail

echo "Predictive IDS setup — SQLite runtime"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl tcpdump docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"

python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p data/raw data/processed model logs

echo "Setup complete. Next:"
echo "  python -m preprocessing.preprocess"
echo "  python train.py"
echo "  docker compose --profile packet-capture up -d --build"
