#!/usr/bin/env python3
import json
import random
import time
import sys
from datetime import datetime
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "ids_db"
LOGS_COLL = "logs"

FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Len", "Bwd Header Len",
    "Fwd Pkts/s", "Bwd Pkts/s",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt",
    "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
    "Down/Up Ratio", "Pkt Size Avg",
    "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
    "Init Fwd Win Byts", "Init Bwd Win Byts",
    "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

def generate_benign_flow():
    flow = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": "192.168.64.5",
        "source_host": "attacker-vm",
        "dest_ip": "192.168.64.4",
        "label": "BENIGN"
    }
    for feature in FEATURES:
        if "Pkts" in feature:
            flow[feature] = random.randint(5, 50)
        elif "Len" in feature or "Byts" in feature:
            flow[feature] = random.randint(100, 1500)
        else:
            flow[feature] = round(random.uniform(0.1, 1000), 2)
    return flow

def generate_attack_flow():
    flow = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": "192.168.64.5",
        "source_host": "attacker-vm",
        "dest_ip": "192.168.64.4",
        "label": "ATTACK"
    }
    for feature in FEATURES:
        if "Pkts" in feature:
            flow[feature] = random.randint(500, 5000)
        elif "SYN Flag" in feature:
            flow[feature] = random.randint(400, 1000)
        else:
            flow[feature] = round(random.uniform(10, 100), 2)
    return flow

def send_to_mongo(flow):
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client[MONGO_DB]
        coll = db[LOGS_COLL]
        coll.insert_one(flow)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

attack_mode = len(sys.argv) > 1 and sys.argv[1] == "attack"

try:
    while True:
        flow = generate_attack_flow() if attack_mode else generate_benign_flow()
        if send_to_mongo(flow):
            label = "ATTACK" if attack_mode else "BENIGN"
            print(f"[+] {label}")
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\n[*] Stopped")
