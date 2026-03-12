# Predictive Intrusion Detection System
### VMware-Based Mobile Financial Services Environments
**CNN Deep Learning | ELK Stack | FastAPI | React Dashboard**
*Tinotenda Belladona Chatora — MTech Cloud Computing — HIT 800*

---

## What You Have Right Now

| | Status |
|---|---|
| UTM installed on Mac | ✅ Done |
| One Ubuntu VM created in UTM | ✅ Done |
| This project folder | ✅ Done |
| Second (attacker) VM | ❌ Need to create |
| CICIDS2017 dataset downloaded | ❌ Need to download |
| Python packages installed | ❌ Need to install |
| ELK Stack running | ❌ Need to start |

---

## Understanding the Two VMs

You need **two Ubuntu VMs running inside UTM** on your Mac. They need to be able to see each other over a network. Here is what each one does:

```
Your Mac (host)
│
├── UTM
│    ├── VM 1 — MAIN VM (ids-vm)          ← "the defender"
│    │         Runs the IDS project
│    │         Runs ELK stack (Docker)
│    │         Runs CNN inference service
│    │         Runs API + Dashboard
│    │
│    └── VM 2 — ATTACKER VM (attacker-vm) ← "the attacker"
│              Sends fake attacks to VM 1
│              Used only for testing
│              No project files needed (just scripts)
```

Both VMs must be on the **same UTM network** so VM 2 can send traffic to VM 1.

---

## Understanding Where data/raw Lives

`data/raw/` is a folder **inside the project folder on your MAIN VM**. It does not exist on your Mac. The full path on the VM will be:

```
/home/bella/predictive-ids/data/raw/
```

When you download the CICIDS2017 dataset on your Mac, you need to **transfer those CSV files into this folder on the VM**. This guide explains exactly how to do that.

```
MAIN VM filesystem:
/home/bella/
└── predictive-ids/           ← project root
    ├── README.md
    ├── data/
    │   ├── raw/              ← CICIDS2017 CSV files go HERE
    │   ├── processed/        ← auto-created when you run preprocessing
    │   └── models/           ← auto-created when you run training
    ├── preprocessing/
    ├── model/
    ├── inference/
    ├── api/
    ├── config/
    └── scripts/
```

---

## PROJECT STRUCTURE

```
predictive-ids/
├── README.md                      ← This file
├── requirements.txt               ← Python packages list
├── docker-compose.yml             ← Starts Elasticsearch, Kibana, Logstash, MongoDB
├── .env                           ← Config variables (ports, hostnames)
│
├── data/
│   ├── raw/                       ← PUT CICIDS2017 CSV FILES HERE (you copy them in)
│   ├── processed/                 ← Created automatically by preprocess.py
│   └── models/                    ← Created automatically, stores trained CNN
│
├── preprocessing/
│   └── preprocess.py              ← Cleans data, applies SMOTE, saves arrays
│
├── model/
│   ├── cnn_model.py               ← CNN architecture definition
│   ├── train.py                   ← Runs the CNN training
│   └── evaluate.py                ← Generates metrics, confusion matrix, comparison
│
├── inference/
│   └── inference_service.py       ← Live detection loop (reads logs, classifies them)
│
├── api/
│   └── main.py                    ← FastAPI backend (dashboard reads from this)
│
├── config/
│   ├── logstash.conf              ← Tells Logstash how to parse and store logs
│   └── filebeat.yml               ← Tells Filebeat which log files to ship
│
├── scripts/
│   ├── setup_vm.sh                ← Run this once on MAIN VM to install everything
│   └── simulate_attacks.sh        ← Run this on ATTACKER VM to test detection
│
└── logs/                          ← Training curves, confusion matrices saved here
```

---

---

# FULL STEP-BY-STEP IMPLEMENTATION

---

## STAGE 0 — Get the Project Folder onto Your MAIN VM

You need to get this `predictive-ids` folder from your Mac onto your Ubuntu VM. The easiest way is GitHub.

### Step 0.1 — Push to GitHub (do this on your Mac)

Open Terminal on your **Mac** and run:

```bash
cd /path/to/predictive-ids        # wherever the folder is saved on your Mac

git init
git add .
git commit -m "Initial project setup"
```

Then go to **github.com** in your browser:
1. Click the **+** button → New repository
2. Name it `predictive-ids`
3. Set it to **Private**
4. Click Create repository
5. GitHub will show you a command like this — copy and run it:

```bash
git remote add origin https://github.com/YOUR_USERNAME/predictive-ids.git
git branch -M main
git push -u origin main
```

### Step 0.2 — Clone onto your MAIN VM

Open your Ubuntu VM in UTM. Log in. Then run:

```bash
sudo apt install -y git
git clone https://github.com/YOUR_USERNAME/predictive-ids.git
cd predictive-ids
```

You now have the project at `/home/bella/predictive-ids/` on your VM.

---

## STAGE 1 — Set Up Your MAIN VM (ids-vm)

This is the Ubuntu VM you already created. Run all of the following commands **inside this VM**.

### Step 1.1 — Find your MAIN VM's IP address

In your main Ubuntu VM terminal, run:

```bash
ip addr show
```

Look for a line like `inet 192.168.64.2/24` under `enp0s1` or `eth0`. Write down this IP address — you will need it later.

> Example: `192.168.64.2`  ← your main VM IP

### Step 1.2 — Run the setup script

```bash
cd predictive-ids
chmod +x scripts/setup_vm.sh
./scripts/setup_vm.sh
```

This script does the following automatically (takes about 5–10 minutes):
- Updates Ubuntu packages
- Installs Python 3, pip, git, Wireshark, tcpdump
- Installs Docker and Docker Compose
- Creates a Python virtual environment in `venv/`
- Installs all Python packages from `requirements.txt`
- Creates the `data/raw`, `data/processed`, `data/models`, `logs` folders
- Starts Elasticsearch, Kibana, Logstash, and MongoDB using Docker
- Installs and starts Filebeat

### Step 1.3 — Verify services are running

```bash
docker-compose ps
```

You should see four containers running:

```
NAME                STATUS
ids-elasticsearch   Up (healthy)
ids-kibana          Up
ids-logstash        Up
ids-mongodb         Up
```

Then test Elasticsearch:

```bash
curl http://localhost:9200/_cluster/health
```

You should see something like: `{"status":"yellow"` or `"green"` — both are fine.

### Step 1.4 — Open Kibana from your Mac browser

On your **Mac**, open Safari or Chrome and go to:

```
http://192.168.64.2:5601
```

(Replace `192.168.64.2` with your actual main VM IP from Step 1.1)

Kibana should load. If it shows a loading spinner, wait 1–2 minutes — it takes time to start.

---

## STAGE 2 — Create the ATTACKER VM

### Step 2.1 — Create a new VM in UTM

1. Open **UTM** on your Mac
2. Click the **+** button → Create a New Virtual Machine
3. Choose **Virtualize** (not Emulate)
4. Choose **Linux**
5. For the ISO image, use the same Ubuntu ISO you used before (Ubuntu 24.04 LTS)
   - If you don't have it, download from: https://ubuntu.com/download/server (Server version is fine, it's smaller)
6. Settings:
   - RAM: **2048 MB** (2 GB is enough)
   - CPU: **2 cores**
   - Storage: **20 GB**
7. **IMPORTANT — Network setting:**
   - In UTM VM settings, find **Network**
   - Change the network mode to **Host Only**
   - Do the same for your MAIN VM — change it to **Host Only** too
   - This puts both VMs on the same private network so they can talk to each other

> **Why Host Only?** With Host Only networking, both VMs get an IP like `192.168.64.x`. They can reach each other, but cannot access the real internet. This is safe for attack simulations.

8. Click **Save** and start the VM
9. Install Ubuntu normally — username: `attacker`, password: your choice

### Step 2.2 — Find the ATTACKER VM's IP address

Inside the attacker VM terminal:

```bash
ip addr show
```

Write down its IP (e.g., `192.168.64.3`).

### Step 2.3 — Confirm the two VMs can see each other

From the **ATTACKER VM**, ping the **MAIN VM**:

```bash
ping 192.168.64.2
```

You should see replies like `64 bytes from 192.168.64.2`. Press `Ctrl+C` to stop.

From the **MAIN VM**, ping the **ATTACKER VM**:

```bash
ping 192.168.64.3
```

If both pings work, the VMs are connected correctly.

### Step 2.4 — Copy the attack script to the Attacker VM

You only need one file on the attacker VM: `scripts/simulate_attacks.sh`.

**Option A — SCP from main VM to attacker VM:**

On the **MAIN VM**, run:

```bash
scp scripts/simulate_attacks.sh attacker@192.168.64.3:/home/attacker/
```

**Option B — Type it manually or clone just the scripts folder:**

On the **ATTACKER VM**:

```bash
git clone https://github.com/YOUR_USERNAME/predictive-ids.git
```

---

## STAGE 3 — Download the CICIDS2017 Dataset

The CICIDS2017 dataset is a collection of real network traffic CSV files with labelled attack types. Your CNN model trains on these files.

### Step 3.1 — Download on your Mac

1. Open this URL on your **Mac**: https://www.unb.ca/cic/datasets/ids-2017.html
2. Scroll down and look for the download link (it may say "Download Dataset" or ask you to fill a short form)
3. You want the **CSV version** — look for a folder called **MachineLearningCSV** or **GeneratedLabelledFlows**
4. Download all 8 CSV files. They have names like:
   ```
   Monday-WorkingHours.pcap_ISCX.csv
   Tuesday-WorkingHours.pcap_ISCX.csv
   Wednesday-workingHours.pcap_ISCX.csv
   Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
   Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
   Friday-WorkingHours-Morning.pcap_ISCX.csv
   Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
   Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
   ```
   Total size is about **1.5 GB**.

> **Alternative if the UNB site is slow:** You can also find CICIDS2017 on Kaggle at https://www.kaggle.com/datasets/cicdataset/cicids2017 — search "CICIDS2017" — you need a free Kaggle account.

### Step 3.2 — Transfer CSV files to data/raw/ on the MAIN VM

The `data/raw/` folder is located at:
```
/home/bella/predictive-ids/data/raw/
```

**Transfer method — SCP from your Mac to the VM:**

Open **Terminal on your Mac** and run (one command per file, or use a wildcard):

```bash
# Transfer all CSV files at once
# Replace /Users/Tinotenda/Downloads/ with wherever you saved the files
# Replace 192.168.64.2 with your main VM IP

scp /Users/Tinotenda/Downloads/*.csv bella@192.168.64.2:/home/bella/predictive-ids/data/raw/
```

It will ask for your VM password. Type it and press Enter. Wait for all files to copy.

**Alternative — UTM Shared Folder:**

1. In UTM, go to your main VM settings → **Sharing** → enable Shared Directory
2. Point it to the folder on your Mac where you downloaded the CSVs
3. On the VM, the shared folder appears at `/media/share/` or similar
4. Copy from there:
   ```bash
   cp /media/share/*.csv /home/bella/predictive-ids/data/raw/
   ```

### Step 3.3 — Verify the files are there

On your **MAIN VM**:

```bash
ls -lh /home/bella/predictive-ids/data/raw/
```

You should see all 8 CSV files listed with their sizes.

---

## STAGE 4 — Preprocess the Dataset

Now that the CSV files are in `data/raw/`, run the preprocessing script. This cleans the data, applies SMOTE, and saves it as numpy arrays ready for the CNN.

```bash
# Make sure you are in the project folder
cd /home/bella/predictive-ids

# Activate the Python virtual environment
source venv/bin/activate

# Run preprocessing
python -m preprocessing.preprocess
```

**What this does step by step:**
1. Loads all 8 CSV files from `data/raw/` and combines them into one big table
2. Removes rows with missing or infinite values
3. Strips unnecessary columns (IP addresses, timestamps)
4. Encodes labels: BENIGN = 0, any attack type = 1
5. Splits data: 70% training, 15% validation, 15% testing
6. Scales all feature values to 0–1 range using MinMaxScaler
7. Applies SMOTE to the training set to balance attack vs normal samples
8. Reshapes data into tensors for the CNN: shape `(samples, 1, 78)`
9. Saves everything to `data/processed/`

**Expected terminal output:**
```
Loading CSVs...  [8/8]
Combined dataset shape: (2830743, 79)
Cleaning dataset...
Rows after cleaning: 2827876
Binary label distribution:
  0 (BENIGN): 2271320
  1 (ATTACK):  556556
Before SMOTE: [2271320  556556]
After SMOTE:  [2271320 2271320]
X_train: (3179848, 1, 78)
X_val:   (424684, 1, 78)
X_test:  (424684, 1, 78)
Scaler saved → data/processed/scaler.pkl
Preprocessing complete.
```

> This step takes about **5–15 minutes** depending on your VM's RAM.

---

## STAGE 5 — Train the CNN Model

```bash
python -m model.train
```

**What happens:**
- Builds the CNN (Conv1D → BatchNorm → MaxPooling → Dropout → Dense → Softmax)
- Trains for up to 50 epochs, stopping early if validation loss stops improving
- Saves the best model automatically to `data/models/cnn_ids_best.h5`
- Saves training curves to `logs/training_curves.png`

**What you will see in the terminal:**
```
Epoch 1/50
loss: 0.1842 - accuracy: 0.9312 - val_loss: 0.0921 - val_accuracy: 0.9648
Epoch 2/50
loss: 0.0784 - accuracy: 0.9721 - val_loss: 0.0612 - val_accuracy: 0.9801
...
Epoch 18/50
EarlyStopping: val_loss did not improve. Stopping.
Best model saved → data/models/cnn_ids_best.h5
Test Accuracy: 0.9603
```

> This step takes about **20–40 minutes**. You can leave it running in the background.

**Target:** Accuracy ≥ 95% (your journal paper reports 96% on this exact dataset)

---

## STAGE 6 — Evaluate the Model

```bash
python -m model.evaluate
```

**What this produces:**

| Output | Location | Purpose |
|--------|----------|---------|
| CNN metrics table | `logs/model_comparison.csv` | Use in Chapter 4 Results |
| CNN confusion matrix | `logs/cnn_confusion_matrix.png` | Use in Chapter 4 |
| RF confusion matrix | `logs/rf_confusion_matrix.png` | Use for comparison |
| Classification report | terminal + `logs/evaluate.log` | Precision/Recall by class |

The comparison table will look like this:

```
Model                   Accuracy  Precision  Recall  F1-Score  FPR    ROC-AUC  Latency(ms)
CNN (Proposed)          0.9603    0.9711     0.9487  0.9598    0.0031  0.9921   0.0023
Random Forest (Baseline) 0.9421   0.9534     0.9298  0.9415    0.0051  0.9802   0.0015
```

---

## STAGE 7 — Start ELK Stack and Configure Kibana

### Step 7.1 — Start all services

```bash
cd /home/bella/predictive-ids
docker-compose up -d
```

### Step 7.2 — Check services are healthy

```bash
docker-compose ps
```

All four should show `Up`.

### Step 7.3 — Open Kibana on your Mac

On your **Mac browser** go to: `http://192.168.64.2:5601`

### Step 7.4 — Create index patterns in Kibana

1. Click the **hamburger menu** (☰) top left
2. Scroll down and click **Stack Management**
3. Under **Kibana**, click **Index Patterns** (or **Data Views** in newer versions)
4. Click **Create index pattern**
5. Type `logs-*` and click **Next step**
6. Select `@timestamp` as the time field → click **Create index pattern**
7. Repeat — create another one for `ids-alerts`

### Step 7.5 — View live logs

1. Click ☰ → **Discover**
2. Select the `logs-*` index pattern
3. You should see your VM's syslog and auth.log entries streaming in

---

## STAGE 8 — Run the Live Inference Service

This service watches for new logs in Elasticsearch every 10 seconds, classifies them with the CNN, and saves any ATTACK detections as alerts.

Open a **new terminal window** in your MAIN VM (keep it running):

```bash
cd /home/bella/predictive-ids
source venv/bin/activate
python -m inference.inference_service
```

You should see output like:

```
Connected to Elasticsearch: http://localhost:9200
Connected to MongoDB: mongodb://localhost:27017
Inference service started. Polling every 10s...
Fetched 47 new log entries
Classified 47 entries | ATTACK: 0 | BENIGN: 47 | Total attacks: 0
```

Leave this running. When the attacker VM sends attacks, you will see `ATTACK` counts increase here.

---

## STAGE 9 — Start the API Backend

Open another **new terminal window** in your MAIN VM:

```bash
cd /home/bella/predictive-ids
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Test it works from your **Mac browser**: `http://192.168.64.2:8000/docs`

You will see a Swagger UI page with all the API endpoints. This is where the React dashboard will connect.

---

## STAGE 10 — Simulate Attacks from the ATTACKER VM

Now go to your **ATTACKER VM** in UTM.

### Step 10.1 — Get the attack script

If you cloned the repo:
```bash
cd predictive-ids
```

If you copied just the script:
```bash
cd /home/attacker/
```

### Step 10.2 — Make the script executable

```bash
chmod +x simulate_attacks.sh
```

### Step 10.3 — Run the attacks

```bash
# Replace 192.168.64.2 with your MAIN VM's actual IP
./simulate_attacks.sh 192.168.64.2
```

The script will run 5 attack types one by one:
1. **Port Scan** — nmap scans all ports on the main VM
2. **SYN Flood** — floods port 80 with TCP SYN packets for 15 seconds
3. **SSH Brute Force** — Hydra tries common usernames and passwords via SSH
4. **UDP Flood** — floods port 53 for 10 seconds
5. **ICMP Flood** — ping flood for 10 seconds

### Step 10.4 — Watch detection happen in real time

While the attacks run, look at the **inference service terminal on your MAIN VM**. You will see:

```
Fetched 312 new log entries
Classified 312 entries | ATTACK: 47 | BENIGN: 265 | Total attacks: 47
Elasticsearch: 47 alerts indexed
MongoDB: 47 alerts inserted
```

In **Kibana**, go to Discover → select `ids-alerts` → you will see the alerts appearing.

---

## STAGE 11 — Build the React Dashboard

This is the final frontend that displays alerts visually.

### Step 11.1 — Install Node.js on MAIN VM

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
node --version    # should show v20.x
```

### Step 11.2 — Set up React project

```bash
cd /home/bella/predictive-ids/dashboard
npx create-react-app . --template typescript
npm install axios recharts lucide-react
```

### Step 11.3 — Start the dashboard

```bash
npm start
```

Open on your Mac: `http://192.168.64.2:3000`

### Step 11.4 — Build the dashboard pages

Create these files in `dashboard/src/`:

- `AlertFeed.tsx` — polls `/api/alerts` every 5 seconds → shows a live table of attacks
- `Summary.tsx` — polls `/api/alerts/summary` → pie chart of Critical/High/Medium/Low
- `Timeline.tsx` — polls `/api/alerts/timeline` → line chart of attacks over time
- `Metrics.tsx` — fetches `/api/metrics` → table comparing CNN vs Random Forest

---

## RUNNING ORDER SUMMARY

Every time you start working on the project, run these in this order:

```
MAIN VM — Terminal 1:
  cd ~/predictive-ids && docker-compose up -d

MAIN VM — Terminal 2 (after training is done):
  cd ~/predictive-ids && source venv/bin/activate
  python -m inference.inference_service

MAIN VM — Terminal 3:
  cd ~/predictive-ids && source venv/bin/activate
  uvicorn api.main:app --host 0.0.0.0 --port 8000

MAIN VM — Terminal 4 (dashboard):
  cd ~/predictive-ids/dashboard && npm start

ATTACKER VM (for testing only):
  ./simulate_attacks.sh 192.168.64.2
```

---

## QUICK REFERENCE — ALL COMMANDS

| What | Where | Command |
|------|-------|---------|
| Find VM IP | Main VM | `ip addr show` |
| Transfer dataset | Mac Terminal | `scp ~/Downloads/*.csv bella@192.168.64.2:~/predictive-ids/data/raw/` |
| Check data/raw | Main VM | `ls -lh ~/predictive-ids/data/raw/` |
| Install everything | Main VM | `./scripts/setup_vm.sh` |
| Activate Python env | Main VM | `source venv/bin/activate` |
| Preprocess data | Main VM | `python -m preprocessing.preprocess` |
| Train CNN | Main VM | `python -m model.train` |
| Evaluate model | Main VM | `python -m model.evaluate` |
| Start ELK stack | Main VM | `docker-compose up -d` |
| Check ELK status | Main VM | `docker-compose ps` |
| Stop ELK stack | Main VM | `docker-compose down` |
| Start inference | Main VM | `python -m inference.inference_service` |
| Start API | Main VM | `uvicorn api.main:app --host 0.0.0.0 --port 8000` |
| Start dashboard | Main VM | `cd dashboard && npm start` |
| Run attacks | Attacker VM | `./simulate_attacks.sh 192.168.64.2` |
| Open Kibana | Mac browser | `http://192.168.64.2:5601` |
| Open API docs | Mac browser | `http://192.168.64.2:8000/docs` |
| Open dashboard | Mac browser | `http://192.168.64.2:3000` |
| View inference logs | Main VM | `tail -f logs/inference.log` |
| View training log | Main VM | `tail -f logs/train.log` |

---

## DATASET DETAILS

| Dataset | Where to download | What it contains | File size |
|---------|------------------|------------------|-----------|
| **CICIDS2017** (primary) | https://www.unb.ca/cic/datasets/ids-2017.html | 8 days of labelled network traffic. Includes DoS, DDoS, Port Scan, SSH Brute Force, Web Attacks, Infiltration, Botnet. Your journal reports 96% accuracy using this dataset. | ~1.5 GB |
| UNSW-NB15 (optional) | https://research.unsw.edu.au/projects/unsw-nb15-dataset | Modern attack simulations. Good for secondary validation. | ~500 MB |
| NSL-KDD (optional) | https://www.unb.ca/cic/datasets/nsl.html | Classic baseline. Useful for Chapter 5 comparison table. | ~100 MB |

**Where the dataset is used in your project:**

```
You download CICIDS2017 CSVs on your Mac
        ↓
You copy them to data/raw/ on the MAIN VM
        ↓
preprocess.py reads them from data/raw/
        ↓
Cleans, encodes, normalizes, applies SMOTE
        ↓
Saves numpy arrays to data/processed/
        ↓
train.py loads from data/processed/ → trains CNN
        ↓
evaluate.py loads from data/processed/ → tests CNN
        ↓
Saves trained model to data/models/cnn_ids_best.h5
        ↓
inference_service.py loads the model from data/models/
and uses it to classify LIVE logs from Elasticsearch
```

---

## TECHNOLOGY STACK

| Component | Technology | Purpose |
|-----------|-----------|---------|
| CNN Model | TensorFlow / Keras | Intrusion classification |
| Data processing | pandas, scikit-learn, imbalanced-learn | Preprocessing and SMOTE |
| Log shipping | Filebeat | Ships VM logs to Logstash |
| Log parsing | Logstash | Parses and normalizes logs |
| Log storage | Elasticsearch | Indexed searchable log store |
| Log visualisation | Kibana | Dashboards and log explorer |
| Alert storage | MongoDB | Persistent alert database |
| API backend | FastAPI + Uvicorn | Serves data to React dashboard |
| Frontend | React + TypeScript | Alert visualisation UI |
| VM environment | UTM + Ubuntu 24.04 | Simulates VMware ESXi lab |
| Version control | Git / GitHub | Code management |

---

## NOTE ON UTM vs VMWARE

Your proposal specifies VMware ESXi. Since you are on a Mac M-series (Apple Silicon), real VMware ESXi cannot run on it. UTM with Ubuntu VMs is the correct academic substitute. In your methodology chapter, write:

> *"Due to hardware constraints of the Apple Silicon architecture, the simulation environment was implemented using UTM-managed Ubuntu 24.04 LTS virtual machines as a functional equivalent of a VMware ESXi hypervisor. The log structure, network behaviour, and resource telemetry are equivalent for the purposes of model training and evaluation."*

This is academically valid and accepted in simulation-based research.

---

*MTech Cloud Computing | HIT 800 Research Project | Supervisor: Mrs M. Gondo*
