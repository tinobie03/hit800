# Predictive Intrusion Detection System

A research prototype that captures bidirectional network flows, transforms them into a canonical 76-feature representation, classifies them with a 1D CNN, persists detections in SQLite, and can enforce host firewall blocks.

## Runtime

```text
packets → five-tuple flow capture → SQLite logs → CNN inference
                                              ├→ SQLite alerts
                                              └→ host iptables

SQLite → FastAPI → React dashboard
```

SQLite is the sole operational datastore. MongoDB, Elasticsearch, Logstash, Kibana, and Filebeat are not required.

## Quick start

```bash
./scripts/setup_vm.sh
source venv/bin/activate
python -m preprocessing.preprocess
python train.py
docker compose --profile packet-capture up -d --build
```

Start the dashboard separately:

```bash
cd dashboard
npm ci
npm run dev -- --host 0.0.0.0
```

Open `http://<ids-vm-ip>:5173`. The API listens on port 8000.

If Vite runs on a different computer from the IDS VM, configure its API target:

```bash
cd dashboard
VITE_API_URL=http://<ids-vm-ip>:8000 npm run dev -- --host 0.0.0.0
```

## Services

- `packet-capture`: host-network packet capture using `NET_RAW`/`NET_ADMIN`.
- `inference`: polls SQLite every 10 seconds, uses threshold `0.50`, and applies host firewall rules.
- `api`: reads SQLite and provides prediction, alert, block, whitelist, and test-run endpoints.
- `dashboard`: React/Vite monitoring interface.

Both inference and API use host networking because their firewall actions must affect the host namespace. Deploy this only on a dedicated IDS VM. Management endpoint authentication is intentionally outside the current scope.

## Model workflow

The supported workflow is:

```bash
python -m preprocessing.preprocess
python train.py
python -m model.evaluate
```

`model/train.py` remains a compatibility entry point for `python -m model.train`. The deployed artifacts are `model/onemoney_cnn.h5` and `model/scaler.pkl`.

Current checked-in held-out results at threshold 0.50 are recorded in `logs/evaluate.json`. These results measure a random held-out split; they do not by themselves establish zero-day detection. Use grouped, temporal, and held-out-attack-family evaluations for research claims.

### Live-data calibration

The live packet extractor must be represented in training data. In a controlled
lab, collect ordinary traffic from a client VM and tracked attacks from a
different attacker VM, then export and retrain:

```bash
# Normal client VM
./scripts/generate_benign_traffic.sh <ids-ip> 600

# Attacker VM: baseline, gradual SYN evidence, then escalation
./scripts/run_live_scenario.sh <ids-ip> syn

# IDS VM
python scripts/export_labeled_flows.py --db data/ids.db
python -m preprocessing.preprocess
python train.py
python -m model.evaluate
docker compose --profile packet-capture up -d --build --force-recreate
```

`preprocessing.preprocess` automatically combines `data/raw/Live_*.csv` with
the base dataset. Review class counts and held-out false positives before
deploying the resulting model.

## Verification

```bash
python -m unittest discover -v
python -m model.evaluate
docker compose config
cd dashboard && npm run build
```

## Important operational notes

- Whitelist changes are picked up on the next inference poll.
- The inference cursor is persisted in SQLite, preventing replay after restart.
- The Docker lab enables automatic blocking after three attack classifications
  from one IP within 60 seconds, with at least one score of 0.80 or above.
  Whitelist the management client before enabling it outside the lab.
- A block is recorded as active only after all host firewall rules succeed.
- Packet capture aggregates bidirectional flows by protocol, source/destination IP, and ports.
- The API currently has no authentication; restrict port 8000 at the network boundary.
