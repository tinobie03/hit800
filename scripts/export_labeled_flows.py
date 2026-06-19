#!/usr/bin/env python3
"""Export lab-captured flows with ground-truth labels for retraining.

Attack labels come from tracked `run_attack.sh` windows and source IPs. Flows
outside those windows are BENIGN, so use this only with a controlled lab DB.
For clean validation, generate benign traffic from a separate client VM.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Direct execution (`python scripts/...`) adds scripts/, not the repository
# root, to sys.path. Resolve the project package without requiring installation.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ids_core.features import FEATURES


def parsed(value: str | None) -> datetime | None:
    if not value:
        return None
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=str(ROOT / "data/ids.db"))
    parser.add_argument("--output", default=str(ROOT / "data/raw/Live_Capture_Labeled.csv"))
    parser.add_argument("--grace-seconds", type=int, default=10)
    args = parser.parse_args()

    with sqlite3.connect(args.db) as connection:
        runs = [
            {
                "source_ip": row[0],
                "start": parsed(row[1]),
                "end": parsed(row[2]) or datetime.now(timezone.utc),
            }
            for row in connection.execute(
                """SELECT source_ip, start_time, end_time FROM attack_runs
                   WHERE source_ip IS NOT NULL AND source_ip != '0.0.0.0'"""
            )
        ]
        logs = connection.execute(
            "SELECT timestamp, source_ip, data FROM logs ORDER BY id"
        ).fetchall()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    counts = {"BENIGN": 0, "ATTACK": 0}
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*FEATURES, "Label"])
        writer.writeheader()
        for timestamp, source_ip, raw_data in logs:
            event_time = parsed(timestamp)
            if event_time is None:
                continue
            is_attack = any(
                run["source_ip"] == source_ip
                and run["start"] <= event_time <= run["end"] + timedelta(seconds=args.grace_seconds)
                for run in runs
            )
            label = "ATTACK" if is_attack else "BENIGN"
            data = json.loads(raw_data)
            writer.writerow({**{name: data.get(name, 0) for name in FEATURES}, "Label": label})
            counts[label] += 1

    print(f"Wrote {sum(counts.values())} flows to {output}: {counts}")


if __name__ == "__main__":
    main()
