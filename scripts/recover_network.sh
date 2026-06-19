#!/bin/bash
# Remove only firewall rules recorded by this IDS and disable their DB entries.
set -euo pipefail

DB_PATH="${DB_PATH:-data/ids.db}"

if docker compose version >/dev/null 2>&1; then
  docker compose stop inference || true
else
  docker-compose stop inference || true
fi

mapfile -t BLOCKED_IPS < <(python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    for (ip,) in connection.execute("SELECT ip FROM blocked_ips WHERE active = 1"):
        print(ip)
PY
)

for ip in "${BLOCKED_IPS[@]}"; do
  for rule in "INPUT -s" "OUTPUT -d" "FORWARD -s" "FORWARD -d"; do
    read -r chain selector <<< "$rule"
    while sudo iptables -C "$chain" "$selector" "$ip" -j DROP 2>/dev/null; do
      sudo iptables -D "$chain" "$selector" "$ip" -j DROP
    done
  done
  echo "Removed IDS firewall rules for $ip"
done

python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("UPDATE blocked_ips SET active = 0 WHERE active = 1")
PY

echo "Network recovery complete. Rebuild before restarting inference."
