# API usage

The API defaults to `http://localhost:8000` and stores operational data in SQLite.

```bash
curl http://localhost:8000/
curl 'http://localhost:8000/api/alerts?hours=24&limit=20'
curl 'http://localhost:8000/api/stats?hours=24'
curl http://localhost:8000/api/blocked
```

Manual prediction accepts a map containing any of the canonical 76 names. Missing values are zero-filled:

```bash
curl -X POST http://localhost:8000/api/predict \
  -H 'Content-Type: application/json' \
  -d '{"features":{"Flow Duration":100000,"Tot Fwd Pkts":20,"SYN Flag Cnt":10}}'
```

Firewall and whitelist operations:

```bash
curl -X POST http://localhost:8000/api/block \
  -H 'Content-Type: application/json' -d '{"ip":"192.0.2.10","reason":"manual"}'
curl -X DELETE http://localhost:8000/api/unblock/192.0.2.10
curl -X POST http://localhost:8000/api/whitelist \
  -H 'Content-Type: application/json' -d '{"ip":"192.0.2.20","reason":"trusted"}'
```

These management endpoints intentionally have no application authentication. Restrict access to port 8000 at the network boundary.
