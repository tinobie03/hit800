# Live testing

Run testing only on an isolated IDS VM and attacker VM.

```bash
docker compose --profile packet-capture up -d --build
docker compose logs -f packet-capture inference api
```

Generate benign traffic first, then run one attack script at a time from the attacker VM. Record:

- source IP and exact start/end timestamps;
- packets sent and attack parameters;
- number of captured flows and alerts;
- attack probabilities at threshold 0.50;
- verified host `iptables` rules;
- false positives during the benign baseline;
- time from first malicious packet to firewall rule creation.

Verify host blocking on the IDS VM:

```bash
sudo iptables -C INPUT -s ATTACKER_IP -j DROP
sudo iptables -C OUTPUT -d ATTACKER_IP -j DROP
```

Do not report a successful block solely from the dashboard; confirm the host rules and an attacker connection timeout. For unknown-attack claims, exclude the complete attack family from training before testing.
