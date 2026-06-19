# Research Objectives Assessment

This document separates implemented capabilities from claims that still require experimental evidence.

## Implemented

- A 1D CNN consumes a fixed 76-feature network-flow representation.
- Bidirectional five-tuple flows are captured from the IDS host network.
- Alerts, runtime state, blocks, whitelists, and test-run metadata are stored in SQLite.
- Detected source IPs can be blocked in the host `iptables` namespace.
- A React dashboard polls the FastAPI service for alerts and operational state.

## Current measured baseline

The checked-in test artifact at threshold 0.50 reports:

- Accuracy: 79.35%
- Attack recall: 64.71%
- False-positive rate: 10.91%
- F1: 71.46%
- ROC-AUC: 0.845

These measurements are from a random held-out split. They do not prove zero-day detection, performance on independent environments, or superiority to a signature IDS.

## Evidence still required

1. Hold out complete attack families during training and evaluate them as unknown attacks.
2. Use grouped and chronological splits to prevent capture-session leakage.
3. Replay benign and malicious traffic through the live flow extractor and report live metrics.
4. Compare against a configured Suricata or Snort baseline on identical traffic.
5. Measure end-to-end detection and blocking latency, including the polling interval.
6. If multi-layer correlation remains an objective, add system, hypervisor, and application features to the model; the present model is network-only.

Until those experiments are complete, describe the system as a network-layer predictive IDS/IPS research prototype.
