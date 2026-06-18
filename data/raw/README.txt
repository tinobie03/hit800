OneMoney IDS — Raw Dataset
===========================
Project  : HIT 800 Research Project
Student  : Tinotenda Belladona Chatora
Dataset  : OneMoney_Training_v3_10k.csv

CONTENTS
--------
File     : OneMoney_Training_v3_10k.csv
Rows     : 10,000
Columns  : 78  (76 numeric features + Label + Traffic_Type)
Format   : CICFlowMeter 76-feature standard

LABELS
------
BENIGN (6,007 rows) — 11 real OneMoney transaction types:
  - Balance Enquiry
  - Send Money
  - Receive Money
  - Pay Bills
  - ZipIt Transfer
  - Account Statement
  - Bank to OneMoney
  - OneMoney to Bank
  - Buy Airtime
  - Cash In / Cash Out
  - Make Payment / Receive Payment

ATTACK (3,993 rows) — 11 MFS-specific attack types:
  - Brute Force PIN
  - API Flood DoS
  - Data Exfiltration
  - Credential Stuffing
  - Account Enumeration
  - Slowloris DoS
  - Session Hijacking
  - SQL Injection
  - Man-in-the-Middle
  - Botnet C&C Beaconing
  - DDoS Distributed Flood

IMPORTANT
---------
- This is a SIMULATED dataset — no real transaction data or PII
- Features are CICFlowMeter network flow statistics (no phone numbers,
  account numbers, amounts, or personal information)
- Do NOT put CIC-IDS-2018 files here — this dataset replaces them
- The processed/ folder will be populated by preprocess.py at runtime

NEXT STEP
---------
Run preprocessing:
  python preprocessing/preprocess.py

This will read from data/raw/ and write scaled outputs to data/processed/
