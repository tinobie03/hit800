FROM python:3.11-slim

# iptables for IP blocking, curl for healthchecks, libpcap for packet capture
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iptables iproute2 curl libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY inference/requirements.txt /app/inference/requirements.txt
RUN pip install --no-cache-dir -r inference/requirements.txt

# Copy model artefacts and feature metadata
COPY model/       /app/model/
COPY data/processed/feature_names.txt /app/data/processed/feature_names.txt
COPY ids_core/    /app/ids_core/

# Copy inference package
COPY inference/   /app/inference/

ENV PYTHONUNBUFFERED=1 \
    MODEL_PATH=model/onemoney_cnn.h5 \
    SCALER_PATH=model/scaler.pkl \
    FEAT_FILE=data/processed/feature_names.txt \
    POLL_INTERVAL=10 \
    BATCH_SIZE=500 \
    THRESHOLD=0.50 \
    AUTO_BLOCK=false \
    PROTECTED_NETWORKS=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

CMD ["python", "-m", "inference.service"]
