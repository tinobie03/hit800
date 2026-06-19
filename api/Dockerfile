FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

# Model artefacts
COPY model/       /app/model/
COPY data/processed/feature_names.txt /app/data/processed/feature_names.txt
COPY ids_core/    /app/ids_core/

# API package
COPY api/ /app/api/

ENV PYTHONUNBUFFERED=1 \
    MODEL_PATH=model/onemoney_cnn.h5 \
    SCALER_PATH=model/scaler.pkl \
    THRESHOLD=0.50

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
