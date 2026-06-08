FROM python:3.12-slim

# System deps for dnspython/whois and building wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Persisted SQLite DB lives in /data (mount a volume here).
ENV VAULTSCAN_DB=/data/vaultscan.db
RUN mkdir -p /data

WORKDIR /app/backend
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
