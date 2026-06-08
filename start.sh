#!/bin/bash
set -e
cd "$(dirname "$0")/backend"

if [ ! -d ".venv" ]; then
  echo "→ Creating virtual environment..."
  /opt/homebrew/bin/python3.12 -m venv .venv
fi

source .venv/bin/activate

echo "→ Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "  VaultScan — http://localhost:8080"
echo "  API docs  — http://localhost:8080/api/docs"
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
