#!/usr/bin/env bash
# Start the API on http://127.0.0.1:8000  (docs at /docs)
set -e
cd "$(dirname "$0")/.."
python3 -m venv .venv 2>/dev/null || true
# shellcheck disable=SC1091
source .venv/bin/activate 2>/dev/null || source .venv/Scripts/activate
pip install -q -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000
