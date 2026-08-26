#!/usr/bin/env bash
# Serve the frontend on http://127.0.0.1:5500
# (Do NOT open index.html via file:// - fetch() to the API will be CORS-blocked.)
set -e
cd "$(dirname "$0")/../frontend"
python3 -m http.server 5500
