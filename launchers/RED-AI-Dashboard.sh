#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python 3 not found. Install it and try again."; exit 1; }
echo "Starting RED-AI dashboard at http://127.0.0.1:8787 ..."
exec "$PY" -m red_ai web --open --port 8787
