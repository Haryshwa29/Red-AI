#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python 3 not found."; exit 1; }
exec "$PY" -m red_ai install
