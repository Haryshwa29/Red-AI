#!/bin/bash
# Double-click to launch the RED-AI dashboard (macOS). It opens in your browser.
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python
echo "Starting RED-AI dashboard…  (close this window to stop)"
exec "$PY" -m red_ai web --open
