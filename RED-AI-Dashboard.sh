#!/bin/bash
# Double-click (or run) to launch the RED-AI dashboard (Linux). Opens in your browser.
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python
echo "Starting RED-AI dashboard…  (Ctrl-C or close this window to stop)"
exec "$PY" -m red_ai web --open
