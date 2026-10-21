#!/bin/bash
# Double-click once to add "RED-AI Dashboard" to your macOS Applications (Launchpad).
cd "$(dirname "$0")" || exit 1
command -v python3 >/dev/null 2>&1 && PY=python3 || PY=python
"$PY" -m red_ai install
echo; read -r -p "Done. Press Return to close."
