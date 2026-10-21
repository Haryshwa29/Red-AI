# launchers/

Click-to-open entry points for the RED-AI dashboard. Pick your OS:

| OS      | Run the dashboard            | Add to app menu / Start menu |
|---------|------------------------------|------------------------------|
| Windows | `RED-AI-Dashboard.bat`       | `INSTALL.bat`                |
| macOS   | `RED-AI-Dashboard.command`   | `INSTALL-mac.command`        |
| Linux   | `RED-AI-Dashboard.sh`        | `INSTALL-linux.sh`           |

Each launcher changes into the repo root and runs `python -m red_ai web`.
`INSTALL*` runs `python -m red_ai install`, which creates a clickable
"RED-AI Dashboard" shortcut for your OS.
