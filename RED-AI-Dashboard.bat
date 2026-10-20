@echo off
rem Double-click to launch the RED-AI dashboard (Windows). Opens in your browser.
cd /d "%~dp0"
echo Starting RED-AI dashboard...  (close this window to stop)
python -m red_ai web --open
pause
