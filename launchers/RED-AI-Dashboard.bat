@echo off
rem RED-AI dashboard launcher (Windows). Double-click to open the dashboard.
cd /d "%~dp0.."
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py" )
if not defined PY (
  echo Python 3 was not found on this PC.
  echo Install it from https://python.org  -  be sure to tick "Add python.exe to PATH"  -  then try again.
  echo.
  pause
  exit /b 1
)
echo Starting RED-AI dashboard at http://127.0.0.1:8787
echo A server window will open; your browser follows in ~2 seconds. Keep the server window open.
start "RED-AI Dashboard server (keep this open)" cmd /k "%PY% -u -m red_ai web --no-open --port 8787"
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:8787"
exit /b 0
