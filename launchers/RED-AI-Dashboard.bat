@echo off
rem RED-AI dashboard launcher (Windows). Double-click to open the dashboard.
cd /d "%~dp0.."
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py" )
if not defined PY (
  echo Python 3 was not found on this PC.
  echo Install it from https://python.org  -  tick "Add python.exe to PATH"  -  then try again.
  echo.
  pause
  exit /b 1
)
echo Launching RED-AI dashboard. A browser tab opens automatically.
echo The URL is printed below - keep this window open; close it to stop.
echo.
%PY% -u -m red_ai web --open
echo.
echo (server stopped)
pause
