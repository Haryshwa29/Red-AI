@echo off
rem Start the RED-AI Practice Range (intentionally vulnerable, localhost only).
cd /d "%~dp0.."
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py" )
if not defined PY ( echo Python 3 not found. Install from https://python.org then retry. & pause & exit /b 1 )
echo Starting the vulnerable practice site. Browse the URL it prints; Ctrl-C to stop.
%PY% -u -m redai_range.site 5000
pause
