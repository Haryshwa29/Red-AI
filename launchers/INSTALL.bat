@echo off
rem Double-click once to add "RED-AI Dashboard" to your Start menu + Desktop.
cd /d "%~dp0.."
where python >nul 2>nul && ( python -m red_ai install ) || ( where py >nul 2>nul && ( py -m red_ai install ) || ( echo Python 3 not found. Install from https://python.org then try again. ) )
echo.
pause
