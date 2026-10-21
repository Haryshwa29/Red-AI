@echo off
REM Double-click once to add "RED-AI Dashboard" to your Windows Start menu + Desktop.
cd /d "%~dp0"
where python >nul 2>nul && (python -m red_ai install) || (
  where py >nul 2>nul && (py -m red_ai install) || (
    echo Python 3 is required but was not found. Install it from https://python.org and run this again.
  )
)
echo.
pause
