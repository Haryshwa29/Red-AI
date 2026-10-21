@echo off
rem Double-click to launch the RED-AI dashboard (Windows). Opens in your browser.
cd /d "%~dp0"
echo Starting RED-AI dashboard... (close this window to stop the server)
echo.
where python >nul 2>nul && (
  python -m red_ai web --open
) || (
  where py >nul 2>nul && (
    py -m red_ai web --open
  ) || (
    echo Python 3 was not found on this PC.
    echo Install it from https://python.org  ^(tick "Add python.exe to PATH"^^) then double-click this again.
  )
)
echo.
pause
