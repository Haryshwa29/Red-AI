"""OS-adaptive installer: create a clickable shortcut that launches the dashboard.

`python -m red_ai install` detects the operating system and installs a launcher
in the right place:
  * Windows  -> a Start Menu (and Desktop) shortcut (.lnk) that runs the dashboard
  * macOS    -> a .app bundle in ~/Applications (shows in Launchpad / Spotlight)
  * Linux    -> a .desktop entry in ~/.local/share/applications (app menu)

Pure standard library (PowerShell is used only to write the .lnk on Windows, and
it ships with Windows). The content generators are pure functions so they are
unit-testable on any OS; `install_shortcut` actually writes/creates things.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

APP_NAME = "RED-AI Dashboard"


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# Pure content generators (unit-testable on any OS)
# --------------------------------------------------------------------------- #
def windows_ps_script(lnk: str, target: str, workdir: str, args: str = "") -> str:
    """PowerShell that creates a .lnk shortcut via WScript.Shell."""
    return (
        "$s=(New-Object -COM WScript.Shell).CreateShortcut('{lnk}');"
        "$s.TargetPath='{target}';"
        "$s.Arguments='{args}';"
        "$s.WorkingDirectory='{workdir}';"
        "$s.Description='RED-AI security dashboard';"
        "$s.Save()"
    ).format(lnk=lnk, target=target, args=args, workdir=workdir)


def macos_plist(executable: str = "run") -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f'  <key>CFBundleName</key><string>{APP_NAME}</string>\n'
        f'  <key>CFBundleExecutable</key><string>{executable}</string>\n'
        '  <key>CFBundleIdentifier</key><string>ai.redai.dashboard</string>\n'
        '  <key>CFBundlePackageType</key><string>APPL</string>\n'
        '  <key>CFBundleVersion</key><string>1.0</string>\n'
        '</dict></plist>\n'
    )


def macos_run_script(repo: str, py: str) -> str:
    return (f'#!/bin/bash\ncd "{repo}" || exit 1\n'
            f'exec "{py}" -m red_ai web\n')


def linux_desktop(repo: str, py: str) -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        "Comment=RED-AI security dashboard\n"
        f"Exec={py} -m red_ai web\n"
        f"Path={repo}\n"
        "Terminal=true\n"
        "Categories=Security;Network;\n"
    )


# --------------------------------------------------------------------------- #
# Installers
# --------------------------------------------------------------------------- #
def _python_for_shortcut() -> str:
    """The python to launch with — prefer the same interpreter running install."""
    return sys.executable or ("python" if platform.system() == "Windows" else "python3")


def _install_windows(repo: Path) -> list[str]:
    done = []
    bat = repo / "launchers" / "RED-AI-Dashboard.bat"
    if not bat.exists():  # tolerate the pre-reorg layout
        bat = repo / "RED-AI-Dashboard.bat"
    target = str(bat) if bat.exists() else _python_for_shortcut()
    args = "" if bat.exists() else "-m red_ai web"
    appdata = os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))
    locations = [
        Path(appdata) / "Microsoft/Windows/Start Menu/Programs" / f"{APP_NAME}.lnk",
        Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Desktop" / f"{APP_NAME}.lnk",
    ]
    for lnk in locations:
        lnk.parent.mkdir(parents=True, exist_ok=True)
        ps = windows_ps_script(str(lnk), target, str(repo), args)
        try:
            subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-Command", ps], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            done.append(str(lnk))
        except Exception as e:
            done.append(f"(failed: {lnk} — {e})")
    return done


def _install_macos(repo: Path) -> list[str]:
    app = Path.home() / "Applications" / f"{APP_NAME}.app"
    macos_dir = app / "Contents" / "MacOS"
    macos_dir.mkdir(parents=True, exist_ok=True)
    (app / "Contents" / "Info.plist").write_text(macos_plist(), encoding="utf-8")
    run = macos_dir / "run"
    run.write_text(macos_run_script(str(repo), _python_for_shortcut()), encoding="utf-8")
    run.chmod(0o755)
    return [str(app)]


def _install_linux(repo: Path) -> list[str]:
    d = Path.home() / ".local/share/applications"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "red-ai-dashboard.desktop"
    f.write_text(linux_desktop(str(repo), _python_for_shortcut()), encoding="utf-8")
    f.chmod(0o755)
    return [str(f)]


def install_shortcut(system: "str | None" = None) -> dict:
    """Create the OS-appropriate launcher. Returns {system, created:[paths]}."""
    system = system or platform.system()
    repo = repo_root()
    if system == "Windows":
        created = _install_windows(repo)
    elif system == "Darwin":
        created = _install_macos(repo)
    else:
        created = _install_linux(repo)
    return {"system": system, "created": created, "repo": str(repo)}
