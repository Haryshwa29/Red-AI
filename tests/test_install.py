"""OS-adaptive installer: content generators are correct and the macOS/Linux
installers actually create a launcher. (Windows .lnk needs PowerShell, so only its
generated script is checked.)"""
import os
import stat
import unittest
from pathlib import Path

from red_ai import install


class TestGenerators(unittest.TestCase):
    def test_windows_ps_script(self):
        s = install.windows_ps_script(r"C:\x\RED-AI.lnk", r"C:\repo\RED-AI-Dashboard.bat",
                                      r"C:\repo", "")
        self.assertIn("CreateShortcut('C:\\x\\RED-AI.lnk')", s)
        self.assertIn("TargetPath='C:\\repo\\RED-AI-Dashboard.bat'", s)
        self.assertIn("$s.Save()", s)

    def test_macos_plist_and_run(self):
        self.assertIn("CFBundleExecutable", install.macos_plist())
        r = install.macos_run_script("/repo", "/usr/bin/python3")
        self.assertIn('cd "/repo"', r)
        self.assertIn("-m red_ai web", r)

    def test_linux_desktop(self):
        d = install.linux_desktop("/repo", "/usr/bin/python3")
        self.assertIn("Type=Application", d)
        self.assertIn("Exec=/usr/bin/python3 -m red_ai web", d)
        self.assertIn("Path=/repo", d)


class TestInstallers(unittest.TestCase):
    def test_linux_creates_desktop_entry(self):
        res = install.install_shortcut(system="Linux")
        self.assertEqual(res["system"], "Linux")
        p = Path(res["created"][0])
        self.assertTrue(p.exists())
        self.assertIn("red_ai web", p.read_text())

    def test_macos_creates_app_bundle(self):
        res = install.install_shortcut(system="Darwin")
        app = Path(res["created"][0])
        self.assertTrue(app.name.endswith(".app"))
        run = app / "Contents" / "MacOS" / "run"
        self.assertTrue(run.exists())
        self.assertTrue(os.stat(run).st_mode & stat.S_IXUSR)  # executable

    def test_windows_does_not_raise_without_powershell(self):
        # On a non-Windows host there is no PowerShell; the installer must degrade
        # gracefully (report failure per shortcut) rather than raising.
        res = install.install_shortcut(system="Windows")
        self.assertEqual(res["system"], "Windows")
        self.assertTrue(res["created"])  # entries present (created or "(failed: …)")


if __name__ == "__main__":
    unittest.main()
