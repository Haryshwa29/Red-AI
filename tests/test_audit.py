"""Audit mode: stop_on_capture=False enumerates every reachable vulnerability
instead of stopping at the first flag. Hermetic."""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.scope import now
from red_ai.exploit import (ExploitScope, FlagDefinition, TargetSurface, ExploitModuleRegistry)
from red_ai.exploit.controller import ExploitController
from red_ai.exploit.modules.web_flag_hunt import WebFlagHuntModule

FLAG = "THM{multi}"
PATTERN = r"THM\{[^}]+\}"


def _flag():
    return FlagDefinition(kind="pattern", description="any THM flag form",
                          target_ref="web body", expected=PATTERN)


def _scope():
    return ExploitScope(scope_id="x", owner="o", authorised_by="o", surfaces=("srf",), flag=_flag(),
                        attestation="lab", owner_attested=True, environment="authorized_lab",
                        valid_from=(now() - timedelta(minutes=1)).isoformat(),
                        valid_until=(now() + timedelta(hours=1)).isoformat())


def _surface():
    return TargetSurface(host="10.0.0.9", port=80, service="HTTP", id="srf")


def _opener(url, t):
    # the same flag is reachable at exactly two distinct wordlist paths
    from urllib.parse import urlparse
    return (200, FLAG.encode()) if urlparse(url).path in ("/flag.txt", "/flag") else (404, b"")


def _reg():
    r = ExploitModuleRegistry(); r.register(WebFlagHuntModule(opener=_opener)); return r


class TestAuditMode(unittest.TestCase):
    def test_stop_mode_captures_once(self):
        out = Path(tempfile.mkdtemp()) / "run"
        s = ExploitController(_scope(), out, _reg(), surfaces=(_surface(),),
                              stop_on_capture=True).run()
        self.assertTrue(s["flag"]["captured"])
        self.assertEqual(s["vulnerabilities"], 1)
        self.assertFalse(s["audit_mode"])

    def test_audit_mode_enumerates_all(self):
        out = Path(tempfile.mkdtemp()) / "run"
        s = ExploitController(_scope(), out, _reg(), surfaces=(_surface(),),
                              stop_on_capture=False).run()
        self.assertTrue(s["flag"]["captured"])
        self.assertTrue(s["audit_mode"])
        self.assertEqual(s["vulnerabilities"], 2)   # both /flag.txt and /flag
        self.assertEqual(len(s["findings"]), 2)


if __name__ == "__main__":
    unittest.main()
