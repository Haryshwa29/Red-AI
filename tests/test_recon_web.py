"""Web enumeration (recon/web.py): root fingerprint, exposure findings vs leads,
404 discipline, never-raise, and controller integration. Hermetic (injected
opener)."""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.recon.web import enumerate_web
from red_ai.recon.scope import ReconScope
from red_ai.recon.controller import ReconController
from red_ai.recon.scanner import ProbeResult, PortState
from red_ai.contracts.scope import now


def fake_opener(responses):
    def op(url, timeout_s):
        after = url.split("://", 1)[1]
        path = "/" + (after.split("/", 1)[1] if "/" in after else "")
        return responses.get(path, (404, {}, b""))
    return op


class TestWebEnum(unittest.TestCase):
    def test_root_title_and_server(self):
        resp = {"/": (200, {"Server": "Apache/2.4.49"}, b"<html><title>Admin Portal</title></html>")}
        w = enumerate_web("h", 80, opener=fake_opener(resp))
        self.assertEqual(w["root"]["status"], 200)
        self.assertEqual(w["root"]["server"], "Apache/2.4.49")
        self.assertEqual(w["root"]["title"], "Admin Portal")

    def test_exposed_git_is_critical_finding(self):
        resp = {"/": (200, {}, b"<title>x</title>"), "/.git/HEAD": (200, {}, b"ref: refs/heads/main")}
        w = enumerate_web("h", 80, opener=fake_opener(resp))
        self.assertTrue(any(f["path"] == "/.git/HEAD" and f["severity"] == "critical" for f in w["findings"]))

    def test_admin_panel_is_lead_not_finding(self):
        resp = {"/": (200, {}, b""), "/admin": (200, {}, b"login")}
        w = enumerate_web("h", 80, opener=fake_opener(resp))
        self.assertTrue(any(l["path"] == "/admin" for l in w["leads"]))
        self.assertFalse(w["findings"])

    def test_404s_ignored(self):
        w = enumerate_web("h", 80, opener=fake_opener({"/": (200, {}, b"")}))
        self.assertEqual(w["findings"], []); self.assertEqual(w["leads"], [])

    def test_dead_server_probes_nothing(self):
        w = enumerate_web("h", 80, opener=lambda u, t: (0, {}, b""))
        self.assertEqual(w["root"]["status"], 0); self.assertEqual(w["paths"], [])

    def test_opener_exception_never_escapes(self):
        def boom(u, t): raise RuntimeError("down")
        w = enumerate_web("h", 80, opener=boom)
        self.assertEqual(w["root"]["status"], 0)


class _OpenScanner:
    def scan(self, targets):
        return [ProbeResult(h, p, PortState.OPEN, 1) for (h, p) in targets]


class TestReconWebIntegration(unittest.TestCase):
    def test_web_enum_attached_to_finding(self):
        scope = ReconScope.build(
            ports="80", hosts=["10.0.0.5"], scope_id="r", owner="o", authorised_by="o",
            attestation="lab", owner_attested=True, environment="authorized_lab", enumerate_web=True,
            valid_from=(now() - timedelta(minutes=1)).isoformat(),
            valid_until=(now() + timedelta(hours=1)).isoformat())
        resp = {"/": (200, {"Server": "nginx"}, b"<title>Home</title>"), "/.env": (200, {}, b"SECRET=1")}
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ReconController(scope, out, scanner=_OpenScanner(), web_opener=fake_opener(resp)).run()
        f = summ["open"][0]
        self.assertIn("web", f)
        self.assertEqual(f["web"]["root"]["title"], "Home")
        self.assertTrue(any(x["path"] == "/.env" for x in f["web"]["findings"]))


if __name__ == "__main__":
    unittest.main()
