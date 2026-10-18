"""Service/version identification (recon banner.py): fingerprint patterns,
benign-probe discipline, no-raise, exposure leads, and controller integration.
Hermetic (injected opener/scanner, no socket)."""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.recon.banner import grab_banner, fingerprint, exposure_leads
from red_ai.recon.scope import ReconScope
from red_ai.recon.controller import ReconController
from red_ai.recon.scanner import ProbeResult, PortState
from red_ai.contracts.scope import now


class TestFingerprint(unittest.TestCase):
    def test_ssh(self):
        s, v = fingerprint(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        self.assertEqual(s, "SSH"); self.assertTrue(v.startswith("OpenSSH_8.2p1"))

    def test_http_server_header(self):
        s, v = fingerprint(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n")
        self.assertEqual(s, "HTTP"); self.assertIn("Apache/2.4.49", v)

    def test_ftp(self):
        s, v = fingerprint(b"220 (vsFTPd 2.3.4)\r\n")
        self.assertEqual(s, "FTP"); self.assertIn("2.3.4", v)

    def test_unknown_returns_raw_first_line(self):
        s, v = fingerprint(b"weird-proto hello\r\nmore\r\n")
        self.assertIsNone(s); self.assertEqual(v, "weird-proto hello")

    def test_empty(self):
        self.assertEqual(fingerprint(b""), (None, None))


class TestExposureLeads(unittest.TestCase):
    def test_vsftpd_backdoor_lead(self):
        self.assertTrue(exposure_leads("vsFTPd 2.3.4"))

    def test_apache_rce_lead(self):
        self.assertTrue(exposure_leads("Apache/2.4.49 (Unix)"))

    def test_clean_version_no_lead(self):
        self.assertEqual(exposure_leads("OpenSSH_9.6"), [])

    def test_none(self):
        self.assertEqual(exposure_leads(None), [])


class TestGrabBanner(unittest.TestCase):
    def test_reads_via_injected_opener(self):
        got = grab_banner("h", 22, 500, opener=lambda host, port, t, send: b"SSH-2.0-X\r\n")
        self.assertEqual(got, b"SSH-2.0-X\r\n")

    def test_http_port_sends_benign_get(self):
        seen = {}
        def op(host, port, t, send): seen["send"] = send; return b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        grab_banner("h", 80, 500, opener=op)
        self.assertIn(b"GET / HTTP/1.0", seen["send"])

    def test_nonhttp_sends_nothing(self):
        seen = {}
        def op(host, port, t, send): seen["send"] = send; return b"SSH-2.0-X\r\n"
        grab_banner("h", 22, 500, opener=op)
        self.assertIsNone(seen["send"])

    def test_opener_failure_is_none_not_raise(self):
        def boom(*a): raise OSError("refused")
        self.assertIsNone(grab_banner("h", 22, 500, opener=boom))


class _OpenScanner:
    name = "fake-open"
    def scan(self, targets):
        return [ProbeResult(h, p, PortState.OPEN, 1) for (h, p) in targets]


class TestReconIdentifyIntegration(unittest.TestCase):
    def _scope(self, **kw):
        base = dict(scope_id="r", owner="o", authorised_by="o", attestation="lab",
                    owner_attested=True, environment="authorized_lab",
                    valid_from=(now() - timedelta(minutes=1)).isoformat(),
                    valid_until=(now() + timedelta(hours=1)).isoformat())
        base.update(kw)
        return ReconScope.build(ports="22", hosts=["10.0.0.9"], **base)

    def test_identify_off_by_default(self):
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ReconController(self._scope(), out, scanner=_OpenScanner()).run()
        self.assertNotIn("version", summ["open"][0])  # pure connect-scan unchanged

    def test_identify_on_adds_service_version_and_leads(self):
        out = Path(tempfile.mkdtemp()) / "run"
        opener = lambda host, port, t, send: b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n"
        summ = ReconController(self._scope(identify_services=True), out,
                               scanner=_OpenScanner(), banner_opener=opener).run()
        f = summ["open"][0]
        self.assertEqual(f["service_detected"], "SSH")
        self.assertIn("OpenSSH_7.6", f["version"])
        self.assertTrue(f["version_leads"])  # OpenSSH 7.x user-enum lead


if __name__ == "__main__":
    unittest.main()
