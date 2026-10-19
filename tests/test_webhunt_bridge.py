"""Discovery-driven capture: the web_flag_hunt module, the pattern flag matcher,
and the recon->exploit bridge. Hermetic (injected HTTP opener; synthetic recon
summary). Proves the live-engagement spine without a network:

  * a `pattern` flag (THM{...} form) is captured without a pre-declared path;
  * recon-disclosed paths flow into the hunt and are tried FIRST (the bridge is
    real, not luck-of-the-wordlist);
  * a body of the wrong form is NOT a capture (controller is the authority);
  * the bridge promotes a web surface from recon's web-root evidence (any port)
    and surfaces disclosed/exposed facts;
  * robots.txt Disallow parsing extracts the breadcrumb paths.
"""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.scope import now
from red_ai.exploit import (ExploitScope, FlagDefinition, TargetSurface,
                            ExploitModuleRegistry, AttemptOutcome)
from red_ai.exploit.controller import ExploitController
from red_ai.exploit.modules.web_flag_hunt import WebFlagHuntModule, _candidate_paths
from red_ai.exploit.bridge import surfaces_from_recon
from red_ai.recon.web import _parse_robots

FLAG = "THM{r3con_t0_expl01t_br1dge}"
PATTERN = r"(?:THM|FLAG|HTB|flag)\{[^}]{1,128}\}"


def _scope(**kw):
    flag = FlagDefinition(kind="pattern", description="any THM-form flag on the web surface",
                          target_ref="a web response body", expected=PATTERN)
    base = dict(scope_id="x", owner="o", authorised_by="o", surfaces=("srf_web",), flag=flag,
                attestation="authorized THM lab", owner_attested=True, environment="authorized_lab",
                valid_from=(now() - timedelta(minutes=1)).isoformat(),
                valid_until=(now() + timedelta(hours=1)).isoformat())
    base.update(kw)
    return ExploitScope(**base)


def _surface():
    return TargetSurface(host="10.10.1.9", port=3000, service="HTTP", id="srf_web")


def _reg(opener):
    r = ExploitModuleRegistry(); r.register(WebFlagHuntModule(opener=opener)); return r


class TestWebFlagHunt(unittest.TestCase):
    def test_captures_pattern_flag_via_disclosed_path(self):
        # flag ONLY at a custom robots-disclosed dir -- no wordlist path reaches it
        def opener(url, t):
            return (200, (FLAG + "\n").encode()) if url.endswith("/z9-area/flag.txt") else (404, b"")
        facts = ("recon: /z9-area/ disclosed by robots.txt",)
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(), out, _reg(opener), surfaces=(_surface(),),
                                 established_facts=facts).run()
        self.assertTrue(summ["flag"]["captured"])
        self.assertEqual(summ["outcome"], AttemptOutcome.FLAG_CAPTURED.value)
        self.assertEqual(summ["findings"][0]["flag_value"], FLAG)
        self.assertEqual(summ["flag"]["rate"], 1.0)

    def test_disclosed_paths_are_tried_first(self):
        paths = _candidate_paths(("recon: /z9-area/ disclosed by robots.txt",))
        self.assertEqual(paths[0], "/z9-area/")
        self.assertIn("/z9-area/flag.txt", paths[:4])   # dir -> flag-file expansion, up front

    def test_wrong_form_is_not_a_capture(self):
        # 200 with content, but not the flag form -> controller checker rejects
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(), out, _reg(lambda u, t: (200, b"just a normal page")),
                                 surfaces=(_surface(),), established_facts=()).run()
        self.assertFalse(summ["flag"]["captured"])
        self.assertEqual(summ["outcome"], AttemptOutcome.NO_BREACH.value)

    def test_no_wordlist_capture_without_the_breadcrumb(self):
        # same flag, same opener, but NO recon fact -> the custom dir is never tried
        def opener(url, t):
            return (200, (FLAG + "\n").encode()) if url.endswith("/z9-area/flag.txt") else (404, b"")
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(), out, _reg(opener), surfaces=(_surface(),),
                                 established_facts=()).run()
        self.assertFalse(summ["flag"]["captured"])


class TestReconExploitBridge(unittest.TestCase):
    def test_promotes_web_surface_on_any_port_from_web_root(self):
        recon = {"open": [{"host": "10.10.1.9", "port": 3000, "service": "unknown",
                           "web": {"root": {"status": 200, "server": "nginx", "title": "x"},
                                   "paths": [{"path": "/robots.txt", "status": 200, "meaning": "robots"}],
                                   "disclosed": [{"path": "/z9-area/", "meaning": "robots"}],
                                   "findings": [{"path": "/.env", "meaning": "env exposed", "severity": "critical"}]}}]}
        surfaces, facts = surfaces_from_recon(recon)
        self.assertEqual(len(surfaces), 1)
        self.assertTrue(surfaces[0].service.upper().startswith("HTTP"))  # evidence-based, not port guess
        self.assertTrue(any("/z9-area/" in f and "robots" in f for f in facts))
        self.assertTrue(any("/.env" in f and "exposed" in f for f in facts))

    def test_non_web_port_is_not_marked_http(self):
        recon = {"open": [{"host": "10.10.1.9", "port": 22, "service": "SSH", "web": {}}]}
        surfaces, _ = surfaces_from_recon(recon)
        self.assertFalse(surfaces[0].service.upper().startswith("HTTP"))

    def test_parse_robots_extracts_disallow_paths(self):
        body = b"User-agent: *\nDisallow: /z9-area/\nDisallow: /admin/\nAllow: /\n"
        got = {d["path"] for d in _parse_robots(body)}
        self.assertEqual(got, {"/z9-area/", "/admin/"})   # "/" is skipped


if __name__ == "__main__":
    unittest.main()
