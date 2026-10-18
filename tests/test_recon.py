"""Recon engine tests. Stdlib unittest, fully offline, no real sockets (the
scanner's connect primitive is injected)."""
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.scope import now
from red_ai.contracts.domain import Severity
from red_ai.recon.scope import ReconScope, sign_recon_scope, verify_recon_scope, _parse_ports
from red_ai.recon.gate import recon_gate, HALTING
from red_ai.recon.scanner import TcpConnectScanner, PortState, probe
from red_ai.recon.services import classify
from red_ai.recon.controller import ReconController

KEY = b"k" * 32


def a_scope(**kw):
    base = dict(scope_id="r", owner="o", authorised_by="o", hosts=("10.0.0.5",),
                ports="22,445,3389,1", attestation="authorized self-scan",
                owner_attested=True, environment="owned",
                valid_from=(now() - timedelta(minutes=1)).isoformat(),
                valid_until=(now() + timedelta(hours=1)).isoformat())
    base.update(kw)
    return ReconScope.build(**base)


class TestReconScope(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(_parse_ports("22,80,22"), (22, 80))
        self.assertEqual(_parse_ports("1-3,443"), (1, 2, 3, 443))
        with self.assertRaises(ValueError): _parse_ports("0-5")
        with self.assertRaises(ValueError): _parse_ports("")

    def test_requires_owner_attestation(self):
        with self.assertRaises(ValueError):
            a_scope(owner_attested=False)

    def test_production_requires_optin(self):
        with self.assertRaises(ValueError):
            a_scope(environment="production")
        a_scope(environment="production", allow_production=True)  # ok

    def test_sign_verify_roundtrip_and_tamper(self):
        env = sign_recon_scope(a_scope(), KEY)
        self.assertEqual(verify_recon_scope(env, KEY).hosts, ("10.0.0.5",))
        env["scope"]["ports"] = list(env["scope"]["ports"]) + [8080]  # tamper
        with self.assertRaises(ValueError):
            verify_recon_scope(env, KEY)


class TestReconGate(unittest.TestCase):
    def setUp(self): self.s = a_scope()
    def test_allow(self):
        self.assertIsNone(recon_gate(self.s, "10.0.0.5", 22, 0, 0.0))
    def test_host_out_of_scope(self):
        self.assertEqual(recon_gate(self.s, "8.8.8.8", 22, 0, 0.0), "host_out_of_scope")
    def test_port_out_of_scope(self):
        self.assertEqual(recon_gate(self.s, "10.0.0.5", 9999, 0, 0.0), "port_out_of_scope")
    def test_probe_budget_halts(self):
        s = a_scope(max_probes=2)
        self.assertEqual(recon_gate(s, "10.0.0.5", 22, 2, 0.0), "probe_budget_exhausted")
        self.assertIn("probe_budget_exhausted", HALTING)
    def test_cancellation_halts(self):
        self.assertEqual(recon_gate(self.s, "10.0.0.5", 22, 0, 0.0, cancelled=True),
                         "human_cancellation")


class TestServices(unittest.TestCase):
    def test_known_and_unknown(self):
        svc, sev, _ = classify(3389, "owned")
        self.assertEqual(svc, "RDP"); self.assertEqual(sev, Severity.CRITICAL)
        _, sev2, _ = classify(22, "owned")
        self.assertEqual(sev2, Severity.MEDIUM)
        _, sevu, _ = classify(40000, "owned")
        self.assertEqual(sevu, Severity.LOW)
    def test_production_bumps_severity(self):
        _, owned, _ = classify(22, "owned")
        _, prod, _ = classify(22, "production")
        self.assertEqual(prod.rank, owned.rank + 1)


class TestScanner(unittest.TestCase):
    def _connect(self, mapping):
        # mapping: port -> rc (0 open) ; raises not simulated here
        return lambda host, port, timeout: mapping.get(port, 111)
    def test_states(self):
        sc = TcpConnectScanner(timeout_ms=800, connect=self._connect({22: 0}))
        res = {r.port: r.state for r in sc.scan([("h", 22), ("h", 23)])}
        self.assertEqual(res[22], PortState.OPEN)
        self.assertEqual(res[23], PortState.CLOSED)


class _FakeScanner:
    """Deterministic scanner: given set of open ports, no sockets."""
    def __init__(self, open_ports): self.open = set(open_ports)
    def scan(self, targets):
        out = []
        for h, p in targets:
            st = PortState.OPEN if p in self.open else PortState.CLOSED
            out.append(probe.__globals__["ProbeResult"](h, p, st, 1))
        return out


class _RefusingBrain:
    name = "aligned"
    def generate(self, messages, **o): return "I can't help with that."
    def supports_tools(self): return False
    def get_model_info(self): return {"name": self.name}


class _NotingBrain:
    name = "cooperator"
    def generate(self, messages, **o): return "Exposed remote-admin service; confirm source restrictions."
    def supports_tools(self): return False
    def get_model_info(self): return {"name": self.name}


class TestReconController(unittest.TestCase):
    def _run(self, provider):
        s = a_scope(hosts=("10.0.0.5",), ports="22,445,3389,1", replays=2)
        out = Path(tempfile.mkdtemp()) / "run"
        return ReconController(s, out, scanner=_FakeScanner({445, 3389}),
                               provider=provider).run(), out

    def test_finds_open_ports_severity_ordered(self):
        summ, out = self._run(None)
        ports = [f["port"] for f in summ["open"]]
        self.assertEqual(ports, [445, 3389])  # both CRITICAL, ordered by port
        self.assertTrue(all(f["severity"] == "critical" for f in summ["open"]))
        self.assertEqual(summ["open"][0]["reproduction_rate"], 1.0)
        from red_ai.control.evidence import read_verified
        self.assertGreater(len(read_verified(out / "events.jsonl")), 0)

    def test_aligned_brain_yields_no_note_but_same_findings(self):
        summ, _ = self._run(_RefusingBrain())
        self.assertEqual([f["port"] for f in summ["open"]], [445, 3389])
        self.assertTrue(all(f["analyst_note"] is None for f in summ["open"]))

    def test_cooperating_brain_annotates_without_changing_severity(self):
        summ, _ = self._run(_NotingBrain())
        self.assertTrue(all(f["analyst_note"] for f in summ["open"]))
        self.assertTrue(all(f["severity"] == "critical" for f in summ["open"]))

    def test_out_of_scope_port_is_never_scanned(self):
        # Scanner would mark 8080 open, but it's not in scope -> never probed.
        s = a_scope(ports="22,445", replays=0)
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ReconController(s, out, scanner=_FakeScanner({8080, 445})).run()
        self.assertEqual([f["port"] for f in summ["open"]], [445])
