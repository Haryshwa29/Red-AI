"""Web console plumbing: the Journal on_event tap (and that an observer can never
break evidence), the educational annotator's mapping, and engage_core's
authorization precondition. All hermetic -- no sockets."""
import tempfile
import unittest
from pathlib import Path

from red_ai.control.evidence import Journal
from red_ai.engage import engage_core, EngageError
from red_ai.web.annotate import annotate


class TestJournalTap(unittest.TestCase):
    def test_on_event_fires_after_append(self):
        seen = []
        j = Journal(Path(tempfile.mkdtemp()) / "e.jsonl", on_event=lambda ev: seen.append(ev))
        j.append("probe", {"port": 80, "state": "open"})
        j.append("finding", {"port": 80})
        j.close()
        self.assertEqual([e["kind"] for e in seen], ["probe", "finding"])
        self.assertIn("hash", seen[0])   # observer sees the fully-formed, hashed event

    def test_observer_error_never_breaks_evidence(self):
        path = Path(tempfile.mkdtemp()) / "e.jsonl"
        j = Journal(path, on_event=lambda ev: (_ for _ in ()).throw(RuntimeError("boom")))
        j.append("run_started", {"x": 1})   # must not raise
        j.close()
        self.assertTrue(path.read_text().strip())  # event still written


class TestAnnotator(unittest.TestCase):
    def test_maps_key_events(self):
        self.assertEqual(annotate({"kind": "engage_started",
            "payload": {"target": "10.0.0.1", "ports": "1-1000", "operator": "me"}})["stage"], "authorize")
        self.assertEqual(annotate({"kind": "probe", "phase": "recon",
            "payload": {"port": 8080, "state": "open", "latency_ms": 1}})["level"], "good")
        cap = annotate({"kind": "engage_finished",
            "payload": {"status": "captured", "flag_value": "THM{x}", "outcome": "flag_captured", "steps": 3}})
        self.assertEqual(cap["level"], "flag")
        self.assertIn("THM{x}", cap["text"])

    def test_drops_noise(self):
        self.assertIsNone(annotate({"kind": "probe", "phase": "recon",
                                    "payload": {"port": 81, "state": "closed"}}))
        self.assertIsNone(annotate({"kind": "gate", "phase": "exploit",
                                    "payload": {"decision": "allow"}}))

    def test_web_enum_with_finding_returns_two_lines(self):
        out = annotate({"kind": "web_enum", "phase": "recon", "payload": {
            "port": 80, "root": {"status": 200}, "paths": [1, 2],
            "web_findings": [{"path": "/.env", "meaning": "secrets", "severity": "critical"}]}})
        self.assertIsInstance(out, list)
        self.assertTrue(any(ln["level"] == "finding" for ln in out))


class TestEngageAuthPrecondition(unittest.TestCase):
    def test_unknown_operator_raises_before_any_network(self):
        root = Path(tempfile.mkdtemp())  # no operators created
        with self.assertRaises(EngageError):
            engage_core(root=root, target="127.0.0.1", operator="ghost",
                        attestation="test")


if __name__ == "__main__":
    unittest.main()
