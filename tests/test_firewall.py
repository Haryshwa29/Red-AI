"""Firewall / exposure posture derived from recon port states."""
import unittest
from red_ai.recon.firewall import assess_firewall


class TestFirewallPosture(unittest.TestCase):
    def test_filtering_firewall(self):
        r = assess_firewall({"counts": {"open": 2, "closed": 0, "filtered": 98, "error": 0}, "open": []})
        self.assertEqual(r["posture"], "filtering")

    def test_no_filtering_answers_closed(self):
        r = assess_firewall({"counts": {"open": 1, "closed": 99, "filtered": 0, "error": 0}, "open": []})
        self.assertEqual(r["posture"], "no-filtering")
        self.assertEqual(r["severity"], "medium")

    def test_permissive_all_open(self):
        r = assess_firewall({"counts": {"open": 5, "closed": 0, "filtered": 0, "error": 0}, "open": []})
        self.assertEqual(r["posture"], "permissive")

    def test_exposed_sensitive_service_raises_severity(self):
        r = assess_firewall({"counts": {"open": 1, "closed": 0, "filtered": 99, "error": 0},
                             "open": [{"port": 3389, "service": "rdp"}]})
        self.assertEqual(r["severity"], "high")
        self.assertEqual(r["exposed_sensitive"][0]["service"], "RDP")
        self.assertTrue(r["recommendations"])

    def test_unknown_when_no_scan(self):
        self.assertEqual(assess_firewall({})["posture"], "unknown")


if __name__ == "__main__":
    unittest.main()
