"""Email-auth posture (SPF/DKIM/DMARC) and WAF detection."""
import unittest
from red_ai.recon.email_auth import assess_email_auth, _parse_txt
from red_ai.recon.waf import detect_waf


class TestEmailAuth(unittest.TestCase):
    def _lookup(self, records):
        return lambda name: records.get(name, [])

    def test_spoofable_no_dmarc(self):
        r = assess_email_auth("example.com", self._lookup({
            "example.com": ["v=spf1 include:_spf.google.com ~all"]}))
        self.assertTrue(r["spoofable"]); self.assertEqual(r["severity"], "high")
        self.assertIn("no DMARC", r["evidence"])

    def test_dmarc_none_is_spoofable(self):
        r = assess_email_auth("example.com", self._lookup({
            "example.com": ["v=spf1 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:x@example.com"]}))
        self.assertTrue(r["spoofable"]); self.assertEqual(r["dmarc"]["p"], "none")

    def test_protected_enforcing_dmarc(self):
        r = assess_email_auth("secure.com", self._lookup({
            "secure.com": ["v=spf1 ip4:1.2.3.4 -all"],
            "_dmarc.secure.com": ["v=DMARC1; p=reject"],
            "default._domainkey.secure.com": ["v=DKIM1; k=rsa; p=MIIB..."]}))
        self.assertFalse(r["spoofable"]); self.assertEqual(r["severity"], "low")
        self.assertIn("default", r["dkim_selectors"])

    def test_parse_txt_malformed_is_safe(self):
        self.assertEqual(_parse_txt(b"\x00\x01"), [])


class TestWAF(unittest.TestCase):
    def test_behavioral_block(self):
        def opener(url, t):
            return (403, {}, "blocked") if "script" in url else (200, {}, "ok")
        r = detect_waf("http://t", opener)
        self.assertTrue(r["present"]); self.assertEqual(r["blocked_status"], 403)

    def test_vendor_signature(self):
        def opener(url, t):
            return 200, {"cf-ray": "abc123", "server": "cloudflare"}, "hi"
        r = detect_waf("http://t", opener)
        self.assertTrue(r["present"]); self.assertEqual(r["vendor"], "Cloudflare")

    def test_no_waf(self):
        def opener(url, t):
            return 200, {"server": "nginx"}, "normal page"
        r = detect_waf("http://t", opener)
        self.assertFalse(r["present"]); self.assertIsNone(r["vendor"])


if __name__ == "__main__":
    unittest.main()
