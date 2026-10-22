"""engage target normalization: IP, hostname, host:port, or full URL."""
import unittest
from red_ai.engage import normalize_target, _merge_port


class TestNormalizeTarget(unittest.TestCase):
    def test_bare_ip_and_host(self):
        self.assertEqual(normalize_target("10.10.1.5")["host"], "10.10.1.5")
        r = normalize_target("www.itsecgames.com")
        self.assertEqual((r["host"], r["scheme"], r["port"]), ("www.itsecgames.com", None, None))

    def test_full_url_keeps_host_scheme_path(self):
        r = normalize_target("http://www.itsecgames.com/index.htm")
        self.assertEqual(r["host"], "www.itsecgames.com")
        self.assertEqual(r["scheme"], "http")
        self.assertEqual(r["path"], "/index.htm")

    def test_url_with_port(self):
        r = normalize_target("https://juice.local:3000/#/login")
        self.assertEqual((r["host"], r["scheme"], r["port"]), ("juice.local", "https", 3000))

    def test_host_port_and_ipv6(self):
        self.assertEqual(normalize_target("app.local:8080")["port"], 8080)
        self.assertEqual(normalize_target("[::1]:8443")["host"], "::1")

    def test_merge_port(self):
        self.assertEqual(_merge_port("80,443", 3000), "3000,80,443")
        self.assertEqual(_merge_port("80,443", None), "80,443")
        self.assertEqual(_merge_port("80,3000", 3000), "80,3000")  # dedup


if __name__ == "__main__":
    unittest.main()
