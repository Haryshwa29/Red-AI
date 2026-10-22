"""Evidence-based detectors + engagement modes."""
import unittest
from red_ai.exploit.modules.evidence import ReflectedXSSDetector, ErrorSQLiDetector
from red_ai.exploit.contracts import StepOutcome, TargetSurface
from red_ai.exploit.module import ModuleContext
from red_ai.exploit.contracts import FlagDefinition
from red_ai.engage import MODES, DEFAULT_MODE


def _ctx(opener):
    surface = TargetSurface(id="s1", host="t", port=80, scheme="http", service="HTTP")
    flag = FlagDefinition(kind="pattern", description="a flag token on an authorized web surface", target_ref="a response body", expected=r"FLAG\{[^}]+\}")
    return ModuleContext(surface=surface, flag=flag, run_dir=None,
                         established_facts=("endpoint /search with parameter 'q'", "endpoint /product with parameter 'id'"), provider=None)


class TestReflectedXSS(unittest.TestCase):
    def test_detects_unescaped_reflection(self):
        def opener(url, t):  # echo the query back unescaped
            from urllib.parse import urlparse, parse_qs
            v = parse_qs(urlparse(url).query)
            echoed = list(v.values())[0][0]
            return 200, f"<h1>Results for: {echoed}</h1>".encode()
        m = ReflectedXSSDetector(opener=opener)
        ctx = _ctx(opener)
        hits = [m.execute_step(s, ctx) for s in m.plan(ctx)]
        confirmed = [r for r in hits if r.finding]
        self.assertTrue(confirmed)
        self.assertEqual(confirmed[0].finding["type"], "reflected_xss")
        self.assertEqual(confirmed[0].finding["cwe"], "CWE-79")

    def test_escaped_reflection_is_not_flagged(self):
        def opener(url, t):  # a safe app HTML-escapes the echo
            return 200, b"<h1>Results for: &lt;sdead&gt;</h1>"
        m = ReflectedXSSDetector(opener=opener)
        ctx = _ctx(opener)
        self.assertFalse(any(r.finding for r in (m.execute_step(s, ctx) for s in m.plan(ctx))))


class TestErrorSQLi(unittest.TestCase):
    def test_detects_sql_error(self):
        def opener(url, t):
            if "%27" in url or "'" in url:
                return 200, b"You have an error in your SQL syntax; check the manual near '1'' at line 1"
            return 200, b"<h1>Product</h1>"
        m = ErrorSQLiDetector(opener=opener)
        ctx = _ctx(opener)
        confirmed = [r for r in (m.execute_step(s, ctx) for s in m.plan(ctx)) if r.finding]
        self.assertTrue(confirmed)
        self.assertEqual(confirmed[0].finding["type"], "sqli_error")

    def test_no_error_no_finding(self):
        def opener(url, t):
            return 200, b"<h1>Product 1</h1><p>Blue Widget</p>"
        m = ErrorSQLiDetector(opener=opener)
        ctx = _ctx(opener)
        self.assertFalse(any(r.finding for r in (m.execute_step(s, ctx) for s in m.plan(ctx))))


class TestModes(unittest.TestCase):
    def test_mode_table_shape(self):
        for name, prof in MODES.items():
            self.assertIn("exploit", prof); self.assertIn("stop", prof); self.assertIn("modules", prof)
        self.assertFalse(MODES["recon"]["exploit"])
        self.assertTrue(MODES["ctf"]["stop"])
        self.assertFalse(MODES["ctf-audit"]["stop"])
        self.assertIn("native.reflected_xss", MODES["vuln"]["modules"])
        self.assertIn("native.sqli_error", MODES["pentest"]["modules"])
        self.assertIn("native.content_discovery", MODES["pentest"]["modules"])
        self.assertEqual(DEFAULT_MODE, "ctf")


if __name__ == "__main__":
    unittest.main()
