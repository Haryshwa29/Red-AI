"""Boolean + time-based blind SQLi detectors (injected opener)."""
import unittest
from red_ai.exploit.modules.evidence import BooleanBlindSQLiDetector, TimeBlindSQLiDetector
from red_ai.exploit.contracts import TargetSurface, FlagDefinition
from red_ai.exploit.module import ModuleContext


def _ctx():
    s = TargetSurface(id="s1", host="t", port=80, scheme="http", service="HTTP")
    flag = FlagDefinition(kind="pattern", description="a flag on an authorized surface",
                          target_ref="a body", expected=r"FLAG\{[^}]+\}")
    return ModuleContext(surface=s, flag=flag, run_dir=None,
                         established_facts=("endpoint /profile with parameter 'uid'",), provider=None)


class TestBooleanBlind(unittest.TestCase):
    def test_boolean_divergence_detected(self):
        def opener(url, t):
            body = "X" * 1000  # baseline/true page
            if "%271%27%3D%272" in url or "1%3D2" in url or "'1'='2" in url.replace("%27","'").replace("%3D","="):
                body = "X" * 1000 + "DIFFERENT-FALSE-PAGE" * 5
            return 200, body.encode()
        m = BooleanBlindSQLiDetector(opener=opener)
        ctx = _ctx()
        hits = [m.execute_step(s, ctx) for s in m.plan(ctx)]
        self.assertTrue(any(r.finding and r.finding["type"] == "sqli_boolean_blind" for r in hits))

    def test_no_divergence_no_finding(self):
        def opener(url, t):
            return 200, (b"X" * 1000)
        m = BooleanBlindSQLiDetector(opener=opener)
        ctx = _ctx()
        self.assertFalse(any(r.finding for r in (m.execute_step(s, ctx) for s in m.plan(ctx))))


class TestTimeBlind(unittest.TestCase):
    def test_sleep_delay_detected(self):
        import time
        def opener(url, t):
            if "SLEEP" in url.upper() or "WAITFOR" in url.upper():
                time.sleep(2.2)
            return 200, b"ok"
        m = TimeBlindSQLiDetector(opener=opener, threshold=1.5)
        ctx = _ctx()
        hits = [m.execute_step(s, ctx) for s in m.plan(ctx)]
        self.assertTrue(any(r.finding and r.finding["type"] == "sqli_time_blind" for r in hits))


if __name__ == "__main__":
    unittest.main()
