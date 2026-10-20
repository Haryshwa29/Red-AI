"""HTTPS / any-port support: web modules honour a surface's scheme, and recon web
enum auto-detects https when http does not answer. Hermetic."""
import unittest

from red_ai.exploit.contracts import TargetSurface
from red_ai.exploit.module import ModuleContext
from red_ai.exploit.contracts import ExploitStep, FlagDefinition
from red_ai.exploit.modules.web_flag_hunt import surface_base, WebFlagHuntModule
from red_ai.recon.web import enumerate_web


class TestSurfaceScheme(unittest.TestCase):
    def test_surface_base_honours_scheme_on_any_port(self):
        s = TargetSurface(host="10.0.0.5", port=8443, service="HTTP", scheme="https", id="x")
        self.assertEqual(surface_base(s), "https://10.0.0.5:8443")

    def test_surface_base_defaults_http(self):
        s = TargetSurface(host="10.0.0.5", port=3000, service="HTTP", id="x")
        self.assertEqual(surface_base(s), "http://10.0.0.5:3000")

    def test_module_requests_https_when_surface_is_https(self):
        seen = {}
        def opener(url, t):
            seen["url"] = url
            return (200, b"THM{x}")
        s = TargetSurface(host="10.0.0.5", port=8443, service="HTTP", scheme="https", id="x")
        ctx = ModuleContext(surface=s,
                            flag=FlagDefinition(kind="pattern", description="flag form",
                                                target_ref="b", expected=r"THM\{[^}]+\}"),
                            run_dir=__import__("pathlib").Path("/tmp"), established_facts=())
        step = ExploitStep(module_id="native.web_flag_hunt", technique="data_access",
                           surface_id="x", intent="get /flag", params={"path": "/flag"})
        WebFlagHuntModule(opener=opener).execute_step(step, ctx)
        self.assertTrue(seen["url"].startswith("https://10.0.0.5:8443/flag"))


class TestWebEnumSchemeDetect(unittest.TestCase):
    def test_falls_back_to_https(self):
        # http root returns nothing (status 0); https answers 200
        def opener(url, t):
            if url.startswith("https://"):
                return (200, {"Server": "lab"}, b"<title>Device</title>")
            return (0, {}, b"")
        out = enumerate_web("10.0.0.5", 8443, opener=opener)
        self.assertEqual(out["root"]["scheme"], "https")
        self.assertEqual(out["root"]["status"], 200)


if __name__ == "__main__":
    unittest.main()
