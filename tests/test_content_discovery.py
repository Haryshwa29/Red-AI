"""Content-discovery module: captures a flag on a brute-found page, records
discovered paths as footholds (so later modules inherit them), ignores 404s, and
is refused by the gate when MISCONFIGURATION isn't authorized. Hermetic."""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.scope import now
from red_ai.exploit import (ExploitScope, FlagDefinition, TargetSurface,
                            ExploitModuleRegistry, AttemptOutcome)
from red_ai.exploit.contracts import ExploitStep, ExploitTechnique, StepOutcome
from red_ai.exploit.module import ModuleContext
from red_ai.exploit.controller import ExploitController
from red_ai.exploit.modules.content_discovery import ContentDiscoveryModule, WORDLIST

FLAG = "THM{dirbrute}"
PATTERN = r"THM\{[^}]+\}"


def _flag():
    return FlagDefinition(kind="pattern", description="flag on a hidden page",
                          target_ref="a discovered page", expected=PATTERN)


def _scope(**kw):
    base = dict(scope_id="x", owner="o", authorised_by="o", surfaces=("srf",), flag=_flag(),
                attestation="authorized lab", owner_attested=True, environment="authorized_lab",
                valid_from=(now() - timedelta(minutes=1)).isoformat(),
                valid_until=(now() + timedelta(hours=1)).isoformat())
    base.update(kw)
    return ExploitScope(**base)


def _surface():
    return TargetSurface(host="10.10.1.9", port=80, service="HTTP", id="srf")


def _opener(url, timeout):
    if url.endswith("/internal"):
        return 200, b"<html>Internal portal " + FLAG.encode() + b"</html>"
    if url.endswith("/admin"):
        return 200, b"<html>admin login</html>"      # discovered, no flag
    return 404, b"Not Found"


class TestContentDiscovery(unittest.TestCase):
    def test_wordlist_includes_internal(self):
        self.assertIn("/internal", WORDLIST)   # the fixture relies on this

    def test_captures_flag_on_brute_found_page(self):
        reg = ExploitModuleRegistry(); reg.register(ContentDiscoveryModule(opener=_opener))
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(), out, reg, surfaces=(_surface(),)).run()
        self.assertTrue(summ["flag"]["captured"])
        self.assertEqual(summ["findings"][0]["flag_value"], FLAG)

    def test_records_discovered_path_as_foothold(self):
        m = ContentDiscoveryModule(opener=_opener)
        ctx = ModuleContext(surface=_surface(), flag=_flag(),
                            run_dir=Path(tempfile.mkdtemp()), established_facts=())
        step = ExploitStep(module_id=m.id, technique=m.technique, surface_id="srf",
                           intent="discover /admin", params={"path": "/admin"})
        res = m.execute_step(step, ctx)
        self.assertIs(res.outcome, StepOutcome.ADVANCED)
        self.assertIn("/admin", res.proves)
        self.assertFalse(res.flag_captured)

    def test_404_is_no_effect(self):
        m = ContentDiscoveryModule(opener=_opener)
        ctx = ModuleContext(surface=_surface(), flag=_flag(),
                            run_dir=Path(tempfile.mkdtemp()), established_facts=())
        step = ExploitStep(module_id=m.id, technique=m.technique, surface_id="srf",
                           intent="discover /nope", params={"path": "/does-not-exist"})
        self.assertIs(m.execute_step(step, ctx).outcome, StepOutcome.NO_EFFECT)

    def test_gated_when_misconfiguration_not_authorized(self):
        reg = ExploitModuleRegistry(); reg.register(ContentDiscoveryModule(opener=_opener))
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(techniques=(ExploitTechnique.DATA_ACCESS.value,)),
                                 out, reg, surfaces=(_surface(),)).run()
        self.assertFalse(summ["flag"]["captured"])


if __name__ == "__main__":
    unittest.main()
