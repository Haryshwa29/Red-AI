"""Injection family (LFI, SQLi, command injection): each captures its flag by
injecting into a recon-discovered parameter, holds on a non-vulnerable endpoint,
and is refused by the gate when `injection` is not an authorized technique.
Hermetic (injected opener that decodes the payload and applies a vuln rule)."""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from red_ai.contracts.scope import now
from red_ai.exploit import (ExploitScope, FlagDefinition, TargetSurface,
                            ExploitModuleRegistry, AttemptOutcome)
from red_ai.exploit.contracts import ExploitTechnique
from red_ai.exploit.controller import ExploitController
from red_ai.exploit.modules.injection import LFIModule, SQLiModule, CommandInjectionModule

FLAG = "THM{injection_proof}"
PATTERN = r"THM\{[^}]+\}"
ENDPOINT_FACT = "recon: endpoint /x with parameter 'p' (sample: a)"


def _flag():
    return FlagDefinition(kind="pattern", description="any THM-form flag via injection",
                          target_ref="injected response", expected=PATTERN)


def _scope(**kw):
    base = dict(scope_id="x", owner="o", authorised_by="o", surfaces=("srf",), flag=_flag(),
                attestation="authorized lab", owner_attested=True, environment="authorized_lab",
                valid_from=(now() - timedelta(minutes=1)).isoformat(),
                valid_until=(now() + timedelta(hours=1)).isoformat())
    base.update(kw)
    return ExploitScope(**base)


def _surface():
    return TargetSurface(host="10.10.1.6", port=80, service="HTTP", id="srf")


def _opener(rule):
    """Build an opener that returns the flag when the decoded payload satisfies `rule`."""
    def opener(url, timeout):
        q = parse_qs(urlparse(url).query)
        payload = unquote(q.get("p", [""])[0])
        if rule(payload):
            return 200, (f"result: {FLAG}\n").encode()
        return 200, b"nothing interesting\n"
    return opener


def _run(module):
    reg = ExploitModuleRegistry(); reg.register(module)
    out = Path(tempfile.mkdtemp()) / "run"
    return ExploitController(_scope(), out, reg, surfaces=(_surface(),),
                             established_facts=(ENDPOINT_FACT,)).run()


class TestInjectionModules(unittest.TestCase):
    def test_lfi_captures_via_traversal(self):
        summ = _run(LFIModule(opener=_opener(lambda p: "../" in p and p.endswith("flag"))))
        self.assertTrue(summ["flag"]["captured"])
        self.assertEqual(summ["findings"][0]["flag_value"], FLAG)

    def test_sqli_captures_via_union(self):
        summ = _run(SQLiModule(opener=_opener(lambda p: "union" in p.lower() and "select" in p.lower())))
        self.assertTrue(summ["flag"]["captured"])

    def test_cmdi_captures_via_separator(self):
        summ = _run(CommandInjectionModule(
            opener=_opener(lambda p: any(c in p for c in (";", "|", "&&", "$(", "`")))))
        self.assertTrue(summ["flag"]["captured"])

    def test_no_capture_on_non_vulnerable_endpoint(self):
        summ = _run(LFIModule(opener=_opener(lambda p: False)))
        self.assertFalse(summ["flag"]["captured"])
        self.assertEqual(summ["outcome"], AttemptOutcome.NO_BREACH.value)

    def test_injection_denied_when_technique_not_authorized(self):
        reg = ExploitModuleRegistry()
        reg.register(LFIModule(opener=_opener(lambda p: "../" in p and p.endswith("flag"))))
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(techniques=(ExploitTechnique.DATA_ACCESS.value,)),
                                 out, reg, surfaces=(_surface(),),
                                 established_facts=(ENDPOINT_FACT,)).run()
        self.assertFalse(summ["flag"]["captured"])

    def test_no_steps_without_a_discovered_parameter(self):
        # no endpoint fact -> nothing to inject into (discovery stays recon's job)
        reg = ExploitModuleRegistry(); reg.register(LFIModule(opener=_opener(lambda p: True)))
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(), out, reg, surfaces=(_surface(),),
                                 established_facts=()).run()
        self.assertFalse(summ["flag"]["captured"])


if __name__ == "__main__":
    unittest.main()
