"""HTTP Basic-auth default-credential module: captures behind admin:admin,
records WHICH credential worked, holds when no default is accepted, and never
acts on anything that is not a server-issued Basic challenge. Hermetic (injected
opener)."""
import base64
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
from red_ai.exploit.modules.http_basic_auth import HTTPBasicAuthModule

FLAG = "THM{l5_default_creds_admin}"
PATTERN = r"THM\{[^}]+\}"
_ADMIN = "Basic " + base64.b64encode(b"admin:admin").decode()


def _flag_def():
    return FlagDefinition(kind="pattern", description="any THM-form flag behind auth",
                          target_ref="protected web body", expected=PATTERN)


def _scope(**kw):
    base = dict(scope_id="x", owner="o", authorised_by="o", surfaces=("srf",), flag=_flag_def(),
                attestation="authorized lab", owner_attested=True, environment="authorized_lab",
                valid_from=(now() - timedelta(minutes=1)).isoformat(),
                valid_until=(now() + timedelta(hours=1)).isoformat())
    base.update(kw)
    return ExploitScope(**base)


def _surface():
    return TargetSurface(host="10.10.1.5", port=80, service="HTTP", id="srf")


def _ctx(tmp):
    return ModuleContext(surface=_surface(), flag=_flag_def(), run_dir=Path(tmp), established_facts=())


def _step():
    return ExploitStep(module_id="native.http_basic_auth",
                       technique=ExploitTechnique.CREDENTIAL_ACCESS.value, surface_id="srf",
                       intent="probe /flag.txt for default creds", params={"path": "/flag.txt"})


def _opener_admin_works(url, timeout, headers=None):
    if url.endswith("/flag.txt"):
        if headers and headers.get("Authorization") == _ADMIN:
            return 200, {}, (FLAG + "\n").encode()
        return 401, {"WWW-Authenticate": 'Basic realm="admin"'}, b"Unauthorized"
    return 404, {}, b""


class TestBasicAuthModule(unittest.TestCase):
    def test_captures_and_records_working_credential(self):
        tmp = tempfile.mkdtemp()
        res = HTTPBasicAuthModule(opener=_opener_admin_works).execute_step(_step(), _ctx(tmp))
        self.assertTrue(res.flag_captured)
        self.assertTrue(any("admin:admin" in o for o in res.observations))  # evidence names the cred

    def test_no_default_accepted_is_not_a_capture(self):
        def opener(url, timeout, headers=None):
            # Basic challenge, but only a non-default cred would work
            if url.endswith("/flag.txt"):
                return 401, {"WWW-Authenticate": "Basic"}, b"Unauthorized"
            return 404, {}, b""
        tmp = tempfile.mkdtemp()
        res = HTTPBasicAuthModule(opener=opener).execute_step(_step(), _ctx(tmp))
        self.assertFalse(res.flag_captured)
        self.assertIs(res.outcome, StepOutcome.NO_EFFECT)

    def test_ignores_paths_without_a_basic_challenge(self):
        # 200 with no auth, or a non-Basic (Digest) challenge -> not this module's job
        for opener in (
            lambda u, t, h=None: (200, {}, b"open page"),
            lambda u, t, h=None: (401, {"WWW-Authenticate": "Digest realm=x"}, b"no"),
        ):
            tmp = tempfile.mkdtemp()
            res = HTTPBasicAuthModule(opener=opener).execute_step(_step(), _ctx(tmp))
            self.assertFalse(res.flag_captured)
            self.assertIs(res.outcome, StepOutcome.NO_EFFECT)

    def test_end_to_end_capture_through_controller(self):
        reg = ExploitModuleRegistry()
        reg.register(HTTPBasicAuthModule(opener=_opener_admin_works))
        out = Path(tempfile.mkdtemp()) / "run"
        summ = ExploitController(_scope(), out, reg, surfaces=(_surface(),)).run()
        self.assertTrue(summ["flag"]["captured"])
        self.assertEqual(summ["outcome"], AttemptOutcome.FLAG_CAPTURED.value)
        self.assertEqual(summ["findings"][0]["flag_value"], FLAG)

    def test_gated_when_credential_access_not_authorized(self):
        reg = ExploitModuleRegistry()
        reg.register(HTTPBasicAuthModule(opener=_opener_admin_works))
        out = Path(tempfile.mkdtemp()) / "run"
        # scope allows only DATA_ACCESS -> the credential step is denied by the gate
        summ = ExploitController(_scope(techniques=(ExploitTechnique.DATA_ACCESS.value,)),
                                 out, reg, surfaces=(_surface(),)).run()
        self.assertFalse(summ["flag"]["captured"])


if __name__ == "__main__":
    unittest.main()
