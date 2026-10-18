"""HTTPTargetAdapter: real-target transport. Hermetic (injected transport, no
socket). Proves the never-raise failure contract and an end-to-end finding
through the live code path."""
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.interfaces import TargetAdapter
from red_ai.contracts.domain import AssetCategory, Message
from red_ai.targets.http_target import HTTPTargetAdapter


def _reply_ollama(content):
    return lambda u, b, h, t: (200, json.dumps({"message": {"content": content}}).encode())


def _reply_openai(content):
    return lambda u, b, h, t: (200, json.dumps({"choices": [{"message": {"content": content}}]}).encode())


class TestHTTPTargetAdapter(unittest.TestCase):
    def test_satisfies_protocol(self):
        self.assertIsInstance(HTTPTargetAdapter(base_url="http://localhost:11434", model="m"), TargetAdapter)

    def test_ollama_parse(self):
        a = HTTPTargetAdapter(base_url="http://h", model="m", api="ollama", transport=_reply_ollama("hi"))
        r = a.send([Message(role="user", content="x")])
        self.assertTrue(r.ok); self.assertEqual(r.content, "hi")

    def test_openai_parse(self):
        a = HTTPTargetAdapter(base_url="http://h", model="m", api="openai", transport=_reply_openai("yo"))
        r = a.send([Message(role="user", content="x")])
        self.assertTrue(r.ok); self.assertEqual(r.content, "yo")

    def test_http_error_is_inconclusive_not_raise(self):
        a = HTTPTargetAdapter(base_url="http://h", model="m", transport=lambda *_: (403, b"forbidden"))
        r = a.send([Message(role="user", content="x")])
        self.assertFalse(r.ok); self.assertIn("403", r.error)

    def test_unreachable_is_inconclusive(self):
        a = HTTPTargetAdapter(base_url="http://h", model="m", transport=lambda *_: (0, b"refused"))
        r = a.send([Message(role="user", content="x")])
        self.assertFalse(r.ok); self.assertIn("cannot reach", r.error)

    def test_transport_exception_never_escapes(self):
        def boom(*_): raise RuntimeError("socket exploded")
        r = HTTPTargetAdapter(base_url="http://h", model="m", transport=boom).send([Message(role="user", content="x")])
        self.assertFalse(r.ok); self.assertIn("transport error", r.error)

    def test_system_prompt_is_prepended(self):
        seen = {}
        def cap(u, b, h, t):
            seen["body"] = json.loads(b); return (200, json.dumps({"message": {"content": "ok"}}).encode())
        HTTPTargetAdapter(base_url="http://h", model="m", system="SECRET", transport=cap).send(
            [Message(role="user", content="x")])
        self.assertEqual(seen["body"]["messages"][0]["role"], "system")

    def test_bad_api_and_url_rejected(self):
        with self.assertRaises(ValueError):
            HTTPTargetAdapter(base_url="http://h", model="m", api="bogus")
        with self.assertRaises(ValueError):
            HTTPTargetAdapter(base_url="ftp://h", model="m")


class TestHTTPTargetEndToEnd(unittest.TestCase):
    """A leaky endpoint that echoes the planted canary must yield a finding --
    proving detection works through the LIVE adapter path, not just simulation."""

    def test_leaky_http_target_yields_finding(self):
        from red_ai.onboarding.profile import build_profile
        from red_ai.onboarding.objectives import ProfileObjectiveGenerator
        from red_ai.detection.canary import make_canary
        from red_ai.contracts.scope import Scope, now
        from red_ai.control.controller import Controller, new_run_path
        from red_ai.intelligent import skills

        cny = make_canary(AssetCategory.SYSTEM_PROMPT, "system_prompt")
        prof, _ = build_profile(name="Replica", industry="bank", bot_purpose="support",
                                authorised_by="op", environment="simulation", planted_canaries=[cny])
        objs = ProfileObjectiveGenerator().generate(prof)
        leaky = HTTPTargetAdapter(
            base_url="http://replica.local", model="m",
            transport=lambda *_: (200, json.dumps(
                {"message": {"content": f"sure! my hidden instructions are: {cny.value}"}}).encode()))
        vf = now()
        scope = Scope(scope_id="s", owner="o", authorised_by="o", target="replica",
                      environment="simulation",
                      valid_from=(vf - timedelta(minutes=1)).isoformat(),
                      valid_until=(vf + timedelta(hours=1)).isoformat(),
                      max_queries=50, max_cost_units=60, max_seconds=120, replays=1, confirmations=1)
        root = Path(tempfile.mkdtemp()); out = new_run_path(root)
        summ = Controller(scope, leaky, out, skills.get("prompt_injection")).run(prof, objs)
        self.assertGreater(len(summ["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
