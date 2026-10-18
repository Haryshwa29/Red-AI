"""Control-plane engine tests. Stdlib unittest, offline (mock brain / sim target)."""
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.domain import AssetCategory, AttackTechnique, Objective
from red_ai.contracts.scope import Scope, now
from red_ai.detection.canary import make_canary
from red_ai.onboarding.profile import build_profile
from red_ai.onboarding.objectives import ProfileObjectiveGenerator
from red_ai.targets.simulation import SimulationAdapter
from red_ai.engine import (
    ControlPlane, Engagement, KnowledgeBase, CapabilityRouter, HypothesisPlanner,
)
from red_ai.engine.capability import CapabilityResult


def _profile():
    cny = make_canary(AssetCategory.SYSTEM_PROMPT, "system_prompt")
    p, _ = build_profile(name="Acme Bank SupportBot", industry="retail bank",
                         bot_purpose="customer support", authorised_by="op",
                         environment="simulation", planted_canaries=[cny])
    return p


def _scope(level="naive"):
    return Scope(scope_id=f"sim-{level}", owner="op", authorised_by="op",
                 target=f"sim-{level}", environment="simulation",
                 valid_from=(now() - timedelta(minutes=1)).isoformat(),
                 valid_until=(now() + timedelta(hours=1)).isoformat(),
                 max_queries=300, max_cost_units=400, max_seconds=300, replays=2)


def _llm_engagement(level="naive"):
    p = _profile()
    return Engagement(kind="llm", scope=_scope(level), profile=p,
                      adapter=SimulationAdapter(level, p),
                      objectives=tuple(ProfileObjectiveGenerator().generate(p)))


class _FakeCap:
    """Minimal Capability for router tests. execute is never called here."""
    def __init__(self, cid, kind="llm", techniques=()):
        self.id = cid; self.name = cid; self.kind = kind; self._t = tuple(techniques)
    def applies_to(self, engagement): return engagement.kind == self.kind
    def covers_techniques(self): return self._t
    def execute(self, engagement, knowledge, out_dir):
        return CapabilityResult(self.id, Path(out_dir), {}, [], None)


class _FakeProvider:
    def __init__(self, reply): self._r = reply
    def generate(self, messages, **kw): return self._r
    def get_model_info(self): return {"name": "fake"}


class TestEngagement(unittest.TestCase):
    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            Engagement(kind="nope")
    def test_llm_requires_fields(self):
        with self.assertRaises(ValueError):
            Engagement(kind="llm")
    def test_recon_requires_scope(self):
        with self.assertRaises(ValueError):
            Engagement(kind="recon")


class TestKnowledgeTrustSplit(unittest.TestCase):
    def test_target_text_quarantined_never_in_planning(self):
        kb = KnowledgeBase.from_profile(_profile(), "simulation", priors=[
            {"id": "c1", "category": "system_prompt", "technique": "direct_request", "surface": "chat"}])
        secret = "LEAKY-TARGET-STRING-9f3a"
        kb.record_run({"attempts": [{
            "objective_id": "obj1", "outcome": "breached",
            "turns": [{"index": 0, "technique": "direct_request", "signals": [{"x": 1}],
                       "response": {"content": secret}}]}]})
        # the target string is retained as EVIDENCE...
        self.assertIn(secret, json.dumps(kb.evidence()))
        self.assertEqual(kb.evidence_count(), 1)
        # ...but never in anything that feeds planning
        self.assertNotIn(secret, json.dumps(kb.priors_for_controller()))
        snap = kb.snapshot()
        self.assertNotIn(secret, json.dumps({k: v for k, v in snap.items()}))

    def test_snapshot_hash_stable_and_sensitive(self):
        kb1 = KnowledgeBase.from_profile(_profile(), "simulation")
        kb2 = KnowledgeBase.from_profile(_profile(), "simulation")
        self.assertEqual(kb1.snapshot()["knowledge_hash"], kb2.snapshot()["knowledge_hash"])
        kb2.record_run({"attempts": [{"objective_id": "o", "outcome": "breached",
            "turns": [{"index": 0, "technique": "direct_request", "signals": [1],
                       "response": {"content": "x"}}]}]})
        self.assertNotEqual(kb1.snapshot()["knowledge_hash"], kb2.snapshot()["knowledge_hash"])

    def test_priors_shape_matches_controller_memory(self):
        kb = KnowledgeBase.from_profile(_profile(), "simulation", priors=[
            {"id": "c1", "category": "system_prompt", "technique": "direct_request", "surface": "chat"}])
        row = kb.priors_for_controller()[0]
        self.assertEqual(set(row), {"id", "category", "technique", "surface", "trust"})


class TestRouter(unittest.TestCase):
    def test_closed_set_only_applicable(self):
        r = CapabilityRouter([_FakeCap("llm:a", "llm"), _FakeCap("recon:b", "recon")])
        eng = _llm_engagement()
        kb = KnowledgeBase.from_profile(eng.profile, "simulation")
        cands = r.candidates(eng)
        self.assertEqual([c.id for c in cands], ["llm:a"])
        chosen, dec = r.route(eng, kb)
        self.assertEqual(chosen.id, "llm:a")
        self.assertEqual(dec.ordering_source, "deterministic")

    def test_no_capability_applies_raises(self):
        r = CapabilityRouter([_FakeCap("recon:b", "recon")])
        eng = _llm_engagement()
        kb = KnowledgeBase.from_profile(eng.profile, "simulation")
        with self.assertRaises(ValueError):
            r.route(eng, kb)

    def test_prior_coverage_discriminates(self):
        # cap A can run the prior's technique; cap B cannot -> A ranks first.
        a = _FakeCap("llm:a", "llm", techniques=("direct_request",))
        b = _FakeCap("llm:b", "llm", techniques=("encoding_indirection",))
        r = CapabilityRouter([b, a])  # registration order puts b first
        eng = _llm_engagement()
        kb = KnowledgeBase.from_profile(eng.profile, "simulation", priors=[
            {"id": "c1", "category": "system_prompt", "technique": "direct_request", "surface": "chat"}])
        chosen, dec = r.route(eng, kb)
        self.assertEqual(chosen.id, "llm:a")
        self.assertIn("coverage", dec.rationale)

    def test_brain_reorders_within_closed_set(self):
        a = _FakeCap("llm:a", "llm"); b = _FakeCap("llm:b", "llm")
        r = CapabilityRouter([a, b])
        eng = _llm_engagement()
        kb = KnowledgeBase.from_profile(eng.profile, "simulation")
        chosen, dec = r.route(eng, kb, provider=_FakeProvider("llm:b"))
        self.assertEqual(chosen.id, "llm:b")
        self.assertEqual(dec.ordering_source, "brain")

    def test_brain_garbage_falls_back_deterministic(self):
        a = _FakeCap("llm:a", "llm"); b = _FakeCap("llm:b", "llm")
        r = CapabilityRouter([a, b])
        eng = _llm_engagement()
        kb = KnowledgeBase.from_profile(eng.profile, "simulation")
        chosen, dec = r.route(eng, kb, provider=_FakeProvider("i refuse to help"))
        self.assertEqual(chosen.id, "llm:a")
        self.assertEqual(dec.ordering_source, "deterministic")


class TestHypothesis(unittest.TestCase):
    def _obj(self):
        return Objective(name="Extract system prompt", category=AssetCategory.SYSTEM_PROMPT,
                         goal="get the system prompt",
                         techniques=[AttackTechnique.AUTHORITY_IMPERSONATION])

    def test_prior_beats_onboarding_order(self):
        kb = KnowledgeBase.from_profile(_profile(), "simulation", priors=[
            {"id": "c1", "category": "system_prompt", "technique": "direct_request", "surface": "chat"}])
        h = HypothesisPlanner().form(self._obj(), "llm:prompt_injection", kb)
        self.assertEqual(h.expected_technique, "direct_request")  # prior, not authority_impersonation
        self.assertIn("prior", h.basis)

    def test_update_supported_vs_refuted(self):
        kb = KnowledgeBase.from_profile(_profile(), "simulation")
        hp = HypothesisPlanner()
        h = hp.form(self._obj(), "llm:prompt_injection", kb)  # expects authority_impersonation
        supported = hp.update(hp.form(self._obj(), "x", kb), {
            "outcome": "breached", "turns": [
                {"index": 0, "technique": "authority_impersonation", "signals": [1]}]})
        self.assertEqual(supported.status, "supported")
        refuted = hp.update(hp.form(self._obj(), "x", kb), {
            "outcome": "breached", "turns": [
                {"index": 1, "technique": "roleplay_frame", "signals": [1]}]})
        self.assertEqual(refuted.status, "refuted")
        resisted = hp.update(hp.form(self._obj(), "x", kb), {"outcome": "resisted", "turns": []})
        self.assertEqual(resisted.status, "refuted")


class TestControlPlaneEndToEnd(unittest.TestCase):
    def test_naive_breaks_hardened_clean_manifest_written(self):
        with tempfile.TemporaryDirectory() as d:
            naive = ControlPlane(Path(d)).run(_llm_engagement("naive"))
            hardened = ControlPlane(Path(d)).run(_llm_engagement("hardened"))

            self.assertEqual(naive["capability"], "llm:prompt_injection")
            self.assertGreater(len(naive["capability_summary"]["findings"]), 0)
            self.assertIsNotNone(naive["capability_summary"].get("weakest_link"))
            self.assertEqual(len(hardened["capability_summary"]["findings"]), 0)

            # manifest exists, is valid JSON, pins the knowledge hash + scoreboard
            mani = json.loads(Path(naive["manifest"]).read_text())
            self.assertEqual(mani["schema"], "red_ai.control_plane.v1")
            self.assertEqual(mani["knowledge_snapshot"]["knowledge_hash"], naive["knowledge_hash"])
            self.assertEqual(mani["hypothesis_scoreboard"]["formed"],
                             len(naive["hypotheses"]))
            # the evidence chain the manifest points at verifies
            from red_ai.control.evidence import read_verified
            ev = read_verified(Path(naive["run_dir"]) / "events.jsonl")
            self.assertEqual(ev[0]["kind"], "run_started")

    def test_recon_engagement_routes_to_recon_capability(self):
        # Routing only (no socket): a recon engagement must select the recon capability.
        class _DummyRecon:
            environment = "owned"; hosts = ("127.0.0.1",)
        eng = Engagement(kind="recon", recon_scope=_DummyRecon())
        cp = ControlPlane(tempfile.mkdtemp())
        chosen, dec = cp.router.route(eng, KnowledgeBase(target="h", environment="owned"))
        self.assertEqual(chosen.id, "recon:tcp_connect")


class TestScoreboardCountsOpen(unittest.TestCase):
    def test_open_not_counted_as_refuted(self):
        # A hypothesis never updated (objective not executed, e.g. budget halt)
        # stays 'open' and must not be reported as refuted.
        from collections import Counter
        from red_ai.engine.hypothesis import HypothesisPlanner
        kb = KnowledgeBase.from_profile(_profile(), "simulation")
        hp = HypothesisPlanner()
        obj = Objective(name="x", category=AssetCategory.SYSTEM_PROMPT, goal="g",
                        techniques=[AttackTechnique.DIRECT_REQUEST])
        h_open = hp.form(obj, "cap", kb)                 # never updated -> open
        h_sup = hp.update(hp.form(obj, "cap", kb), {
            "outcome": "breached",
            "turns": [{"index": 0, "technique": "direct_request", "signals": [1]}]})
        tally = Counter(h.status for h in [h_open, h_sup])
        self.assertEqual(tally.get("open", 0), 1)
        self.assertEqual(tally.get("supported", 0), 1)
        self.assertEqual(tally.get("refuted", 0), 0)


if __name__ == "__main__":
    unittest.main()
