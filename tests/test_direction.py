"""
Invariants for the engagement-type / action-tier authority model and the
confirmed-vs-lead claim contract. Stdlib unittest only; fully offline.

These tests encode the direction settled in design discussion:
  * authority is driven by engagement INTENT (pentest vs monitoring), not by
    where the target lives;
  * PENTEST opens every reversibility tier; MONITORING human-gates the
    irreversible step (prove-and-stop);
  * unknown classifications fail CLOSED;
  * a Lead cannot be emitted without answering all four "why" questions, and
    can never carry a proven severity.
"""
import unittest
from datetime import timedelta

from red_ai.contracts.action import (
    ActionTier, Authority, tier_authority,
    ACTION_TIER_VALUES, ENGAGEMENT_VALUES,
)
from red_ai.contracts.domain import AssetCategory, Severity
from red_ai.contracts.proposal import Proposal
from red_ai.contracts.scope import Scope, now, sign_scope, verify_scope
from red_ai.contracts.verdict import Lead
from red_ai.control.gate import gate, HALTING

KEY = b"k" * 32


def a_scope(engagement_type="pentest", **kw):
    vf = now()
    vu = vf + timedelta(hours=1)
    base = dict(scope_id="s1", owner="o", authorised_by="a", target="t",
                valid_from=vf.isoformat(), valid_until=vu.isoformat(),
                engagement_type=engagement_type)
    base.update(kw)
    return Scope(**base)


def a_proposal(action_tier="active_safe"):
    return Proposal(skill="k", objective_id="obj_1", technique="direct_request",
                    message="hello", action_tier=action_tier)


class TierAuthorityTests(unittest.TestCase):
    def test_pentest_opens_every_tier(self):
        for tier in ActionTier:
            self.assertIs(tier_authority("pentest", tier.value), Authority.ALLOW)

    def test_monitoring_allows_observe_and_prove(self):
        self.assertIs(tier_authority("monitoring", "passive"), Authority.ALLOW)
        self.assertIs(tier_authority("monitoring", "active_safe"), Authority.ALLOW)

    def test_monitoring_human_gates_destructive(self):
        self.assertIs(tier_authority("monitoring", "destructive"), Authority.HUMAN_GATE)

    def test_unknown_values_fail_closed(self):
        self.assertIs(tier_authority("bogus", "destructive"), Authority.HUMAN_GATE)
        self.assertIs(tier_authority("pentest", "bogus"), Authority.HUMAN_GATE)

    def test_value_rosters(self):
        self.assertEqual(set(ENGAGEMENT_VALUES), {"pentest", "monitoring"})
        self.assertEqual(set(ACTION_TIER_VALUES), {"passive", "active_safe", "destructive"})


class GateAuthorityTests(unittest.TestCase):
    def test_pentest_allows_destructive(self):
        self.assertIsNone(gate(a_scope("pentest"), a_proposal("destructive"), 0, 0, 0.0))

    def test_monitoring_allows_active_safe(self):
        self.assertIsNone(gate(a_scope("monitoring"), a_proposal("active_safe"), 0, 0, 0.0))

    def test_monitoring_denies_destructive(self):
        reason = gate(a_scope("monitoring"), a_proposal("destructive"), 0, 0, 0.0)
        self.assertEqual(reason, "action_requires_human_authorization")

    def test_human_gate_is_a_denial_not_a_halt(self):
        # prove-and-stop records the item and continues; it must not stop the run.
        self.assertNotIn("action_requires_human_authorization", HALTING)

    def test_budget_halt_still_precedes_tier_check(self):
        # An expired/over-budget scope halts regardless of tier.
        reason = gate(a_scope("pentest"), a_proposal("destructive"),
                      queries=10_000, cost=0, elapsed=0.0)
        self.assertEqual(reason, "query_budget_exhausted")


class ScopeFieldTests(unittest.TestCase):
    def test_default_engagement_type_is_pentest(self):
        self.assertEqual(a_scope().engagement_type, "pentest")

    def test_invalid_engagement_type_rejected(self):
        with self.assertRaises(ValueError):
            a_scope(engagement_type="aggressive")

    def test_signing_roundtrips_with_engagement_type(self):
        env = sign_scope(a_scope("monitoring"), KEY)
        restored = verify_scope(env, KEY)
        self.assertEqual(restored.engagement_type, "monitoring")

    def test_proposal_default_tier_and_validation(self):
        self.assertEqual(a_proposal().action_tier, "active_safe")
        with self.assertRaises(ValueError):
            Proposal(skill="k", objective_id="obj_1", technique="direct_request",
                     message="hi", action_tier="nuclear")


class LeadContractTests(unittest.TestCase):
    def _lead(self, **override):
        base = dict(
            title="Unusual error surface on /login",
            category=AssetCategory.CREDENTIALS,
            anomaly="Malformed input returned a full stack trace with a SQL fragment.",
            hypothesis="Possible unparameterized query reachable via the login form.",
            benign_explanation="Could also be a verbose dev error page with no injection reachable.",
            implication_if_true="If real, an attacker may read or alter the credentials store.",
            how_to_confirm="Fuzz the username parameter with boolean/time payloads and compare timing.",
        )
        base.update(override)
        return Lead(**base)

    def test_full_lead_constructs(self):
        lead = self._lead()
        self.assertTrue(lead.requires_human_review)
        self.assertFalse(lead.is_proven)
        self.assertEqual(lead.as_dict()["unproven"], True)

    def test_lead_has_no_proven_severity(self):
        lead = self._lead()
        self.assertFalse(hasattr(lead, "severity"))
        self.assertIsInstance(lead.conditional_severity, Severity)

    def test_missing_any_why_is_refused(self):
        for field_name in ("anomaly", "hypothesis", "benign_explanation",
                           "implication_if_true", "how_to_confirm"):
            with self.assertRaises(ValueError, msg=f"empty {field_name} must raise"):
                self._lead(**{field_name: "   "})

    def test_as_dict_exposes_the_four_whys(self):
        d = self._lead().as_dict()
        for key in ("why_suspicious", "hypothesis", "benign_explanation",
                    "implication_if_true", "how_to_confirm"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
