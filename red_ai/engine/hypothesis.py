"""
Plan / Hypothesis: make the engine's reasoning explicit and checkable.

Realizes the "PLAN / HYPOTHESIS" node. Turn-level move selection stays in the
existing planner; this layer records, per objective, the *hypothesis* the engine
is testing -- which asset, via which capability, with which technique it expects
to give first, and on what basis -- then marks it supported or refuted from the
result. That makes every run answer "what did we think would break, and were we
right", which is what feeds honest reporting and (reviewed) learning.

A hypothesis is a belief, not an authorization: it only orders effort. It is
built solely from established knowledge (priors + declared assets), never from
quarantined target text.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from red_ai.contracts.domain import Objective


@dataclass
class Hypothesis:
    objective_id: str
    objective_name: str
    asset_category: str
    capability_id: str
    expected_technique: str
    basis: str
    status: str = "open"                       # open | supported | refuted
    observed_break_technique: Optional[str] = None
    turns_to_break: Optional[int] = None

    def as_dict(self) -> dict:
        return {
            "objective_id": self.objective_id, "objective": self.objective_name,
            "asset_category": self.asset_category, "capability_id": self.capability_id,
            "expected_technique": self.expected_technique, "basis": self.basis,
            "status": self.status,
            "observed_break_technique": self.observed_break_technique,
            "turns_to_break": self.turns_to_break,
        }


class HypothesisPlanner:
    def form(self, objective: Objective, capability_id: str, knowledge) -> Hypothesis:
        """Form the hypothesis for one objective from established knowledge."""
        cat = objective.category.value
        prior_techs = knowledge.prior_techniques_for(cat)
        if prior_techs:
            expected = prior_techs[0]
            basis = (f"reviewed prior: '{expected}' previously broke '{cat}' on a "
                     f"comparable target")
        elif objective.techniques:
            expected = objective.techniques[0].value
            basis = "no prior; onboarding technique order (cheapest/highest-signal first)"
        else:
            expected = "direct_request"
            basis = "no prior and no declared order; defaulting to direct_request"
        return Hypothesis(objective_id=objective.id, objective_name=objective.name,
                          asset_category=cat, capability_id=capability_id,
                          expected_technique=expected, basis=basis)

    def update(self, hypothesis: Hypothesis, attempt: dict) -> Hypothesis:
        """Mark the hypothesis from the objective's attempt result."""
        if attempt.get("outcome") != "breached":
            hypothesis.status = "refuted"
            return hypothesis
        broke_tech = None
        turns_to_break = None
        for turn in attempt.get("turns", []):
            if turn.get("signals"):
                broke_tech = turn.get("technique")
                turns_to_break = turn.get("index")
                break
        hypothesis.observed_break_technique = broke_tech
        hypothesis.turns_to_break = turns_to_break
        hypothesis.status = "supported" if broke_tech == hypothesis.expected_technique else "refuted"
        return hypothesis
