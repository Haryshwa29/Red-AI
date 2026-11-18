"""
Capability Router: choose which capability handles an engagement, explainably.

Realizes the "Capability Router" node. It picks from a CLOSED set of registered
capabilities that apply to the engagement, ordered by knowledge priors. The
model (if present) may only REORDER that closed set; it can never add a
capability, and it never authorizes execution -- the per-action gate inside the
chosen capability's controller remains the sole authority.

No black-box routing: every decision carries the candidate set, the chosen id,
the ordering source, and a plain-English rationale, and is written into the run
manifest.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from red_ai.engine.capability import Capability, Engagement


@dataclass
class RoutingDecision:
    capability_id: str
    rationale: str
    candidates: list[str] = field(default_factory=list)
    ordering_source: str = "deterministic"   # deterministic | brain

    def as_dict(self) -> dict:
        return {"capability_id": self.capability_id, "rationale": self.rationale,
                "candidates": list(self.candidates), "ordering_source": self.ordering_source}


class CapabilityRouter:
    def __init__(self, capabilities: list[Capability]) -> None:
        if not capabilities:
            raise ValueError("router needs at least one capability")
        self._caps = list(capabilities)

    def candidates(self, engagement: Engagement) -> list[Capability]:
        """The closed candidate set: registered capabilities that apply."""
        return [c for c in self._caps if c.applies_to(engagement)]

    def route(self, engagement: Engagement, knowledge, provider=None) -> tuple[Capability, RoutingDecision]:
        candidates = self.candidates(engagement)
        if not candidates:
            raise ValueError(
                f"no registered capability applies to a {engagement.kind!r} engagement")

        ranked = self._rank_by_priors(candidates, knowledge)
        ordering_source = "deterministic"
        rationale = self._deterministic_rationale(engagement, ranked, knowledge)

        if provider is not None and len(ranked) > 1:
            reordered = self._brain_reorder(ranked, engagement, knowledge, provider)
            if reordered is not None:
                ranked = reordered
                ordering_source = "brain"
                rationale = (f"model reordered a closed candidate set of "
                             f"{[c.id for c in candidates]}; chose {ranked[0].id}. "
                             "Gate still authorizes every action.")

        chosen = ranked[0]
        return chosen, RoutingDecision(
            capability_id=chosen.id, rationale=rationale,
            candidates=[c.id for c in candidates], ordering_source=ordering_source)

    # -- deterministic ordering ---------------------------------------------

    def _coverage_score(self, cap: Capability, knowledge) -> int:
        """How many reviewed-prior techniques this capability can actually run.
        A capability a prior says broke this target ranks ahead of one that
        can't express those techniques at all."""
        covered = set(cap.covers_techniques())
        score = 0
        for p in knowledge.priors():
            if p.technique in covered:
                score += 1
        return score

    def _rank_by_priors(self, candidates: list[Capability], knowledge) -> list[Capability]:
        indexed = list(enumerate(candidates))
        indexed.sort(key=lambda it: (-self._coverage_score(it[1], knowledge), it[0]))
        return [c for _, c in indexed]

    def _deterministic_rationale(self, engagement, ranked, knowledge) -> str:
        if len(ranked) == 1:
            return (f"only registered capability applying to a {engagement.kind!r} "
                    f"engagement: {ranked[0].id}")
        top = ranked[0]
        score = self._coverage_score(top, knowledge)
        if score:
            return (f"chose {top.id}: highest reviewed-prior technique coverage "
                    f"({score}) among {[c.id for c in ranked]}")
        return (f"chose {top.id}: no priors to discriminate; registration order "
                f"over {[c.id for c in ranked]}")

    # -- optional brain influence (ordering only) ---------------------------

    def _brain_reorder(self, ranked, engagement, knowledge, provider):
        """Let the model pick the first capability from the CLOSED set by id.
        Any error / unparseable / out-of-set answer -> keep deterministic order.
        The model sees only capability ids and asset categories, never target
        text (which is quarantined)."""
        try:
            from red_ai.contracts.domain import Message
            ids = [c.id for c in ranked]
            cats = sorted({a.category for a in knowledge.assets()})
            prompt = (
                "Choose which security-test capability to run first. Reply with "
                "exactly one id from this list and nothing else.\n"
                f"capabilities: {ids}\n"
                f"target asset categories: {cats}\n"
                f"environment: {engagement.environment}")
            reply = provider.generate([Message(role="user", content=prompt)],
                                      num_predict=16).strip()
            pick = None
            for cid in ids:
                if cid in reply:
                    pick = cid
                    break
            if pick is None:
                return None
            chosen = next(c for c in ranked if c.id == pick)
            return [chosen] + [c for c in ranked if c.id != pick]
        except Exception:
            return None
