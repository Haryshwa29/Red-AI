"""
Knowledge System: the control plane's single, typed view of what it knows.

Realizes the "Knowledge System (assets / paths / risks / history)" node of the
control-plane diagram, and it is where the memory-poisoning defense lives.

The one rule that makes this safe
----------------------------------
A red-team tool reads a lot of attacker-controlled output. If that output can
flow back in as *planning input*, a malicious or compromised target can steer
the red-teamer (indirect prompt injection against us). So knowledge is split by
TRUST, by construction, into two stores that never mix:

  * ESTABLISHED facts  -- things WE established: the client's declared assets,
    reviewed risk priors from durable memory, and observations our own
    detectors/signal-analyzer derived (which asset leaked, which technique gave,
    how many turns it took). Only these reach the strategist and router.
  * QUARANTINED output -- raw target-emitted text. Kept for evidence and
    reconstruction, tagged untrusted, and NEVER returned in a form that feeds
    planning. There is deliberately no method that folds it into priors.

Everything the planner consumes is hashable into a ``snapshot`` pinned in the
run manifest, so a run names the exact knowledge it reasoned over -- adaptation
stays fully reproducible.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from red_ai.contracts.domain import TargetProfile
from red_ai.contracts.scope import canonical


@dataclass(frozen=True)
class Asset:
    """An established fact: a declared sensitive asset of the target."""
    category: str
    label: str
    impact: str


@dataclass(frozen=True)
class RiskPrior:
    """An established fact: a reviewed (category, technique, surface) prior drawn
    from durable memory. Ordering influence only -- never an authorization."""
    category: str
    technique: str
    surface: str
    case_id: str = ""


@dataclass(frozen=True)
class Observation:
    """An established fact WE derived this run from our own detectors/signals.

    Note: this records our analysis (which asset, which technique, breached?),
    NOT the target's words. Target words are quarantined separately."""
    objective_id: str
    category: str
    technique: str
    gave: bool
    breached: bool
    note: str = ""


@dataclass(frozen=True)
class _Quarantined:
    """Untrusted target-emitted text. Evidence only; never planning input."""
    objective_id: str
    index: int
    text: str
    source: str = "target"


class KnowledgeBase:
    """In-run knowledge for one engagement. Trusted facts are planning input;
    quarantined text is evidence only."""

    def __init__(self, *, target: str, environment: str) -> None:
        self.target = target
        self.environment = environment
        self._assets: list[Asset] = []
        self._priors: list[RiskPrior] = []
        self._observations: list[Observation] = []
        self._quarantine: list[_Quarantined] = []

    # -- construction --------------------------------------------------------

    @classmethod
    def from_profile(cls, profile: TargetProfile, environment: str,
                     priors: list[dict] | None = None) -> "KnowledgeBase":
        kb = cls(target=profile.name, environment=environment)
        for a in profile.sensitive_assets:
            kb._assets.append(Asset(category=a.category.value, label=a.label,
                                    impact=a.impact.value))
        for p in priors or []:
            kb._priors.append(RiskPrior(
                category=p.get("category", ""), technique=p.get("technique", ""),
                surface=p.get("surface", "chat"), case_id=p.get("id", "")))
        return kb

    # -- trusted (planning) --------------------------------------------------

    def assets(self) -> list[Asset]:
        return list(self._assets)

    def priors(self) -> list[RiskPrior]:
        return list(self._priors)

    def observations(self) -> list[Observation]:
        return list(self._observations)

    def priors_for_controller(self) -> list[dict]:
        """Reviewed priors in the exact shape ``Controller._apply_memory`` wants.

        This is how knowledge drives capability ordering/routing -- reusing the
        existing, tested memory path. Priors only: the gate still authorizes
        every action and this never adds a scope-forbidden technique."""
        out: list[dict] = []
        for p in self._priors:
            out.append({"id": p.case_id or f"{p.category}:{p.technique}",
                        "category": p.category, "technique": p.technique,
                        "surface": p.surface, "trust": "reviewed_metadata"})
        return out

    def prior_techniques_for(self, category: str) -> list[str]:
        """Techniques a reviewed prior associates with this asset category."""
        seen: list[str] = []
        for p in self._priors:
            if p.category == category and p.technique and p.technique != "unknown" \
                    and p.technique not in seen:
                seen.append(p.technique)
        return seen

    # -- ingest a completed capability run -----------------------------------

    def record_run(self, summary: dict) -> None:
        """Fold a capability's result into knowledge: our derived observations
        become established facts; any raw target text is quarantined."""
        for att in summary.get("attempts", []):
            breached = att.get("outcome") == "breached"
            for turn in att.get("turns", []):
                has_signal = bool(turn.get("signals"))
                self._observations.append(Observation(
                    objective_id=att.get("objective_id", ""),
                    category=_category_of(summary, att.get("objective_id", "")),
                    technique=turn.get("technique", "unknown"),
                    gave=has_signal, breached=has_signal,
                    note="detector fired" if has_signal else "no signal"))
                resp = turn.get("response") or {}
                text = resp.get("content") if isinstance(resp, dict) else None
                if text:
                    self._quarantine.append(_Quarantined(
                        objective_id=att.get("objective_id", ""),
                        index=turn.get("index", 0), text=text))
            _ = breached

    # -- quarantined (evidence only) -----------------------------------------

    def evidence_count(self) -> int:
        return len(self._quarantine)

    def evidence(self) -> list[dict]:
        """Untrusted target text, each item loudly tagged. For evidence display
        only; deliberately NOT consumable as priors or a prompt."""
        return [{"objective_id": q.objective_id, "index": q.index,
                 "trust": "untrusted_target_data", "text": q.text}
                for q in self._quarantine]

    # -- reproducibility -----------------------------------------------------

    def snapshot(self) -> dict:
        """Canonical view of the TRUSTED knowledge used for planning, plus a
        hash. Quarantined text is excluded -- it is evidence, not a planning
        input, and must not change the planning identity of a run."""
        body = {
            "target": self.target, "environment": self.environment,
            "assets": [{"category": a.category, "label": a.label, "impact": a.impact}
                       for a in self._assets],
            "priors": [{"category": p.category, "technique": p.technique,
                        "surface": p.surface} for p in self._priors],
            "observations": [{"objective_id": o.objective_id, "category": o.category,
                              "technique": o.technique, "breached": o.breached}
                             for o in self._observations],
        }
        digest = hashlib.sha256(canonical(body).encode()).hexdigest()
        return {"knowledge_hash": digest, "evidence_items_quarantined": len(self._quarantine),
                **body}


def _category_of(summary: dict, objective_id: str) -> str:
    for o in summary.get("coverage", {}).get("objectives", []) or []:
        if o.get("id") == objective_id:
            return o.get("category", "")
    # objectives also recorded on the run_started event; summary may not carry
    # them -- fall back to empty, observation still records technique+outcome.
    return ""
