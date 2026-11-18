"""
Proposal: a single action the intelligent layer proposes to the control layer.

This is the hand-off point between the two layers. A planner/skill emits a
Proposal; the deterministic gate (``red_ai.control.gate``) validates it against
the signed scope BEFORE anything is sent to a target. The model never executes
its own proposals and never edits the scope that judges them.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from red_ai.contracts.domain import AttackTechnique
from red_ai.contracts.scope import canonical
from red_ai.contracts.action import ACTION_TIER_VALUES as _ACTION_TIER_VALUES

_TECHNIQUES = {t.value for t in AttackTechnique}


@dataclass(frozen=True)
class Proposal:
    """One proposed attacker move. Immutable; structurally validated on build."""
    skill: str
    objective_id: str
    technique: str
    message: str
    rationale: str = ""
    surface: str = "chat"
    tool: str | None = None
    action_tier: str = "active_safe"   # reversibility tier; gate consults tier_authority

    def __post_init__(self) -> None:
        if not self.skill or not isinstance(self.skill, str):
            raise ValueError("Proposal.skill is required")
        if not self.objective_id:
            raise ValueError("Proposal.objective_id is required")
        if self.technique not in _TECHNIQUES:
            raise ValueError(f"Unknown technique: {self.technique!r}")
        if not isinstance(self.message, str) or not (1 <= len(self.message) <= 8000):
            raise ValueError("Proposal.message must be 1..8000 chars")
        if not isinstance(self.rationale, str) or len(self.rationale) > 2000:
            raise ValueError("Proposal.rationale too long")
        if self.action_tier not in _ACTION_TIER_VALUES:
            raise ValueError(f"Unknown action_tier: {self.action_tier!r}")

    @property
    def fingerprint(self) -> str:
        """Stable hash for exact-duplicate rejection."""
        return hashlib.sha256(
            canonical([self.technique, self.surface, self.message]).encode()
        ).hexdigest()
