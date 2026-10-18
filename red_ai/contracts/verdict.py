"""
The claim contract: nothing leaves RED-AI without a "why".

RED-AI emits exactly two shapes, and the difference is only what *kind* of why
each owes:

  * A CONFIRMED finding (``red_ai.contracts.domain.Finding``) was PROVEN by
    exploitation. Its why IS the evidence -- the reproduced exchange and the
    derived severity with stated inputs. Proof is self-justifying; nobody argues
    with a reproduced breach.

  * A LEAD (this module) was NOT proven. It has no evidence to carry it, so it
    must earn its weight entirely by argument. A lead that cannot answer all
    four questions below is not emitted at all -- enforced in ``__post_init__``,
    not left to discipline. The thing RED-AI could not prove is held to the
    HIGHER narrative bar, precisely because the evidence is not there.

The four questions a lead must answer:
  1. anomaly             -- WHY it looks suspicious (a concrete, observed fact).
  2. hypothesis          -- what weakness it MIGHT be (explicitly unproven).
  3. benign_explanation  -- why it might be NOTHING (the competing reading). This
                            is what separates a useful lead from fear-mongering
                            and keeps false-positive discipline alive.
  4. implication_if_true + how_to_confirm -- what is at stake IF true, and the
                            actionable next step to prove or kill it.

A lead never carries a proven severity. It has no ``severity`` field at all --
only ``conditional_severity`` (the severity IF the hypothesis is confirmed) --
so an unproven claim can never masquerade as a graded one. "No black-box
scoring" survives by construction.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from red_ai.contracts.domain import AssetCategory, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _require(text: str, field_name: str, minimum: int = 12) -> None:
    if not isinstance(text, str) or len(text.strip()) < minimum:
        raise ValueError(
            f"Lead.{field_name} must be a substantive statement (>= {minimum} "
            f"chars): a suspicion with no {field_name} does not get emitted"
        )


@dataclass
class Lead:
    """An unproven, human-routed suspicion that has earned its weight.

    Structurally incapable of asserting a proven vulnerability: there is no
    ``severity`` field, only ``conditional_severity``, and it is always routed
    to a human (``requires_human_review`` is always True, ``is_proven`` always
    False).
    """
    title: str
    category: AssetCategory
    anomaly: str                 # (1) why suspicious -- observed fact
    hypothesis: str              # (2) what it might be -- unproven
    benign_explanation: str      # (3) why it might be nothing -- counter-reading
    implication_if_true: str     # (4a) what is at stake if confirmed
    how_to_confirm: str          # (4b) actionable next step to prove/kill it
    conditional_severity: Severity = Severity.MEDIUM   # IF confirmed; never proven
    evidence: tuple[str, ...] = ()        # literal spans that triggered the anomaly
    confidence: float = 0.3               # suspicion strength; deliberately low default
    surface: str = "chat"
    id: str = field(default_factory=lambda: _new_id("led"))
    created_at: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValueError("Lead.title is required")
        if not isinstance(self.category, AssetCategory):
            raise ValueError("Lead.category must be an AssetCategory")
        if not isinstance(self.conditional_severity, Severity):
            raise ValueError("Lead.conditional_severity must be a Severity")
        _require(self.anomaly, "anomaly")
        _require(self.hypothesis, "hypothesis")
        _require(self.benign_explanation, "benign_explanation")
        _require(self.implication_if_true, "implication_if_true")
        _require(self.how_to_confirm, "how_to_confirm")
        if not isinstance(self.evidence, tuple):
            raise ValueError("Lead.evidence must be a tuple")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")

    @property
    def requires_human_review(self) -> bool:
        # A lead is unproven by definition; it NEVER auto-confirms.
        return True

    @property
    def is_proven(self) -> bool:
        return False

    def as_dict(self) -> dict:
        """Report-ready view. ``unproven`` is always True; the key names mirror
        the four questions so a reader sees the reasoning, not a bare score."""
        return {
            "id": self.id,
            "kind": "lead",
            "title": self.title,
            "category": self.category.value,
            "why_suspicious": self.anomaly,
            "hypothesis": self.hypothesis,
            "benign_explanation": self.benign_explanation,
            "implication_if_true": self.implication_if_true,
            "how_to_confirm": self.how_to_confirm,
            "conditional_severity": self.conditional_severity.value,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "surface": self.surface,
            "unproven": True,
        }
