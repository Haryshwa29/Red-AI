"""
Detector registry and the three-tier detection ladder.

Purpose
-------
Assembles detectors into the ladder that decides what a human ever sees:

    Tier 1  exact canary / declared-literal match   -> auto-confirm, no human
    Tier 2  machine-checkable policy assertions     -> auto-confirm, no human
    Tier 3  semantic model judgement                -> handler review queue

Design rationale
----------------
Tier 3 only runs when tiers 1 and 2 are silent. Deterministic detectors are free
and certain; if one has already established that the target failed, spending a
judge-model call to reach the same conclusion adds cost, latency, and a
human-review obligation for no additional information.

The corollary is the property that makes the economics work: handler workload is
proportional to the number of *ambiguous* exchanges, not to the number of
attempts. A scan can run ten thousand turns and still produce a review queue a
person can clear in an afternoon.

Security considerations
-----------------------
A detector raising an exception must never abort a scan or, worse, cause a turn
to be silently recorded as clean. ``DetectorLadder.inspect`` isolates each
detector and records failures explicitly so that a broken detector degrades
coverage visibly rather than producing a false clean result.
"""

from __future__ import annotations

import logging
from typing import Iterable

from red_ai.contracts.interfaces import Detector
from red_ai.contracts.domain import (
    AssetCategory,
    DetectorTier,
    Signal,
    TargetProfile,
    TargetResponse,
)
from red_ai.detection.canary import CanaryDetector
from red_ai.detection.policy import (
    GuardrailDisclosureDetector,
    PIIEmissionDetector,
    ScopeDeviationDetector,
    SystemPromptLeakDetector,
)

logger = logging.getLogger(__name__)


# Rule identifier -> detector class. Prohibition.rule values must resolve here;
# the test suite asserts that every universal prohibition has a registered
# detector, so a rename cannot silently disable a check.
POLICY_DETECTORS: dict[str, type] = {
    SystemPromptLeakDetector.id: SystemPromptLeakDetector,
    GuardrailDisclosureDetector.id: GuardrailDisclosureDetector,
    PIIEmissionDetector.id: PIIEmissionDetector,
    ScopeDeviationDetector.id: ScopeDeviationDetector,
}


class DetectorLadder:
    """
    Runs detectors tier by tier and returns the signals for one exchange.

    Args:
        deterministic: Tier-1 detectors.
        policy: Tier-2 detectors.
        semantic: Optional tier-3 detector. Consulted only when the lower tiers
            are silent.
    """

    def __init__(
        self,
        deterministic: Iterable[Detector] | None = None,
        policy: Iterable[Detector] | None = None,
        semantic: Detector | None = None,
    ) -> None:
        self.deterministic: list[Detector] = list(deterministic or [CanaryDetector()])
        self.policy: list[Detector] = list(policy or [])
        self.semantic = semantic
        self.failures: list[str] = []

    @classmethod
    def from_profile(
        cls,
        profile: TargetProfile,
        semantic: Detector | None = None,
    ) -> "DetectorLadder":
        """
        Build a ladder containing exactly the detectors this profile requires.

        Tier-2 detectors are instantiated from the profile's prohibitions, so a
        target with no PII obligation does not pay for PII scanning and cannot
        be flagged for it.
        """
        policy: list[Detector] = []
        for prohibition in profile.prohibitions:
            detector_cls = POLICY_DETECTORS.get(prohibition.rule)
            if detector_cls is None:
                logger.warning(
                    "Prohibition %r references unregistered detector %r; "
                    "this check will NOT run.",
                    prohibition.id,
                    prohibition.rule,
                )
                continue
            policy.append(detector_cls())
        return cls(deterministic=[CanaryDetector()], policy=policy, semantic=semantic)

    def _run(
        self,
        detectors: Iterable[Detector],
        profile: TargetProfile,
        attacker_message: str,
        response: TargetResponse,
    ) -> list[Signal]:
        out: list[Signal] = []
        for detector in detectors:
            try:
                out.extend(detector.inspect(profile, attacker_message, response))
            except Exception:  # noqa: BLE001 - isolation is the point
                # A crashing detector must reduce coverage visibly, never
                # produce a silent clean verdict.
                logger.exception("Detector %r raised; coverage reduced.", detector.id)
                self.failures.append(detector.id)
        return out

    def inspect(
        self,
        profile: TargetProfile,
        attacker_message: str,
        response: TargetResponse,
    ) -> list[Signal]:
        """Return every signal for one attacker/target exchange."""
        signals = self._run(self.deterministic, profile, attacker_message, response)
        signals.extend(self._run(self.policy, profile, attacker_message, response))

        # Short-circuit: the expensive, human-costly tier only runs when the
        # cheap deterministic tiers found nothing.
        if not signals and self.semantic is not None:
            signals.extend(self._run([self.semantic], profile, attacker_message, response))

        return signals


class NullSemanticDetector:
    """
    Placeholder tier-3 detector.

    Phase 1 ships without a judge model on purpose. Every finding RedAI produces
    today is deterministic and auditable, which means no finding requires a
    customer to trust a model's opinion. The semantic tier is what will catch
    paraphrased leakage and subtle policy drift, and it is the right next
    component to build - but shipping it badly would undermine the one property
    the product is selling.

    Implements ``red_ai.contracts.interfaces.Detector``.
    """

    id = "semantic_null"
    tier = DetectorTier.SEMANTIC

    def inspect(
        self,
        profile: TargetProfile,
        attacker_message: str,
        response: TargetResponse,
    ) -> list[Signal]:
        return []

    @staticmethod
    def coverage_caveat() -> str:
        """Text the report must carry so a clean result is not overstated."""
        return (
            "Semantic detection is not enabled. Findings in this report are "
            "limited to deterministic canary matches and policy assertions. "
            "Paraphrased disclosure and subtle policy drift were NOT tested."
        )


__all__ = [
    "AssetCategory",
    "DetectorLadder",
    "NullSemanticDetector",
    "POLICY_DETECTORS",
]
