"""
Onboarding: build a TargetProfile from minimal customer input.

Purpose
-------
The customer answers two substantive questions - who they are and what the bot
is for - and RedAI derives the rest. Everything inferred is returned alongside
the reason it was inferred, so the onboarding UI can present it for confirmation
rather than hiding it.

Data flow
---------
    industry + purpose
        -> taxonomy.match_rules()      (keyword -> asset category)
        -> SensitiveAsset[] (inferred=True, confirmed=False)
        + UNIVERSAL_ASSETS             (always present)
        + UNIVERSAL_PROHIBITIONS       (always present)
        -> TargetProfile
        -> InferenceReport             (what/why, for customer confirmation)

Security considerations
-----------------------
An *unconfirmed* inferred asset is a blind-spot candidate: RedAI will attack it,
but the customer has not verified that it reflects reality. ``InferenceReport``
exists specifically so unconfirmed assets are visible rather than silently
assumed. ``TargetProfile.unconfirmed_assets`` should be surfaced prominently in
the UI and, later, blocked from producing a "clean" report.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from red_ai.contracts.domain import (
    AssetCategory,
    Canary,
    Prohibition,
    SensitiveAsset,
    Severity,
    TargetProfile,
)
from red_ai.onboarding.taxonomy import (
    UNIVERSAL_ASSETS,
    UNIVERSAL_PROHIBITIONS,
    match_rules,
)


@dataclass(frozen=True)
class InferredAssetExplanation:
    """Why a particular asset ended up in the profile."""

    category: AssetCategory
    label: str
    impact: Severity
    reason: str


@dataclass(frozen=True)
class InferenceReport:
    """
    Human-readable account of what onboarding derived and why.

    Rendered in the onboarding UI as a confirmation step. The customer ticks
    what is real, removes what is not, and adds what we missed.
    """

    explanations: tuple[InferredAssetExplanation, ...]
    unmatched_warning: str | None = None

    def to_lines(self) -> list[str]:
        lines = [f"- [{e.impact.value.upper():8}] {e.label}  ({e.reason})" for e in self.explanations]
        if self.unmatched_warning:
            lines.append(f"! {self.unmatched_warning}")
        return lines


# Tasks that are outside the remit of essentially every deployed business bot.
# Used both to seed scope-deviation detection and to give the planner concrete
# off-purpose asks. Kept here rather than in the detector so a customer can
# override them per-target later.
DEFAULT_OUT_OF_SCOPE_TASKS: tuple[str, ...] = (
    "write software or debug code",
    "write poetry, songs or fiction",
    "solve mathematics or homework problems",
    "translate arbitrary documents",
    "give medical, legal or investment advice",
    "act as a general-purpose assistant",
)


def build_profile(
    *,
    name: str,
    industry: str,
    bot_purpose: str,
    in_scope_tasks: Iterable[str] | None = None,
    extra_context: str = "",
    authorised_by: str | None = None,
    environment: str = "staging",
    planted_canaries: Iterable[Canary] | None = None,
) -> tuple[TargetProfile, InferenceReport]:
    """
    Derive a full target profile from minimal onboarding input.

    Args:
        name: Display name for the target.
        industry: Free-text industry, e.g. "call center", "auto dealership".
        bot_purpose: What the bot is deployed to do, in the customer's words.
        in_scope_tasks: Tasks legitimately within remit. Anything materially
            outside these is treated as scope deviation.
        extra_context: Optional extra description to widen keyword matching.
        authorised_by: Person authorising the test. Required before a scan runs.
        environment: "staging" or "production".
        planted_canaries: Canaries the customer has planted. Each is attached to
            the asset matching its category, upgrading that asset from tier-3
            semantic detection to tier-1 exact matching.

    Returns:
        The profile and an inference report explaining every inferred asset.
    """
    canaries = list(planted_canaries or [])
    assets: list[SensitiveAsset] = []
    explanations: list[InferredAssetExplanation] = []

    # 1. Universal assets. Always present, never inferred, never need confirming
    #    - a bot leaking its own system prompt is a failure for any deployment.
    for category, label, impact in UNIVERSAL_ASSETS:
        assets.append(
            SensitiveAsset(
                category=category,
                label=label,
                impact=impact,
                inferred=False,
                confirmed_by_customer=True,
                canaries=[c for c in canaries if c.category is category],
            )
        )
        explanations.append(
            InferredAssetExplanation(
                category=category,
                label=label,
                impact=impact,
                reason="universal - applies to every deployed assistant",
            )
        )

    # 2. Contextual assets inferred from the industry/purpose text.
    matched = match_rules(industry, bot_purpose, extra_context)
    seen: set[AssetCategory] = set()
    for rule, keyword in matched:
        if rule.category in seen:
            continue
        seen.add(rule.category)
        assets.append(
            SensitiveAsset(
                category=rule.category,
                label=rule.label,
                impact=rule.impact,
                inferred=True,
                confirmed_by_customer=False,
                canaries=[c for c in canaries if c.category is rule.category],
                example_values=list(rule.example_values),
            )
        )
        explanations.append(
            InferredAssetExplanation(
                category=rule.category,
                label=rule.label,
                impact=rule.impact,
                reason=f"inferred from the word {keyword!r}",
            )
        )

    warning = None
    if not matched:
        warning = (
            "No industry-specific assets were inferred from the description. "
            "Only universal checks will run, which materially reduces coverage. "
            "Add detail to the purpose, or declare assets explicitly."
        )

    prohibitions = [
        Prohibition(
            rule=p["rule"],
            description=p["description"],
            severity=p["severity"],
        )
        for p in UNIVERSAL_PROHIBITIONS
    ]

    profile = TargetProfile(
        name=name,
        industry=industry,
        bot_purpose=bot_purpose,
        in_scope_tasks=list(in_scope_tasks or []),
        sensitive_assets=assets,
        prohibitions=prohibitions,
        authorised_by=authorised_by,
        environment=environment,  # type: ignore[arg-type]
    )
    return profile, InferenceReport(
        explanations=tuple(explanations), unmatched_warning=warning
    )


def confirm_assets(profile: TargetProfile, categories: Iterable[AssetCategory]) -> TargetProfile:
    """
    Mark the given inferred asset categories as customer-confirmed.

    Returns a new profile; profiles are treated as immutable once a scan has
    started so that a stored scan always references the exact profile it ran
    against.
    """
    wanted = set(categories)
    updated = [
        a.model_copy(update={"confirmed_by_customer": True}) if a.category in wanted else a
        for a in profile.sensitive_assets
    ]
    return profile.model_copy(update={"sensitive_assets": updated})
