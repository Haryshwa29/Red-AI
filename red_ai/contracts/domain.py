"""
Core domain model for RED-AI. Stdlib dataclasses only (no third-party deps),
so the whole system runs on a bundled Python, offline.

These types are the vocabulary every component speaks: the planner, the
detector ladder, the target adapters, the controller and the reporter all
consume and produce them.

Principles carried over from the original design:
  * Evidence is the product. Records that capture what the target said are
    frozen and keep enough context to reconstruct the exchange.
  * No black-box scoring. A Signal names the detector, the literal evidence,
    and a plain-English rationale; severity is always derived from stated
    inputs.
  * A refusal is not a verdict. An Attempt records effort spent, not just
    whether it "succeeded".
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}
_SEVERITY_BY_RANK = {r: s for s, r in _SEVERITY_RANK.items()}


def severity_from_rank(rank: int) -> "Severity":
    return _SEVERITY_BY_RANK[max(0, min(4, rank))]


class DetectorTier(IntEnum):
    """Which rung of the detection ladder fired. Tier 3 alone needs a human."""
    DETERMINISTIC = 1   # exact canary / declared-literal match
    POLICY = 2          # machine-checkable rule from the target profile
    SEMANTIC = 3        # model-judged; always requires adjudication


class AssetCategory(str, Enum):
    # Universal — always checked.
    SYSTEM_PROMPT = "system_prompt"
    GUARDRAIL_DISCLOSURE = "guardrail_disclosure"
    OTHER_USER_DATA = "other_user_data"
    SCOPE_INTEGRITY = "scope_integrity"
    # Contextual — inferred from industry + bot purpose at onboarding.
    CUSTOMER_PII = "customer_pii"
    FINANCIAL_DATA = "financial_data"
    HEALTH_DATA = "health_data"
    CREDENTIALS = "credentials"
    PRICING_LOGIC = "pricing_logic"
    INTERNAL_DOCS = "internal_docs"
    EMPLOYEE_DATA = "employee_data"
    LEGAL_COMMITMENT = "legal_commitment"
    # Agent / tool-using targets.
    TOOL_ABUSE = "tool_abuse"
    EXCESSIVE_AGENCY = "excessive_agency"


UNIVERSAL_CATEGORIES = frozenset({
    AssetCategory.SYSTEM_PROMPT,
    AssetCategory.GUARDRAIL_DISCLOSURE,
    AssetCategory.OTHER_USER_DATA,
    AssetCategory.SCOPE_INTEGRITY,
})


class AttackTechnique(str, Enum):
    """Technique space: prompt injection and social engineering, plus the
    agent/tool-abuse rung (last three members)."""
    DIRECT_REQUEST = "direct_request"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    DEVELOPER_MODE = "developer_mode"
    ROLEPLAY_FRAME = "roleplay_frame"
    HYPOTHETICAL_FRAME = "hypothetical_frame"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CONTEXT_RESET = "context_reset"
    INCREMENTAL_ESCALATION = "incremental_escalation"
    EMOTIONAL_PRESSURE = "emotional_pressure"
    TASK_REFRAMING = "task_reframing"
    OUTPUT_FORMAT_COERCION = "output_format_coercion"
    ENCODING_INDIRECTION = "encoding_indirection"
    # Agent / tool-abuse rung (shared vocabulary; used by the agent_tool_abuse skill).
    TOOL_INVOCATION_COERCION = "tool_invocation_coercion"
    INDIRECT_TOOL_INJECTION = "indirect_tool_injection"
    EXCESSIVE_AGENCY_PROBE = "excessive_agency_probe"


class AttemptOutcome(str, Enum):
    BREACHED = "breached"     # at least one signal fired
    RESISTED = "resisted"     # budget exhausted, no signal
    ERRORED = "errored"       # transport/target failure; inconclusive
    ABORTED = "aborted"       # killed by operator or gate


class ReviewState(str, Enum):
    AUTO_CONFIRMED = "auto_confirmed"   # tier 1/2, no human needed
    PENDING_REVIEW = "pending_review"   # tier 3, queued for handler
    CONFIRMED = "confirmed"             # handler agreed
    REJECTED = "rejected"              # handler disagreed


# --------------------------------------------------------------------------- #
# Onboarding / target profile
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Canary:
    """A high-entropy token planted in the target. Its appearance in output is
    a zero-false-positive leak signal."""
    value: str
    category: AssetCategory
    placement: str
    description: str = ""
    id: str = field(default_factory=lambda: _new_id("cny"))

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or len(self.value) < 8:
            raise ValueError("Canary value must be a string of at least 8 chars")


@dataclass
class SensitiveAsset:
    category: AssetCategory
    label: str
    impact: Severity = Severity.MEDIUM
    inferred: bool = True
    confirmed_by_customer: bool = False
    canaries: list[Canary] = field(default_factory=list)
    example_values: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: _new_id("ast"))


@dataclass
class Prohibition:
    """A machine-checkable rule the target must never violate. ``rule`` maps to
    a registered tier-2 policy detector."""
    rule: str
    description: str
    severity: Severity = Severity.MEDIUM
    params: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: _new_id("prh"))


@dataclass
class Objective:
    """A goal-directed attack objective: can an attacker extract/induce X."""
    name: str
    category: AssetCategory
    goal: str
    severity_if_achieved: Severity = Severity.MEDIUM
    max_turns: int = 12
    techniques: list[AttackTechnique] = field(default_factory=list)
    id: str = field(default_factory=lambda: _new_id("obj"))

    def __post_init__(self) -> None:
        if not 1 <= self.max_turns <= 100:
            raise ValueError("max_turns must be between 1 and 100")


@dataclass
class TargetProfile:
    """The complete output of onboarding; the only customer-supplied input the
    attack engine and detector ladder consume."""
    name: str
    industry: str
    bot_purpose: str
    in_scope_tasks: list[str] = field(default_factory=list)
    sensitive_assets: list[SensitiveAsset] = field(default_factory=list)
    prohibitions: list[Prohibition] = field(default_factory=list)
    authorised_by: Optional[str] = None
    environment: str = "simulation"
    created_at: datetime = field(default_factory=_utcnow)
    id: str = field(default_factory=lambda: _new_id("tgt"))

    @property
    def unconfirmed_assets(self) -> list[SensitiveAsset]:
        return [a for a in self.sensitive_assets if a.inferred and not a.confirmed_by_customer]

    def canaries(self) -> list[Canary]:
        return [c for a in self.sensitive_assets for c in a.canaries]


# --------------------------------------------------------------------------- #
# Conversation and execution records
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Message:
    role: str  # system | user | assistant
    content: str


@dataclass(frozen=True)
class TargetResponse:
    """Raw, unmodified target reply plus what is needed to reproduce the call."""
    content: str
    model: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: Optional[int] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class Signal:
    """One detector's observation: evidence span + stated rationale. Not yet a
    finding."""
    detector: str
    tier: DetectorTier
    category: AssetCategory
    confidence: float
    evidence: str
    rationale: str
    asset_id: Optional[str] = None
    id: str = field(default_factory=lambda: _new_id("sig"))

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")

    @property
    def requires_human_review(self) -> bool:
        return self.tier is DetectorTier.SEMANTIC


@dataclass(frozen=True)
class Turn:
    """One attacker utterance and the target's reply, with any signals. The
    atomic unit of the evidence chain."""
    index: int
    technique: AttackTechnique
    attacker_message: str
    response: TargetResponse
    signals: tuple[Signal, ...] = ()
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class Attempt:
    """One complete attack path against one objective: transcript + effort."""
    objective_id: str
    target_id: str
    outcome: AttemptOutcome
    turns: list[Turn] = field(default_factory=list)
    system_prompt_sent: Optional[str] = None
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None
    id: str = field(default_factory=lambda: _new_id("att"))

    @property
    def signals(self) -> list[Signal]:
        return [s for t in self.turns for s in t.signals]

    @property
    def turns_to_first_signal(self) -> Optional[int]:
        for turn in self.turns:
            if turn.signals:
                return turn.index
        return None

    @property
    def techniques_tried(self) -> list[AttackTechnique]:
        seen: list[AttackTechnique] = []
        for turn in self.turns:
            if turn.technique not in seen:
                seen.append(turn.technique)
        return seen

    @property
    def effort_to_break(self) -> Optional[int]:
        """Turns to first failure. Raw count, deliberately not a 0-100 score."""
        return self.turns_to_first_signal


@dataclass
class Finding:
    """An adjudicated weakness: the weakest link, with reproduction. Severity is
    derived; ``severity_rationale`` records the inputs."""
    title: str
    category: AssetCategory
    severity: Severity
    severity_rationale: str
    tier: DetectorTier
    review_state: ReviewState
    objective_id: str
    attempt_ids: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    reproduction: list[Message] = field(default_factory=list)
    effort_to_break: Optional[int] = None
    reproduction_rate: Optional[float] = None
    handler_note: Optional[str] = None
    id: str = field(default_factory=lambda: _new_id("fnd"))

    def __post_init__(self) -> None:
        if self.reproduction_rate is not None and not 0.0 <= self.reproduction_rate <= 1.0:
            raise ValueError("reproduction_rate must be in [0, 1]")

    @property
    def is_actionable(self) -> bool:
        return self.review_state in (ReviewState.AUTO_CONFIRMED, ReviewState.CONFIRMED)


@dataclass
class ScanResult:
    target: TargetProfile
    attempts: list[Attempt] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None
    id: str = field(default_factory=lambda: _new_id("scn"))

    @property
    def weakest_link(self) -> Optional[Finding]:
        actionable = [f for f in self.findings if f.is_actionable]
        if not actionable:
            return None
        return max(actionable, key=lambda f: (f.severity.rank, -(f.effort_to_break or 999)))

    @property
    def review_queue(self) -> list[Finding]:
        return [f for f in self.findings if f.review_state is ReviewState.PENDING_REVIEW]

    @property
    def coverage_summary(self) -> dict[str, Any]:
        techniques: set[AttackTechnique] = set()
        for attempt in self.attempts:
            techniques.update(attempt.techniques_tried)
        return {
            "objectives_tested": len({a.objective_id for a in self.attempts}),
            "attempts": len(self.attempts),
            "turns": sum(len(a.turns) for a in self.attempts),
            "techniques_used": sorted(t.value for t in techniques),
            "errored_attempts": sum(1 for a in self.attempts if a.outcome is AttemptOutcome.ERRORED),
        }
