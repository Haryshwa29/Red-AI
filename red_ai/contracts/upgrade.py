"""
Upgrade candidate: the A->V0 upstream hand-off, split so review can catch leaks.

Why this type exists
--------------------
RED-AI ships a baseline (V0) to every client. Each client's instance adapts
LOCALLY to its own environment and that adapted state stays at that client
(reviewed-finding memory, see ``red_ai.control.memory``). Occasionally a client
instance observes something that looks like a *generic* capability worth folding
back into V0 for everyone. That upstream back-flow is the single most sensitive
path in the product: the whole product promise is "no client data leaves the
client network", and a learned "capability" can quietly encode the client's own
environment (a target name, an environment label, a config detail).

A human already decides whether anything reaches V0 (the operator reviews and
promotes; the engine never alters itself). But a human gate protects AUTHORITY,
not LEAKAGE -- a reviewer approving "is this a good upgrade?" will not notice a
client's name embedded in the capability text. So this type splits the candidate
into two halves kept apart *by construction*:

  * ``GenericCapability``   -- environment-agnostic, built only from
                               non-identifying metadata (technique / surface /
                               category). The ONLY half eligible to reach V0.
  * ``LocalProvenance``     -- the client-identifying justification (target,
                               environment, owner, source runs). Shown to the
                               reviewer as evidence, NEVER serialized upstream.

The constructor runs a deterministic leakage tripwire: if any client identifier
from the provenance appears in the generic half's text, the candidate refuses to
build. That makes the operator's review a review *for leakage*, because the two
halves are already separated and checked when they reach the review report.

Stated limit: the tripwire is a conservative substring/token check, not a proof.
It catches the identifiers we hold; it cannot catch a paraphrase of a client's
environment. It fails closed (raises) and the generic half is built from metadata
that contains no client text in the first place, so the tripwire is a second line,
not the only one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from red_ai.contracts.domain import AttackTechnique, AssetCategory
from red_ai.contracts.scope import canonical, now

_TECHNIQUES = {t.value for t in AttackTechnique}
_CATEGORIES = {c.value for c in AssetCategory}

# Identifier word-tokens shorter than this are ignored by the tripwire to avoid
# false trips on common words. Full identifier strings are always checked whole.
_MIN_TOKEN_LEN = 4


class LeakageError(ValueError):
    """Raised when a generic (upstream-eligible) half carries a client identifier."""


def _tokens(*values: str) -> set[str]:
    out: set[str] = set()
    for value in values:
        if not value:
            continue
        for raw in str(value).replace("/", " ").replace("-", " ").replace("_", " ").split():
            token = "".join(ch for ch in raw.lower() if ch.isalnum())
            if len(token) >= _MIN_TOKEN_LEN:
                out.add(token)
    return out


@dataclass(frozen=True)
class GenericCapability:
    """Environment-agnostic capability. The only half eligible to reach V0.

    Built from non-identifying metadata only. ``condition`` and ``rationale`` are
    generic descriptions; they must name no client, environment, or raw target
    text (enforced by the candidate's leakage tripwire)."""
    technique: str
    surface: str
    category: str
    condition: str
    rationale: str
    recommended_detectors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.technique not in _TECHNIQUES:
            raise ValueError(f"Unknown technique: {self.technique!r}")
        if self.category not in _CATEGORIES:
            raise ValueError(f"Unknown category: {self.category!r}")
        if not self.surface or not isinstance(self.surface, str):
            raise ValueError("surface is required")
        if not (1 <= len(self.condition) <= 2000):
            raise ValueError("condition must be 1..2000 chars")
        if not (1 <= len(self.rationale) <= 2000):
            raise ValueError("rationale must be 1..2000 chars")
        if not isinstance(self.recommended_detectors, tuple):
            raise ValueError("recommended_detectors must be a tuple")

    @property
    def fingerprint(self) -> str:
        """Stable identity of the capability, independent of any client."""
        return hashlib.sha256(
            canonical([self.technique, self.surface, self.category]).encode()
        ).hexdigest()[:24]

    def text_tokens(self) -> set[str]:
        """Every token a leakage check must scan."""
        return _tokens(self.condition, self.rationale, *self.recommended_detectors)


@dataclass(frozen=True)
class LocalProvenance:
    """Client-identifying justification. NEVER serialized upstream.

    ``case_ids`` / ``source_runs`` are opaque hashes already; ``target``,
    ``environment`` and ``owner`` are the human-meaningful identifiers the
    tripwire guards against."""
    target: str
    environment: str
    owner: str = ""
    observations: int = 0
    distinct_targets: int = 0
    reproduction_rate: float | None = None
    case_ids: tuple[str, ...] = ()
    source_runs: tuple[str, ...] = ()

    def identifier_tokens(self) -> set[str]:
        return _tokens(self.target, self.environment, self.owner)

    def identifier_strings(self) -> tuple[str, ...]:
        return tuple(v for v in (self.target, self.environment, self.owner) if v)


@dataclass(frozen=True)
class UpgradeCandidate:
    """A proposed V0 upgrade: a generic half + the local evidence for it.

    Immutable, leakage-checked on build, content-hashed for traceability. Status
    is always ``proposed`` here: promotion into V0 is a vendor-side human act
    outside the client instance, never an automatic effect of building this."""
    generic: GenericCapability
    provenance: LocalProvenance
    status: str = "proposed"
    created_at: str = field(default_factory=lambda: now().isoformat())

    def __post_init__(self) -> None:
        assert_clean(self.generic, self.provenance)

    @property
    def candidate_id(self) -> str:
        return self.generic.fingerprint

    @property
    def content_hash(self) -> str:
        """Hash over the upstream-eligible half only -- what a V0 reviewer signs."""
        return hashlib.sha256(canonical({
            "technique": self.generic.technique,
            "surface": self.generic.surface,
            "category": self.generic.category,
            "condition": self.generic.condition,
            "rationale": self.generic.rationale,
            "recommended_detectors": list(self.generic.recommended_detectors),
        }).encode()).hexdigest()

    def upstream_payload(self) -> dict:
        """The ONLY thing allowed to travel to V0. Contains no provenance.

        Re-checks for leakage before emitting, so even a hand-built candidate
        cannot export a client identifier."""
        assert_clean(self.generic, self.provenance)
        return {
            "candidate_id": self.candidate_id,
            "content_hash": self.content_hash,
            "technique": self.generic.technique,
            "surface": self.generic.surface,
            "category": self.generic.category,
            "condition": self.generic.condition,
            "rationale": self.generic.rationale,
            "recommended_detectors": list(self.generic.recommended_detectors),
            "observations": self.provenance.observations,
            "distinct_targets": self.provenance.distinct_targets,
            "status": self.status,
        }


def assert_clean(generic: GenericCapability, provenance: LocalProvenance) -> None:
    """Refuse if any client identifier leaked into the upstream-eligible half.

    Two passes: whole-string (case-insensitive substring) and per-token overlap.
    Raises ``LeakageError`` naming the offending identifier; never mutates."""
    haystack = " ".join([generic.condition, generic.rationale,
                          " ".join(generic.recommended_detectors)]).lower()
    for ident in provenance.identifier_strings():
        if ident.lower() in haystack:
            raise LeakageError(
                f"Client identifier {ident!r} appears in the upstream-eligible "
                f"capability text; refusing to build/export this candidate.")
    overlap = generic.text_tokens() & provenance.identifier_tokens()
    if overlap:
        raise LeakageError(
            f"Client identifier token(s) {sorted(overlap)} appear in the "
            f"upstream-eligible capability text; refusing this candidate.")
