"""
Authorization contract: a signed, immutable scope the control layer enforces.

The scope is the ONLY thing that decides what RED-AI is allowed to do. The
intelligent layer may propose any action; the deterministic gate (see
``red_ai.control.gate``) checks every proposed action against this object and
nothing else. The model never edits a scope, and a scope is HMAC-signed so a
tampered copy is refused before a single message is sent.

Ported and generalized from the RED-AI_Self prototype: the authorization facts
that used to live in a separate safety policy (authoriser, environment,
production opt-in) are folded in here, so one signed object carries the whole
permission context.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json

from red_ai.contracts.domain import AttackTechnique
from red_ai.contracts.action import ENGAGEMENT_VALUES as _ENGAGEMENT_VALUES

_TECHNIQUE_VALUES: tuple[str, ...] = tuple(t.value for t in AttackTechnique)


def canonical(value) -> str:
    """Stable JSON encoding used for both hashing and signing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Scope timestamps must include a timezone")
    return result


@dataclass(frozen=True)
class Scope:
    """
    One authorized engagement. Immutable and signable.

    Authorization facts (``owner``, ``authorised_by``, ``environment``) and the
    hard limits (budgets, validity window, allowed techniques) are all here so
    that the gate has a single source of truth it can enforce deterministically.
    """

    scope_id: str
    owner: str
    authorised_by: str
    target: str
    valid_from: str
    valid_until: str
    environment: str = "simulation"          # simulation | staging | production
    engagement_type: str = "pentest"         # pentest | monitoring (how far authority goes)
    techniques: tuple[str, ...] = _TECHNIQUE_VALUES
    tools: tuple[str, ...] = ()
    max_queries: int = 40
    max_seconds: int = 1800
    timeout_seconds: int = 30
    max_cost_units: int = 60
    confirmations: int = 1
    replays: int = 2
    synthetic_only: bool = True
    allow_production: bool = False
    target_version: str = "sim-1"
    operator_id: str = ""                    # named operator bound to this scope (identity)
    readers: tuple[str, ...] = ()            # operator ids that may read this run's reports (need-to-know)

    def __post_init__(self) -> None:
        for name in ("scope_id", "owner", "authorised_by", "target", "target_version", "environment"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Invalid {name}")
        if self.environment not in ("simulation", "staging", "production"):
            raise ValueError("environment must be simulation, staging or production")
        if self.engagement_type not in _ENGAGEMENT_VALUES:
            raise ValueError("engagement_type must be pentest or monitoring")
        if not isinstance(self.techniques, tuple) or not self.techniques:
            raise ValueError("At least one technique must be authorized")
        unknown = [t for t in self.techniques if t not in _TECHNIQUE_VALUES]
        if unknown:
            raise ValueError(f"Unknown technique(s): {unknown}")
        if len(set(self.techniques)) != len(self.techniques):
            raise ValueError("Duplicate techniques")
        if not isinstance(self.tools, tuple):
            raise ValueError("tools must be a tuple")
        if not isinstance(self.operator_id, str):
            raise ValueError("operator_id must be a string")
        if not isinstance(self.readers, tuple):
            raise ValueError("readers must be a tuple")
        for name in ("max_queries", "max_seconds", "timeout_seconds", "max_cost_units"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 100000:
                raise ValueError(f"Invalid {name}")
        if type(self.confirmations) is not int or not 0 <= self.confirmations <= 5:
            raise ValueError("confirmations must be between 0 and 5")
        if type(self.replays) is not int or not 0 <= self.replays <= 20:
            raise ValueError("replays must be between 0 and 20")
        if self.synthetic_only is not True and self.environment == "simulation":
            raise ValueError("Simulation scopes must stay synthetic_only")
        if self.environment == "production" and not self.allow_production:
            raise ValueError("Production target requires allow_production=True")
        if timestamp(self.valid_from) >= timestamp(self.valid_until):
            raise ValueError("Invalid validity window")

    @classmethod
    def from_dict(cls, value: dict) -> "Scope":
        value = dict(value)
        for name in ("techniques", "tools", "readers"):
            if name in value and isinstance(value[name], list):
                value[name] = tuple(value[name])
        return cls(**value)


def sign_scope(scope: Scope, key: bytes) -> dict:
    payload = asdict(scope)
    signature = hmac.new(key, canonical(payload).encode(), hashlib.sha256).hexdigest()
    return {"scope": payload, "signature": signature}


def verify_scope(envelope: dict, key: bytes) -> Scope:
    expected = hmac.new(key, canonical(envelope["scope"]).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["signature"]):
        raise ValueError("Scope signature invalid; execution refused")
    return Scope.from_dict(envelope["scope"])
