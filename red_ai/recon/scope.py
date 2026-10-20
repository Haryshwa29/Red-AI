"""Signed authorization for a recon engagement.

Separate from the LLM ``Scope`` on purpose: network recon authorizes *hosts and
ports*, not attack techniques. One signed object carries who authorized it, what
may be probed, the budgets, and an explicit owner/authorization attestation. The
gate enforces this and nothing else; the model never edits it.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac

from red_ai.contracts.scope import canonical, now, timestamp
from red_ai.contracts.action import ENGAGEMENT_VALUES as _ENGAGEMENT_VALUES


def _parse_ports(spec: str) -> tuple[int, ...]:
    """'22,80,443' or '1-1024' or a mix -> sorted unique tuple of valid ports."""
    out: set[int] = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"port range out of bounds: {part}")
            out.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"port out of bounds: {p}")
            out.add(p)
    if not out:
        raise ValueError("no ports specified")
    return tuple(sorted(out))


@dataclass(frozen=True)
class ReconScope:
    """One authorized reconnaissance engagement. Immutable and signable."""

    scope_id: str
    owner: str
    authorised_by: str
    hosts: tuple[str, ...]          # exact host/IP strings the engine may probe
    ports: tuple[int, ...]          # exact ports the engine may probe
    valid_from: str
    valid_until: str
    attestation: str                # free-text authorization statement, required
    owner_attested: bool = False    # must be True: a human asserted authorization
    environment: str = "owned"      # owned | authorized_lab | production
    allow_production: bool = False
    engagement_type: str = "pentest"   # pentest | monitoring (recon probes are PASSIVE)
    max_probes: int = 2000
    max_seconds: int = 600
    timeout_ms: int = 800
    concurrency: int = 64
    replays: int = 1                # re-probe open ports to report a stable result
    identify_services: bool = False  # opt-in active-safe service/version ID (banner.py)
    enumerate_web: bool = False      # opt-in read-only web surface enumeration (web.py)
    assess_tls: bool = False         # opt-in TLS/crypto posture assessment (tls.py)

    @classmethod
    def build(cls, *, ports: str, hosts, **kw) -> "ReconScope":
        hosts = tuple(hosts) if not isinstance(hosts, str) else (hosts,)
        return cls(hosts=hosts, ports=_parse_ports(ports), **kw)

    def __post_init__(self) -> None:
        for name in ("scope_id", "owner", "authorised_by", "attestation", "environment"):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"Invalid {name}")
        if self.environment not in ("owned", "authorized_lab", "production"):
            raise ValueError("environment must be owned, authorized_lab or production")
        if self.engagement_type not in _ENGAGEMENT_VALUES:
            raise ValueError("engagement_type must be pentest or monitoring")
        if not isinstance(self.hosts, tuple) or not self.hosts:
            raise ValueError("at least one host must be authorized")
        if any(not isinstance(h, str) or not h.strip() for h in self.hosts):
            raise ValueError("hosts must be non-empty strings")
        if not isinstance(self.ports, tuple) or not self.ports:
            raise ValueError("at least one port must be authorized")
        if self.owner_attested is not True:
            raise ValueError("owner_attested must be True: a human must assert authorization to scan")
        for name in ("max_probes", "max_seconds", "timeout_ms", "concurrency"):
            v = getattr(self, name)
            if type(v) is not int or not 1 <= v <= 1_000_000:
                raise ValueError(f"Invalid {name}")
        if type(self.replays) is not int or not 0 <= self.replays <= 10:
            raise ValueError("replays must be 0..10")
        if self.environment == "production" and not self.allow_production:
            raise ValueError("production target requires allow_production=True")
        if timestamp(self.valid_from) >= timestamp(self.valid_until):
            raise ValueError("invalid validity window")

    @classmethod
    def from_dict(cls, value: dict) -> "ReconScope":
        value = dict(value)
        for name in ("hosts", "ports"):
            if name in value and isinstance(value[name], list):
                value[name] = tuple(value[name])
        return cls(**value)


def sign_recon_scope(scope: ReconScope, key: bytes) -> dict:
    payload = asdict(scope)
    sig = hmac.new(key, canonical(payload).encode(), hashlib.sha256).hexdigest()
    return {"scope": payload, "signature": sig}


def verify_recon_scope(envelope: dict, key: bytes) -> ReconScope:
    expected = hmac.new(key, canonical(envelope["scope"]).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["signature"]):
        raise ValueError("Recon scope signature invalid; execution refused")
    return ReconScope.from_dict(envelope["scope"])
