"""
Engagement type and action-reversibility taxonomy -- the axis that decides how
far RED-AI's authority extends in a given engagement.

Two orthogonal facts travel on every signed scope:

  * ``environment`` (simulation | staging | production) -- WHERE the target is.
  * ``EngagementType`` (pentest | monitoring)           -- HOW FAR authority goes.

They are not the same question, and conflating them was the original design
error. Testing almost always happens against a disposable replica, so the
useful distinction is not location but engagement intent:

  * PENTEST    -- a scoped, consented, one-shot breach test (sandbox or CTF).
                  Harm is reversible; full exploitation is the whole point.
  * MONITORING -- a standing, autonomous watch over a LIVE network. An always-on
                  agent must not complete an irreversible action on its own; it
                  proves reachability and hands the final command to a human.

Every proposed action also declares an ``ActionTier`` by the reversibility of
its effect on the target:

  * PASSIVE     -- observe only; fully reversible (recon, read, enumerate).
  * ACTIVE_SAFE -- non-destructive proof (a single auth probe, read one file to
                  prove access). Reversible, but it touches the target.
  * DESTRUCTIVE -- irreversible or state-changing (bruteforce that can lock an
                  account, write/delete, DoS, exfiltrate real data, capture the
                  flag, plant persistence).

``tier_authority`` is the deterministic policy the gate consults. It is the
mechanical form of the firm principle: *no AI completes an irreversible change
on a live system on its own -- a human issues the final command.* That principle
binds in MONITORING; in a disposable PENTEST sandbox nothing is irreversible, so
the gate opens on every tier.
"""
from __future__ import annotations

from enum import Enum


class EngagementType(str, Enum):
    PENTEST = "pentest"
    MONITORING = "monitoring"


class ActionTier(str, Enum):
    PASSIVE = "passive"
    ACTIVE_SAFE = "active_safe"
    DESTRUCTIVE = "destructive"


class Authority(str, Enum):
    """What the gate may do with a proposed action of a given tier."""
    ALLOW = "allow"              # autonomous; the gate opens
    HUMAN_GATE = "human_gate"    # refused autonomously; a human must issue it
    # Reserved for a future rung: ACTIVE_SAFE under MONITORING becoming a
    # per-action authorization prompt rather than a blanket allow.
    AUTHORIZE = "authorize"


# The whole policy, as data. No branching cleverness: a 2x3 table anyone can
# read and audit. PENTEST opens every tier (reversible sandbox); MONITORING
# opens observation and non-destructive proof but human-gates the irreversible
# step -- prove-and-stop.
_AUTHORITY: dict[EngagementType, dict[ActionTier, Authority]] = {
    EngagementType.PENTEST: {
        ActionTier.PASSIVE: Authority.ALLOW,
        ActionTier.ACTIVE_SAFE: Authority.ALLOW,
        ActionTier.DESTRUCTIVE: Authority.ALLOW,
    },
    EngagementType.MONITORING: {
        ActionTier.PASSIVE: Authority.ALLOW,
        ActionTier.ACTIVE_SAFE: Authority.ALLOW,
        ActionTier.DESTRUCTIVE: Authority.HUMAN_GATE,
    },
}


def tier_authority(engagement_type: str, action_tier: str) -> Authority:
    """Deterministic authority for (engagement_type, action_tier).

    Accepts the raw strings carried on a scope/proposal so callers need not
    import the enums. Unknown values fail CLOSED (HUMAN_GATE): an action whose
    reversibility we cannot classify is never taken autonomously.
    """
    try:
        et = EngagementType(engagement_type)
        tier = ActionTier(action_tier)
    except ValueError:
        return Authority.HUMAN_GATE
    return _AUTHORITY[et][tier]


ENGAGEMENT_VALUES: tuple[str, ...] = tuple(e.value for e in EngagementType)
ACTION_TIER_VALUES: tuple[str, ...] = tuple(t.value for t in ActionTier)
