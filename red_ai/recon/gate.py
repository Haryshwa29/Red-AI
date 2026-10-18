"""Deterministic recon gate: the control layer's authority for network probes.

Every proposed probe (host, port) is checked here against the signed
``ReconScope`` before a socket is opened. The model may propose a probe order;
it can never add a host or port the scope does not authorize, raise a budget, or
scan after expiry. Returns None to allow, else a stable reason. HALTING reasons
stop the engagement; others deny a single probe and the loop continues.
"""
from __future__ import annotations

from red_ai.contracts.scope import now, timestamp
from red_ai.recon.scope import ReconScope

HALTING = frozenset({
    "human_cancellation",
    "authorization_expired_or_not_yet_valid",
    "time_budget_exhausted",
    "probe_budget_exhausted",
})


def recon_gate(scope: ReconScope, host: str, port: int, probes: int, elapsed: float,
               cancelled: bool = False, clock=None) -> str | None:
    clock = clock or now()
    if cancelled:
        return "human_cancellation"
    if clock < timestamp(scope.valid_from) or clock >= timestamp(scope.valid_until):
        return "authorization_expired_or_not_yet_valid"
    if elapsed >= scope.max_seconds:
        return "time_budget_exhausted"
    if probes >= scope.max_probes:
        return "probe_budget_exhausted"
    if host not in scope.hosts:
        return "host_out_of_scope"
    if port not in scope.ports:
        return "port_out_of_scope"
    return None
