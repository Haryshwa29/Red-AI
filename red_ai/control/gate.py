"""The deterministic policy gate: the control layer's final authority.

Every Proposal the intelligent layer emits is checked here against the signed
Scope BEFORE anything reaches a target. The model cannot widen scope, raise a
budget, or disable a limit -- it can only propose actions that this function
then allows or denies. Authorization is code, never an LLM judgement.

Returns None when the action is allowed, otherwise a stable reason string.
Reasons are split by the controller into HALTS (stop the campaign) and DENIALS
(skip this one proposal, keep going).
"""
from __future__ import annotations

from red_ai.contracts.scope import Scope, now, timestamp
from red_ai.contracts.proposal import Proposal
from red_ai.contracts.action import tier_authority, Authority

# Reasons that stop the whole campaign.
HALTING = frozenset({
    "human_cancellation",
    "authorization_expired_or_not_yet_valid",
    "time_budget_exhausted",
    "query_budget_exhausted",
    "cost_budget_exhausted",
})


def gate(scope: Scope, proposal: Proposal, queries: int, cost: int, elapsed: float,
         cancelled: bool = False, clock=None) -> str | None:
    clock = clock or now()
    if cancelled:
        return "human_cancellation"
    if clock < timestamp(scope.valid_from) or clock >= timestamp(scope.valid_until):
        return "authorization_expired_or_not_yet_valid"
    if elapsed >= scope.max_seconds:
        return "time_budget_exhausted"
    if queries >= scope.max_queries:
        return "query_budget_exhausted"
    if cost >= scope.max_cost_units:
        return "cost_budget_exhausted"
    if proposal.technique not in scope.techniques:
        return "prohibited_technique"
    if proposal.tool is not None and proposal.tool not in scope.tools:
        return "prohibited_tool"
    # Action-reversibility authority: the mechanical form of prove-and-stop.
    # PENTEST opens every tier; MONITORING human-gates a DESTRUCTIVE action so
    # no irreversible change on a live system is completed autonomously.
    # Anything not explicitly ALLOW is refused here (fail-closed). This is a
    # per-proposal denial, not a HALT: the campaign records it and continues.
    if tier_authority(scope.engagement_type, proposal.action_tier) is not Authority.ALLOW:
        return "action_requires_human_authorization"
    return None
