"""Optional model analyst: the brain EXPLAINS open ports; it never scores them.

Severity and remediation come from the deterministic ``services`` table. The
analyst adds a short, human-readable note per open finding -- the kind of line a
pentester writes next to a result -- and nothing more. It is strictly additive
commentary:

  * It cannot change a severity, add a finding, or authorize anything.
  * On any provider error it is simply omitted; findings stand without it.
  * It is the same untrusted/aligned-brain seam as the LLM engine: a safety
    model that declines just yields no note, and the report is still complete.
"""
from __future__ import annotations

from typing import Optional

from red_ai.contracts.domain import Message
from red_ai.contracts.interfaces import ModelProvider

_SYSTEM = (
    "You are a security analyst assisting an AUTHORISED internal port-exposure "
    "review of the operator's own host. For the single open port described, "
    "write ONE plain sentence (max 200 chars) on why exposing it on this host "
    "may matter and what to check. Do not include commands or exploit steps. "
    "If you have nothing useful to add, reply exactly: (no note)."
)


def annotate(provider: Optional[ModelProvider], host: str, port: int,
             service: str, severity: str, environment: str) -> Optional[str]:
    if provider is None:
        return None
    user = (f"Host {host}, open TCP port {port} ({service}). Environment: "
            f"{environment}. Deterministic severity already assigned: {severity}.")
    try:
        note = provider.generate(
            [Message(role="system", content=_SYSTEM), Message(role="user", content=user)],
            num_predict=160, think=False,
        ).strip()
    except Exception:
        return None
    if not note or note.lower().startswith("(no note") or note.lower().startswith("i can"):
        return None  # aligned refusal or empty -> no note, finding still stands
    return note[:400]
