"""RED-AI recon engine (rung 5): authorized network reconnaissance.

A SEPARATE execution engine from the LLM-interface engine, by design. It shares
the trusted spine -- a signed authorization scope, a deterministic gate, and the
hash-linked evidence journal -- but has its own scope type, its own gate, and no
import path back into the prompt-injection skill/controller. The hard wall is
structural: the LLM engine never scans a network, and the recon engine never
sends attacker prompts.

Capability in this build: TCP connect reconnaissance (open-port discovery) only.
It is read-only -- it completes a TCP handshake and closes; it sends no payloads,
runs no exploits, and changes nothing on the target. That matches the firm
project rule: the AI may propose and the engine may observe, but no AI alters an
environment; any permanent change is a separate, human-issued step.
"""
from red_ai.recon.scope import ReconScope, sign_recon_scope, verify_recon_scope
from red_ai.recon.scanner import TcpConnectScanner, ProbeResult, PortState
from red_ai.recon.controller import ReconController

__all__ = [
    "ReconScope", "sign_recon_scope", "verify_recon_scope",
    "TcpConnectScanner", "ProbeResult", "PortState", "ReconController",
]
