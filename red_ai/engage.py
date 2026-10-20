"""Reusable live-engagement core: recon -> bridge -> exploit -> capture.

Both the CLI (`python -m red_ai engage`) and the web dashboard call this, so the
exact same gated, evidenced pipeline runs whichever way an operator drives it.
Nothing here is UI-specific: it takes an optional ``on_event`` tap (each recon /
exploit journal event, tagged with its phase, plus a few engage-level phase
markers) and an optional ``verbose`` for terminal streaming.

Authorization is unchanged: the caller supplies an operator identity (must exist)
and an owner attestation, both recorded in the evidence; every exploit step is
still gated; the brain is not involved.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import secrets

from red_ai.contracts.scope import now
from red_ai.control.identity import Keyring, DEFAULT_OPERATOR, AccessDenied
from red_ai.recon.scope import ReconScope
from red_ai.recon.controller import ReconController
from red_ai.exploit.scope import ExploitScope
from red_ai.exploit.contracts import FlagDefinition
from red_ai.exploit.module import ExploitModuleRegistry
from red_ai.exploit.modules import (HTTPFlagReadModule, WebFlagHuntModule, HTTPBasicAuthModule,
                                    LFIModule, SQLiModule, CommandInjectionModule,
                                    ContentDiscoveryModule)
from red_ai.exploit.controller import ExploitController
from red_ai.exploit.bridge import surfaces_from_recon

_WEB_PORTS = {80, 443, 591, 8000, 8008, 8080, 8888}

# Default: match THM/HTB/flag{...} wrappers or a bare 32-hex (HTB machine flags).
DEFAULT_FLAG_PATTERN = r"(?:THM|FLAG|HTB|flag)\{[^}]{1,128}\}|\b[0-9a-f]{32}\b"


def build_registry() -> ExploitModuleRegistry:
    """The native, gated web exploit module set, native-first order.

    Content discovery runs FIRST: the paths it finds are recorded as footholds
    that the flag hunt and injection modules then inherit as candidate surface."""
    reg = ExploitModuleRegistry()
    reg.register(ContentDiscoveryModule())
    reg.register(WebFlagHuntModule())
    reg.register(HTTPBasicAuthModule())
    reg.register(LFIModule())
    reg.register(SQLiModule())
    reg.register(CommandInjectionModule())
    reg.register(HTTPFlagReadModule())
    return reg


class EngageError(ValueError):
    """Bad engagement inputs (unknown operator, production without opt-in, ...)."""


def module_roster() -> list:
    """The web module set as {id, name} — for the dashboard's enable/disable toggles."""
    return [{"id": m.id, "name": m.name} for m in build_registry().all()]


def engage_core(*, root, target, ports="80,8080,8000,8888,443",
                flag_pattern=DEFAULT_FLAG_PATTERN, env="authorized_lab",
                attestation="Authorized lab/CTF engagement (operator-attested).",
                allow_production=False, max_steps=400, max_seconds=900,
                operator=DEFAULT_OPERATOR, enabled_modules=(), on_event=None,
                verbose=False) -> dict:
    """Run one engagement. Returns a result dict (see keys at the bottom)."""
    root = Path(root)
    flag_pattern = flag_pattern or DEFAULT_FLAG_PATTERN   # None/empty -> default

    # --- authorization preconditions -------------------------------------
    keyring = Keyring(root)
    try:
        keyring.key(operator)
    except (AccessDenied, KeyError, FileNotFoundError):
        raise EngageError(f"unknown operator '{operator}' "
                          f"(create one: python -m red_ai operator add {operator})")
    if env == "production" and not allow_production:
        raise EngageError("engaging a production target requires allow_production")

    def emit(kind, payload, phase):
        if on_event is not None:
            try:
                on_event({"kind": kind, "payload": payload, "phase": phase,
                          "timestamp": now().isoformat(), "source": "engage"})
            except Exception:
                pass

    def phased(phase):
        return (lambda ev: on_event({**ev, "phase": phase})) if on_event else None

    stamp = now().strftime("%Y%m%dT%H%M%S")
    run_tag = f"{stamp}-{secrets.token_hex(2)}"
    valid_from = (now() - timedelta(minutes=1)).isoformat()
    valid_until = (now() + timedelta(hours=2)).isoformat()

    emit("engage_started", {"target": target, "ports": ports, "env": env,
                            "operator": operator}, "engage")

    # --- 1) RECON --------------------------------------------------------
    recon_scope = ReconScope.build(
        scope_id=f"engage-recon-{stamp}", owner=target, authorised_by=operator,
        hosts=target, ports=ports, attestation=attestation,
        owner_attested=True, environment=env, allow_production=allow_production,
        identify_services=True, enumerate_web=True,
        valid_from=valid_from, valid_until=valid_until)
    recon_out = root / "runs" / f"{run_tag}-engage-recon"
    recon_summary = ReconController(recon_scope, recon_out, cancel_file=root / "STOP",
                                    verbose=verbose, on_event=phased("recon")).run()

    surfaces, facts = surfaces_from_recon(recon_summary)
    web_surfaces = [s for s in surfaces
                    if str(s.service or "").upper().startswith("HTTP") or s.port in _WEB_PORTS]
    emit("recon_done", {"open_surfaces": len(surfaces), "web_surfaces": len(web_surfaces),
                        "facts": len(facts), "evidence": str(recon_out)}, "enumerate")

    result = {"target": target, "run_tag": run_tag, "recon_summary": recon_summary,
              "surfaces": len(surfaces), "web_surfaces": len(web_surfaces), "facts": facts,
              "recon_out": str(recon_out), "exploit_out": None, "summary": None,
              "captured": False, "flag_value": "", "outcome": "no_web_surface",
              "steps": 0, "rate": None}

    if not web_surfaces:
        emit("engage_finished", {"status": "no_web_surface"}, "engage")
        result["status"] = "no_web_surface"
        return result

    # --- 2) EXPLOIT ------------------------------------------------------
    flag = FlagDefinition(
        kind="pattern",
        description=f"Any platform flag token returned by an authorized web surface on {target}",
        target_ref="a response body on an in-scope web surface", expected=flag_pattern)
    xscope = ExploitScope(
        scope_id=f"engage-exploit-{stamp}", owner=target, authorised_by=operator,
        surfaces=tuple(s.id for s in web_surfaces), flag=flag,
        valid_from=valid_from, valid_until=valid_until, attestation=attestation,
        owner_attested=True, environment=env, allow_production=allow_production,
        engagement_type="pentest", modules=tuple(enabled_modules),
        max_steps=max_steps, max_seconds=max_seconds)

    exploit_out = root / "runs" / f"{run_tag}-engage-exploit"
    emit("exploit_started", {"surfaces": len(web_surfaces)}, "exploit")
    summary = ExploitController(xscope, exploit_out, build_registry(), surfaces=web_surfaces,
                                established_facts=facts, provider=None,
                                cancel_file=root / "STOP", verbose=verbose,
                                on_event=phased("exploit")).run()

    captured = summary["flag"]["captured"]
    fv = next((f.get("flag_value") for f in summary.get("findings", []) if f.get("flag_value")), "")
    result.update(summary=summary, exploit_out=str(exploit_out), captured=captured,
                  flag_value=fv, outcome=summary["outcome"], steps=summary["steps"],
                  rate=summary["flag"]["rate"],
                  status="captured" if captured else "no_breach")
    emit("engage_finished", {"status": result["status"], "flag_value": fv,
                             "outcome": summary["outcome"], "steps": summary["steps"]}, "engage")
    return result
