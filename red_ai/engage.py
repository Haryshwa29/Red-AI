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


def normalize_target(raw: str) -> dict:
    """Accept an IP, hostname, host:port, or full URL; return its parts.

    Returns ``{host, scheme, port, path, raw}`` with ``scheme``/``port`` ``None``
    when unspecified and ``path`` defaulting to ``"/"``. This lets an operator
    point RED-AI at a web app by URL (``http://host/app/``) instead of a bare IP:
    ``host`` is what recon scans, while ``scheme``/``port``/``path`` steer the web
    surface. The host still flows through the signed scope and gate unchanged.
    """
    raw = (raw or "").strip()
    if "://" in raw:
        from urllib.parse import urlparse
        u = urlparse(raw)
        return {"host": u.hostname or "", "scheme": (u.scheme or "").lower() or None,
                "port": u.port, "path": u.path or "/", "raw": raw}
    host, port = raw, None
    if raw.startswith("[") and "]" in raw:                 # [IPv6]:port
        host = raw[1:raw.index("]")]
        rest = raw[raw.index("]") + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif raw.count(":") == 1:                              # host:port
        h, _, p = raw.partition(":")
        if p.isdigit():
            host, port = h, int(p)
    return {"host": host, "scheme": None, "port": port, "path": "/", "raw": raw}


def _merge_port(ports: str, extra: "int | None") -> str:
    """Prepend an explicit URL port to the recon port list (deduped)."""
    if not extra:
        return ports
    have = [p.strip() for p in str(ports).split(",") if p.strip()]
    if str(extra) not in have:
        have.insert(0, str(extra))
    return ",".join(have)


def engage_core(*, root, target, ports="80,8080,8000,8888,443",
                flag_pattern=DEFAULT_FLAG_PATTERN, env="authorized_lab",
                attestation="Authorized lab/CTF engagement (operator-attested).",
                allow_production=False, max_steps=400, max_seconds=900,
                operator=DEFAULT_OPERATOR, enabled_modules=(), objective="",
                audit=False, on_event=None, verbose=False) -> dict:
    """Run one engagement. Returns a result dict (see keys at the bottom)."""
    root = Path(root)
    flag_pattern = flag_pattern or DEFAULT_FLAG_PATTERN   # None/empty -> default
    # Accept an IP, hostname, host:port, or full URL. The bare host is what the
    # scanner connects to (socket resolves names); an explicit URL port is folded
    # into the recon list so e.g. http://app:3000/ is reached without extra flags.
    tgt = normalize_target(target)
    host = tgt["host"] or target
    ports = _merge_port(ports, tgt["port"])
    if tgt["raw"] != host:
        attestation = f"{attestation} | target: {tgt['raw']}"
    # The operator's stated objective is recorded in the signed attestation (and
    # the evidence), so a run's intent is auditable. It is context, not an
    # autonomous planner: the pipeline stays deterministic.
    if objective:
        attestation = f"{attestation} | objective: {objective}"

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

    emit("engage_started", {"target": target, "host": host, "scheme": tgt["scheme"],
                            "path": tgt["path"], "ports": ports, "env": env,
                            "operator": operator, "objective": objective}, "engage")

    # --- 1) RECON --------------------------------------------------------
    recon_scope = ReconScope.build(
        scope_id=f"engage-recon-{stamp}", owner=target, authorised_by=operator,
        hosts=host, ports=ports, attestation=attestation,
        owner_attested=True, environment=env, allow_production=allow_production,
        identify_services=True, enumerate_web=True, assess_tls=True,
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
                                on_event=phased("exploit"), stop_on_capture=not audit).run()

    captured = summary["flag"]["captured"]
    fv = next((f.get("flag_value") for f in summary.get("findings", []) if f.get("flag_value")), "")
    result.update(summary=summary, exploit_out=str(exploit_out), captured=captured,
                  flag_value=fv, outcome=summary["outcome"], steps=summary["steps"],
                  rate=summary["flag"]["rate"],
                  status="captured" if captured else "no_breach")
    emit("engage_finished", {"status": result["status"], "flag_value": fv,
                             "outcome": summary["outcome"], "steps": summary["steps"]}, "engage")
    return result
