"""Shape raw engagement events into panel-ready records, and turn a finished run
into a 'where to improve' gap list.

The dashboard shows the *process*, not just the outcome, so every event is shaped
into {kind, phase, t, ann, data}: ``ann`` is the friendly feed line (from
``annotate``), ``data`` is the trimmed structured fields each panel needs (ports,
services, discovered paths, routing, gate decisions, per-step outcomes, capture).

``gap_analysis`` reads a finished engagement and names what RED-AI *found but
could not use* — mapped to the capability that would get further and the
checkpoint it belongs to. That is the signal for where to improve the engine.
"""
from __future__ import annotations

import re

from red_ai.web.annotate import annotate

# Non-web services worth calling out as "found, but no capability yet".
_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 139: "SMB",
    143: "IMAP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB", 161: "SNMP",
}


def _hhmmss(ts: str) -> str:
    # ISO timestamp -> HH:MM:SS
    if ts and "T" in ts:
        return ts.split("T", 1)[1][:8]
    return (ts or "")[:8]


def shape_event(ev: dict) -> dict:
    """Return {kind, phase, t, ann, data} for one raw event."""
    kind = ev.get("kind", "")
    phase = ev.get("phase", "")
    p = ev.get("payload", {}) or {}
    data: dict = {}

    if kind == "probe":
        data = {"port": p.get("port"), "state": p.get("state"), "latency_ms": p.get("latency_ms")}
    elif kind == "finding" and phase == "recon":
        data = {"port": p.get("port"), "service": p.get("service_detected") or p.get("service"),
                "severity": p.get("severity")}
    elif kind == "web_enum":
        paths = [e.get("path") for e in (p.get("paths") or [])]
        paths += [e.get("path") for e in (p.get("disclosed") or [])]
        paths += [e.get("path") for e in (p.get("linked") or [])]
        data = {"port": p.get("port"),
                "root": {"status": (p.get("root") or {}).get("status"),
                         "server": (p.get("root") or {}).get("server")},
                "paths": paths,
                "params": [f"{e.get('path')}?{e.get('param')}" for e in (p.get("params") or [])],
                "findings": [{"path": f.get("path"), "severity": f.get("severity")}
                             for f in (p.get("web_findings") or [])]}
    elif kind == "tls_posture":
        data = {"port": p.get("port"), "accepted": p.get("accepted") or [],
                "findings": [{"title": f.get("title"), "severity": f.get("severity")}
                             for f in (p.get("findings") or [])]}
    elif kind == "routing":
        data = {"modules": p.get("candidate_modules") or []}
    elif kind == "gate":
        data = {"decision": p.get("decision"), "reason": p.get("reason"),
                "module": p.get("module"), "technique": p.get("technique")}
    elif kind == "step":
        obs0 = (p.get("observations") or [""])[0]
        proves = p.get("proves") or ""
        path = ""
        if proves.startswith("discovered "):
            # "discovered /x (HTTP 200)" -> /x
            rest = proves.split(" ", 1)[1]
            path = rest.split(" ", 1)[0]
        if not path:
            # most step observations carry the path, e.g. "HTTP 404 /secret"
            m = re.search(r"(/\S*)", proves or obs0 or "")
            if m:
                path = m.group(1).rstrip(".,);")
        data = {"module": p.get("module"), "outcome": p.get("outcome"),
                "flag_claimed": p.get("flag_claimed"), "proves": proves,
                "obs": obs0, "path": path}
    elif kind == "capture":
        data = {"matched": p.get("matched"), "rate": p.get("rate"), "trials": p.get("trials")}
    elif kind in ("engage_started", "recon_done", "exploit_started", "engage_finished"):
        data = dict(p)

    return {"kind": kind, "phase": phase, "t": _hhmmss(ev.get("timestamp", "")),
            "ann": annotate(ev), "data": data}


def gap_analysis(result: dict) -> list:
    """From a finished engagement, list discovered-but-unexploited leads mapped to
    the missing capability. Each item: {lead, missing, checkpoint}."""
    gaps: list[dict] = []
    recon = result.get("recon_summary") or {}
    facts = result.get("facts") or []
    captured = result.get("captured")

    # 1) non-web services that are open but we have no capability for
    for f in recon.get("open", []) or []:
        port = f.get("port")
        svc = _SERVICES.get(port)
        web = str(f.get("service_detected") or f.get("service") or "").upper().startswith("HTTP")
        if svc and not web:
            gaps.append({
                "lead": f"Open {svc} on port {port}",
                "missing": f"no {svc} capability (credential attack / protocol client)",
                "checkpoint": "CP3 — non-web services"})

    # 2) login/admin surface discovered but no form-login / auth-bypass module
    joined = " ".join(facts).lower()
    if any(k in joined for k in ("/login", "/admin", "/signin", "login from")):
        gaps.append({
            "lead": "Login / admin surface discovered",
            "missing": "no form-login or auth-bypass module (only HTTP Basic default creds today)",
            "checkpoint": "CP3 — form auth"})

    # 3) parameters found but injection did not succeed (possible blind/second-order)
    param_facts = [x for x in facts if "parameter '" in x]
    summary = result.get("summary") or {}
    if param_facts and not captured and summary:
        gaps.append({
            "lead": f"{len(param_facts)} injectable parameter(s) found, no flag via injection",
            "missing": "single-step payloads only — blind / time-based / second-order not built",
            "checkpoint": "CP3 — deeper injection"})

    # 4) web surface exists but flag not web-reachable (classic boot2root)
    if not captured and result.get("web_surfaces", 0) and summary.get("outcome") != "flag_captured":
        gaps.append({
            "lead": "Web surface enumerated, flag not reachable over HTTP",
            "missing": "post-exploitation — recovered-credential login, shell, privilege escalation",
            "checkpoint": "CP3 — foothold + privesc"})

    # 5) no web surface at all — distinguish "unreachable" from "open but non-web"
    if result.get("status") == "no_web_surface":
        open_ports = recon.get("open", []) or []
        if not open_ports:
            gaps.append({
                "lead": "No open ports found — the target may be unreachable",
                "missing": "check the IP is correct, the device is powered/wired on the same network, "
                           "no firewall is blocking, and widen the port range",
                "checkpoint": "connectivity"})
        else:
            gaps.append({
                "lead": f"{len(open_ports)} port(s) open, but no web surface",
                "missing": "web flag capture is the shipped capability; the open service is non-web "
                           "(SSH/FTP/DB/…) — build a non-web module, or it may be HTTPS on an odd port",
                "checkpoint": "CP3 — non-web services"})

    return gaps
