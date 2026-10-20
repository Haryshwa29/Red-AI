"""Turn raw engagement events into human, educational feed lines.

The dashboard is meant to teach the CTF method, so each event becomes a short
plain-English line tagged with a stage (authorize / recon / enumerate / exploit /
capture) and a level (info / good / warn / finding / flag). Noisy events (closed
ports, every allow decision) are dropped. Tolerant by design: unknown shapes fall
back to a generic line rather than erroring."""
from __future__ import annotations

_MODULE_NAMES = {
    "native.content_discovery": "content discovery",
    "native.web_flag_hunt": "content / flag hunt",
    "native.http_basic_auth": "default-credential check",
    "native.lfi_read": "LFI / path traversal",
    "native.sqli_read": "SQL injection",
    "native.cmd_injection": "command injection",
    "native.http_flag_read": "direct file read",
}


def _mod(mid: str) -> str:
    return _MODULE_NAMES.get(mid, mid)


def annotate(ev: dict) -> "dict | None":
    """Map one event to {stage, level, text} for the feed, or None to drop it."""
    kind = ev.get("kind", "")
    p = ev.get("payload", {}) or {}
    phase = ev.get("phase", "")

    # --- engage-level phase markers (synthetic) --------------------------
    if kind == "engage_started":
        return _line("authorize", "good",
                     f"Authorized — starting engagement on {p.get('target')} "
                     f"(ports {p.get('ports')}), operator '{p.get('operator')}'.")
    if kind == "recon_done":
        return _line("enumerate", "info",
                     f"Recon complete: {p.get('web_surfaces', 0)} web surface(s) found, "
                     f"{p.get('facts', 0)} lead(s) to try.")
    if kind == "exploit_started":
        return _line("exploit", "info",
                     f"Exploiting: trying authorized techniques against "
                     f"{p.get('surfaces', 0)} surface(s).")
    if kind == "engage_finished":
        if p.get("status") == "captured":
            return _line("capture", "flag",
                         f"FLAG CAPTURED → {p.get('flag_value') or '(file read)'}  "
                         f"(outcome: {p.get('outcome')}, {p.get('steps')} steps).")
        if p.get("status") == "no_web_surface":
            return _line("enumerate", "warn",
                         "No reachable web surface — nothing to hunt. "
                         "(Web flag capture is the capability shipped today.)")
        return _line("capture", "warn",
                     f"No flag captured ({p.get('outcome')}). Not broken in "
                     f"{p.get('steps')} step(s) — signal, not 'secure'.")

    # --- recon phase -----------------------------------------------------
    if phase == "recon":
        if kind == "run_started":
            hosts = ", ".join(p.get("hosts", []) or [])
            return _line("recon", "info", f"Recon started on {hosts} ({p.get('ports')} ports).")
        if kind == "scan_started":
            return _line("recon", "info", f"Scanning {p.get('authorized_probes')} authorized probe(s)…")
        if kind == "probe":
            if p.get("state") == "open":
                return _line("recon", "good", f"Port {p.get('port')} is OPEN ({p.get('latency_ms')}ms).")
            return None  # closed/filtered ports are noise
        if kind == "web_enum":
            root = p.get("root", {}) or {}
            wf = p.get("web_findings", []) or []
            msg = (f"Web on port {p.get('port')}: root HTTP {root.get('status')}"
                   f"{(' · ' + root.get('server')) if root.get('server') else ''}"
                   f" · {len(p.get('paths', []) or [])} path(s) probed")
            line = _line("enumerate", "info", msg)
            if wf:
                # surface the first exposure finding prominently
                f0 = wf[0]
                return [line, _line("enumerate", "finding",
                        f"Exposed: {f0.get('path')} ({f0.get('meaning')}) — severity {f0.get('severity')}.")]
            return line
        if kind == "finding":
            svc = p.get("service_detected") or p.get("service") or "unknown"
            return _line("recon", "info", f"Port {p.get('port')}: {svc}.")
        if kind == "tls_posture":
            tf = p.get("findings") or []
            if not tf:
                return _line("enumerate", "good", f"TLS on {p.get('port')}: no weak posture found.")
            worst = tf[0]
            return _line("enumerate", "finding",
                         f"TLS weakness on {p.get('port')}: {worst.get('title')} "
                         f"(+{len(tf)-1} more)" if len(tf) > 1 else
                         f"TLS weakness on {p.get('port')}: {worst.get('title')}")
        return None  # reproduction, run_finished, etc.

    # --- exploit phase ---------------------------------------------------
    if phase == "exploit":
        if kind == "routing":
            mods = ", ".join(_mod(m) for m in (p.get("candidate_modules", []) or []))
            return _line("exploit", "info", f"Techniques queued: {mods}.")
        if kind == "gate":
            if p.get("decision") == "deny":
                return _line("exploit", "warn",
                             f"Gate denied {p.get('technique')} ({p.get('reason')}).")
            return None  # allows are expected; don't flood the feed
        if kind == "step":
            mod = _mod(p.get("module", ""))
            if p.get("flag_claimed"):
                return _line("exploit", "good", f"{mod}: possible flag found — verifying…")
            outcome = p.get("outcome")
            if outcome == "no_effect":
                return None  # "tried, nothing" is noise; show only progress
            proves = p.get("proves") or ""
            obs = (p.get("observations") or [""])[0]
            detail = proves or obs
            level = "finding" if outcome == "advanced" else "info"
            return _line("exploit", level, f"{mod}: {outcome}"
                         + (f" — {detail}" if detail else ""))
        if kind == "capture":
            if p.get("matched"):
                return _line("capture", "good",
                             f"Capture verified — reproduced {int(p.get('rate', 0)*100)}% "
                             f"over {p.get('trials')} trial(s).")
            return None
        return None

    return None


def _line(stage: str, level: str, text: str) -> dict:
    return {"stage": stage, "level": level, "text": text}
