"""Offline recon report rendered from the VERIFIED evidence journal.

Reads the hash-checked events (not an in-memory object) so the report can only
describe what the evidence supports, then writes report.md next to the journal.
"""
from __future__ import annotations

from pathlib import Path

from red_ai.control.evidence import read_verified


def write_report(run_dir) -> Path:
    run_dir = Path(run_dir)
    events = read_verified(run_dir / "events.jsonl")
    summary = next(e["payload"] for e in events if e["kind"] == "run_finished")
    started = next(e["payload"] for e in events if e["kind"] == "run_started")
    lines = []
    w = lines.append
    w(f"# RED-AI recon report — {summary['run_id']}")
    w("")
    w(f"- Engine: `{summary['engine']}` (read-only TCP connect)")
    w(f"- Environment: **{summary['environment']}**")
    w(f"- Hosts: {', '.join(summary['hosts'])}")
    w(f"- Authorized by: {started['authorization']['authorised_by']} — "
      f"\"{started['authorization']['attestation']}\"")
    w(f"- Ports authorized: {summary['ports_authorized']} · probes: {summary['probes']} · "
      f"elapsed: {summary['elapsed_seconds']}s · outcome: `{summary['halt_reason']}`")
    w(f"- Brain: {summary['brain'] or 'none (deterministic)'}")
    w(f"- Port states: {summary['counts']}")
    w("")
    openf = summary["open"]
    if not openf:
        w("## No open ports found within the authorized scope")
        w("")
        w("A clean result means *not exposed under this coverage* — the authorized "
          "ports were closed/filtered. It is not proof the host is secure.")
    else:
        w(f"## {len(openf)} open port(s) — weakest first")
        w("")
        w("| Severity | Host | Port | Service | Repro | Remediation |")
        w("|---|---|---|---|---|---|")
        for f in openf:
            rate = f.get("reproduction_rate")
            rate_s = "n/a" if rate is None else f"{int(rate*100)}%"
            w(f"| {f['severity'].upper()} | {f['host']} | {f['port']} | {f['service']} | "
              f"{rate_s} | {f['remediation']} |")
        w("")
        w("Severity is derived from the stated service-risk table "
          "(`red_ai/recon/services.py`), not a model — each row cites its source "
          "in the evidence journal.")
        notes = [f for f in openf if f.get("analyst_note")]
        if notes:
            w("")
            w("### Analyst notes (model commentary — non-authoritative)")
            for f in notes:
                w(f"- **{f['service']}/{f['port']}**: {f['analyst_note']}")
    webf = [f for f in summary["open"] if f.get("web")]
    if webf:
        w("")
        w("### Web surface (read-only enumeration)")
        for f in webf:
            web = f["web"]; rt = web["root"]
            w(f"- **{f['host']}:{f['port']}** root HTTP {rt.get('status')} · "
              f"server `{rt.get('server') or '?'}` · title {rt.get('title') or '-'}")
            for wf in web.get("findings", []):
                w(f"    - EXPOSED `{wf['path']}` ({wf['status']}) — {wf['severity'].upper()}: {wf['meaning']}")
            for wl in web.get("leads", []):
                w(f"    - LEAD `{wl['path']}` ({wl['status']}) — {wl['meaning']} (verify)")
    idf = [f for f in summary["open"] if f.get("version") or f.get("service_detected")]
    if idf:
        w("")
        w("### Service identification (active-safe probe)")
        for f in idf:
            svc = f.get("service_detected") or f.get("service")
            ver = f.get("version") or "unknown"
            w(f"- **{f['host']}:{f['port']}** -> {svc} `{ver}`")
            for lead in f.get("version_leads", []):
                w(f"    - LEAD (verify, not confirmed): {lead}")
    w("")
    out = run_dir / "report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out
