"""
Offline reports generated from the verified evidence journal.

JSON is canonical; Markdown and HTML are derived views. Everything is produced
from the hash-verified trace, so a report cannot claim something the evidence
does not contain. All target-controlled text is HTML-escaped; no external
scripts, fonts, or network calls are referenced.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from red_ai.control.evidence import read_verified

_SEV_COLOR = {"critical": "#ff989b", "high": "#ffb57a", "medium": "#f2cd84",
              "low": "#84d9b2", "info": "#8fb7e8"}


def _esc(v) -> str:
    return html.escape(str(v), quote=True)


def write_report(run_dir) -> Path:
    run_dir = Path(run_dir)
    events = read_verified(run_dir / "events.jsonl")
    summary = events[-1]["payload"]
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    findings = summary.get("findings", [])
    attempts = summary.get("attempts", [])
    scope = summary.get("scope", {})
    weakest = summary.get("weakest_link")
    environment = summary.get("environment", "simulation")

    # ----- Markdown ---------------------------------------------------------
    md = [f"# RED-AI report — {summary.get('target','?')}", "",
          f"*Environment: **{environment}**. Skill: `{summary.get('skill','?')}`. "
          f"Run `{summary.get('run_id','?')}`.*", ""]
    if environment == "simulation":
        md += ["> Scripted synthetic targets. Results validate the pipeline, "
               "not the security of any production system.", ""]
    md += ["## Executive summary",
           f"- Objectives: {summary.get('coverage',{}).get('objectives_tested','?')}  "
           f"- Findings: {len(findings)}  - Outcomes: {summary.get('counts',{})}",
           f"- Stop reason: `{summary.get('halt_reason')}`  "
           f"- Queries: {summary.get('queries')}  Cost units: {summary.get('cost_units')}", ""]
    _brain = summary.get("brain") or {}
    _ov_note = (" Brain is the same model as the target (brain == target): the finding is "
                "evidence-based and independent of brain ordering, and a budget-protected "
                "coverage floor prevents ordering from starving the target's own test."
                if _brain.get("target_overlap") else "")
    md += [f"- Brain: {_brain.get('provider') or 'none (deterministic floor)'} -- "
           f"{_brain.get('model_decisions', 0)} model-decided vs {_brain.get('fallbacks', 0)} "
           f"deterministic fallback + {_brain.get('coverage_forced', 0)} coverage-forced step(s); "
           f"a refusing or absent brain changes ordering only, not the verdict.{_ov_note}", ""]
    if weakest:
        md += ["### Weakest link",
               f"**{weakest['title']}** — severity **{weakest['severity']}** "
               f"(effort to break: {weakest.get('effort_to_break')} turn(s), "
               f"reproduction: {weakest.get('reproduction_rate')}).",
               f"Why this severity: {weakest.get('severity_rationale')}", ""]
    md += ["## Findings", ""]
    if not findings:
        md += ["No actionable findings. Under the stated coverage this is "
               "'not broken in this scan', not a proof of security.", ""]
    for f in findings:
        md += [f"### {f['title']} — {f['severity']}",
               f"- Category: `{f['category']}`  Tier: {f['tier']}  Review: {f['review_state']}",
               f"- Effort to break: {f.get('effort_to_break')}  Reproduction: {f.get('reproduction_rate')}",
               f"- Severity rationale: {f.get('severity_rationale')}",
               f"- Evidence signals: {len(f.get('signals',[]))}", ""]
    md += ["## Coverage", f"```json\n{json.dumps(summary.get('coverage',{}), indent=2)}\n```", "",
           "## Authorization scope", f"```json\n{json.dumps(scope, indent=2)}\n```", "",
           "## Honesty notes",
           "- A refusal is recorded as effort spent, never as proof of safety.",
           "- Reproduction is a measured rate over replays, not a promise.",
           "- Severity is derived from stated inputs (asset impact, tier, effort); no black-box score.",
           "- Evidence is hash-linked for tamper *detection* against a trusted copy, not immutable storage."]
    (run_dir / "report.md").write_text("\n".join(md), encoding="utf-8")

    # ----- HTML -------------------------------------------------------------
    fcards = []
    for f in findings:
        color = _SEV_COLOR.get(f["severity"], "#b7bac9")
        fcards.append(
            f'<article class="card"><div class="row"><h3>{_esc(f["title"])}</h3>'
            f'<span class="badge" style="color:{color};border-color:{color}">{_esc(f["severity"])}</span></div>'
            f'<p class="meta">{_esc(f["category"])} · tier {_esc(f["tier"])} · {_esc(f["review_state"])} · '
            f'effort {_esc(f.get("effort_to_break"))} · repro {_esc(f.get("reproduction_rate"))}</p>'
            f'<p>{_esc(f.get("severity_rationale",""))}</p>'
            f'<details><summary>{len(f.get("signals",[]))} evidence signal(s)</summary>'
            f'<pre>{_esc(json.dumps(f.get("signals",[]), indent=2))}</pre></details></article>')
    tl = []
    for a in attempts:
        tl.append(f'<article class="card" data-outcome="{_esc(a["outcome"])}">'
                  f'<div class="row"><h3>{_esc(a["objective_id"])}</h3>'
                  f'<span class="badge">{_esc(a["outcome"])}</span></div>'
                  f'<p class="meta">{len(a.get("turns",[]))} turn(s) · effort '
                  f'{_esc(a.get("effort_to_break") if "effort_to_break" in a else "")}</p></article>')
    caveat = ("Scripted synthetic targets — validates the pipeline, not a real system."
              if environment == "simulation" else f"Environment: {environment}.")
    wl_html = ""
    if weakest:
        wl_html = (f'<div class="wl"><span>WEAKEST LINK</span><strong>{_esc(weakest["title"])}</strong>'
                   f'<span>{_esc(weakest["severity"])} · repro {_esc(weakest.get("reproduction_rate"))}</span></div>')
    _b = summary.get("brain") or {}
    brain_html = ""
    if _b:
        _ovt = " &middot; brain==target (coverage-floor protected)" if _b.get("target_overlap") else ""
        brain_html = (f'<div class="wl" style="background:#131a20;border-color:#2a4656">'
                      f'<span>BRAIN</span><strong>{_esc(_b.get("provider") or "none (deterministic floor)")}</strong>'
                      f'<span>{_esc(_b.get("model_decisions",0))} model-decided &middot; {_esc(_b.get("fallbacks",0))} fallback &middot; {_esc(_b.get("coverage_forced",0))} coverage-forced{_ovt}</span></div>')
    page = f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>RED-AI report</title><style>
:root{{color-scheme:dark;font-family:Segoe UI,system-ui,sans-serif;background:#0f1117;color:#e9eaf0}}
*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:1000px;margin:auto;padding:40px 24px}}
header{{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #2b2d38;padding-bottom:18px}}
.logo b{{color:#ff575c}}.logo{{font-weight:800;letter-spacing:3px}}
h1{{font-size:clamp(26px,4vw,40px);letter-spacing:-1px;margin:18px 0 4px}}
.sub{{color:#9aa0b4;font-size:13px}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}}
.stat{{background:#171922;border:1px solid #2b2d38;border-radius:10px;padding:16px}}
.stat strong{{display:block;font-size:26px;margin-top:4px}}.stat span{{color:#9aa0b4;font-size:11px;letter-spacing:1px}}
.wl{{background:#1a1420;border:1px solid #5a2a34;border-radius:10px;padding:16px;margin:8px 0 24px;display:flex;gap:14px;align-items:center}}
.wl strong{{flex:1;font-size:18px}}.wl span{{color:#ff9b9e;font-size:11px;letter-spacing:1px}}
h2{{font-size:17px;margin:28px 0 12px;color:#cfd3e2}}.card{{background:#171922;border:1px solid #2b2d38;border-radius:10px;padding:18px;margin:10px 0}}
.row{{display:flex;gap:12px;align-items:center}}h3{{margin:0;flex:1;font-size:14px}}
.badge{{font-size:12px;border:1px solid #444653;padding:4px 9px;border-radius:14px;white-space:nowrap}}
.meta{{color:#9aa0b4;font-size:12px;margin:8px 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c0e14;padding:12px;border-radius:7px;font-size:11px}}
details{{margin-top:10px;font-size:12px}}summary{{cursor:pointer;color:#b8bfd5}}footer{{margin-top:36px;color:#7c8498;font-size:11px}}
@media(max-width:720px){{.stats{{grid-template-columns:1fr 1fr}}main{{padding:22px 14px}}}}
</style><main>
<header><div class="logo"><b>RED</b>-AI</div><span class="badge">{_esc(environment)} · {_esc(summary.get("skill",""))}</span></header>
<h1>{_esc(summary.get("target","Target"))}</h1><p class="sub">{_esc(caveat)} Run {_esc(summary.get("run_id",""))}.</p>
<section class="stats">
<div class="stat"><span>FINDINGS</span><strong>{len(findings)}</strong></div>
<div class="stat"><span>OBJECTIVES</span><strong>{_esc(summary.get("coverage",{}).get("objectives_tested",0))}</strong></div>
<div class="stat"><span>QUERIES</span><strong>{_esc(summary.get("queries",0))}</strong></div>
<div class="stat"><span>STOP</span><strong style="font-size:14px">{_esc(summary.get("halt_reason",""))}</strong></div>
</section>{wl_html}{brain_html}
<h2>Findings</h2>{''.join(fcards) or '<p class="sub">No actionable findings under the stated coverage. This is "not broken in this scan", not proof of security.</p>'}
<h2>Attempt history</h2>{''.join(tl)}
<footer>Local, offline evidence. Hash-linked for tamper detection against a trusted copy, not immutable storage.<br>
A refusal is effort, never proof of safety. Reproduction is a measured rate. Severity is derived from stated inputs.</footer>
</main></html>'''
    (run_dir / "report.html").write_text(page, encoding="utf-8")
    return run_dir / "report.html"
