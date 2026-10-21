"""RED-AI operator CLI. Offline; simulation targets only in this release.

Commands:
  init-demo            create the local operator key and signed demo scopes
  demo [--open]        run naive/guarded/hardened simulations + reports
  run --scope F --level L   run one signed scope against a simulation level
  report RUN_DIR       regenerate reports from a run's evidence
  verify RUN_DIR       verify the evidence hash chain
  doctor               validate config/skills/signing WITHOUT running a scan
  stop | resume        operator kill switch (persists until resume)
"""
from __future__ import annotations

import argparse
from datetime import timedelta
import json
import os
from pathlib import Path
import secrets
import sys

from red_ai.contracts.domain import AssetCategory
from red_ai.contracts.scope import Scope, now, sign_scope, verify_scope
from red_ai.detection.canary import make_canary
from red_ai.onboarding.profile import build_profile
from red_ai.onboarding.objectives import ProfileObjectiveGenerator
from red_ai.intelligent import skills
from red_ai.intelligent.providers import MockProvider, make_provider, ProviderError
from red_ai.targets.simulation import SimulationAdapter, _LEVELS
from red_ai.control.controller import Controller, new_run_path
from red_ai.control.memory import CaseStore
from red_ai.control.identity import (
    Keyring, DEFAULT_OPERATOR, AccessDenied, authorize_invocation, authorize_read,
)
from red_ai.learning import propose_upgrades, write_upgrade_review
from red_ai.engine import ControlPlane, Engagement
from red_ai.reporting.report import write_report

LEVELS = tuple(_LEVELS)


def key_at(root: Path, create: bool = False) -> bytes:
    path = root / "operator.key"
    if not path.exists() and create:
        root.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as h:
            h.write(secrets.token_bytes(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    if not path.exists():
        raise ValueError("No operator key. Run: red_ai init-demo")
    return path.read_bytes()


def demo_scope(level: str) -> Scope:
    return Scope(
        scope_id=f"sim-{level}", owner="Local operator", authorised_by="Local operator",
        target=f"sim-{level}", environment="simulation",
        valid_from=(now() - timedelta(minutes=1)).isoformat(),
        valid_until=(now() + timedelta(hours=24)).isoformat(),
        max_queries=300, max_cost_units=400, max_seconds=300, replays=3, confirmations=1,
        operator_id=DEFAULT_OPERATOR, readers=(DEFAULT_OPERATOR,),
    )


def init_demo(root: Path) -> None:
    key = key_at(root, create=True)
    for level in LEVELS:
        (root / f"sim-{level}.scope.json").write_text(
            json.dumps(sign_scope(demo_scope(level), key), indent=2), encoding="utf-8")


def demo_profile():
    cny = make_canary(AssetCategory.SYSTEM_PROMPT, "system_prompt")
    profile, _ = build_profile(
        name="Acme Bank SupportBot", industry="retail bank",
        bot_purpose="customer support for accounts, cards and payments",
        authorised_by="Local operator", environment="simulation", planted_canaries=[cny])
    return profile


def execute(scope: Scope, root: Path, level: str, profile=None, use_memory: bool = False, adapter=None):
    profile = profile or demo_profile()
    objectives = ProfileObjectiveGenerator().generate(profile)
    skill = skills.get("prompt_injection")
    memory = []
    if use_memory:
        store = CaseStore(root / "memory.sqlite")
        try:
            memory = store.retrieve(profile, scope.environment)
        finally:
            store.close()
        print(f"    memory: {len(memory)} reviewed case(s) influencing order")
    out = new_run_path(root)
    adapter = adapter or SimulationAdapter(level, profile)
    provider = make_provider()  # None unless RED_AI_MODEL_URL is set -> deterministic planner
    if provider is not None:
        print(f"    brain: {provider.get_model_info()['name']} (model-driven technique selection)")
    summary = Controller(scope, adapter, out, skill, cancel_file=root / "STOP", provider=provider).run(profile, objectives, memory=memory)
    report = write_report(out)
    print(f"[{level}] outcomes={summary['counts']} findings={len(summary['findings'])} "
          f"stop={summary['halt_reason']} queries={summary['queries']}")
    print(f"    report: {report.resolve()}")
    return out


def execute_engine(scope: Scope, root: Path, level: str, profile=None):
    """Run one engagement through the unified control plane (knowledge + routing
    + hypotheses + delegated execution + learning). Old `run` path is untouched."""
    profile = profile or demo_profile()
    objectives = ProfileObjectiveGenerator().generate(profile)
    provider = make_provider()
    eng = Engagement(kind="llm", scope=scope, profile=profile,
                     adapter=SimulationAdapter(level, profile),
                     objectives=tuple(objectives), provider=provider,
                     cancel_file=root / "STOP")
    cp = ControlPlane(root, provider=provider, cancel_file=root / "STOP",
                      case_store_path=root / "memory.sqlite")
    out = cp.run(eng)
    sb = out["capability_summary"]
    sb_counts = sb.get("counts", {})
    scoreboard = {"supported": sum(1 for h in out["hypotheses"] if h["status"] == "supported"),
                  "formed": len(out["hypotheses"])}
    print(f"[control-plane:{level}] capability={out['capability']} "
          f"routing={out['routing']['ordering_source']}")
    print(f"    hypotheses supported={scoreboard['supported']}/{scoreboard['formed']}  "
          f"findings={len(sb['findings'])}  outcomes={sb_counts}  "
          f"quarantined_evidence={out['evidence_quarantined']}")
    print(f"    knowledge_hash={out['knowledge_hash'][:16]}  "
          f"upstream_candidates={out['learning'].get('upstream_candidates')}")
    if out.get("report"):
        print(f"    report: {Path(out['report']).resolve()}")
    print(f"    manifest: {Path(out['manifest']).resolve()}")
    return out


def doctor(root: Path) -> None:
    print("RED-AI doctor — configuration and readiness (no scan executed)")
    ok = True
    try:
        key = key_at(root, create=True)
        s = demo_scope("naive")
        assert verify_scope(sign_scope(s, key), key) == s
        print("  [ok] operator key present and scope sign/verify round-trips")
    except Exception as e:
        ok = False; print(f"  [FAIL] scope signing: {e}")
    try:
        names = [s.id for s in skills.all_skills()]
        print(f"  [ok] skills registered: {names}")
    except Exception as e:
        ok = False; print(f"  [FAIL] skill registry: {e}")
    try:
        from red_ai.engine import default_capabilities, CapabilityRouter
        caps = default_capabilities()
        CapabilityRouter(caps)
        print(f"  [ok] control plane: {len(caps)} routable capability(ies): {[c.id for c in caps]}")
    except Exception as e:
        ok = False; print(f"  [FAIL] control plane: {e}")
    try:
        info = MockProvider().get_model_info()
        print(f"  [ok] model provider seam: {info['name']} (offline)")
    except Exception as e:
        ok = False; print(f"  [FAIL] provider: {e}")
    provider = make_provider()
    if provider is None:
        print("  [ok] brain: none configured -> deterministic planner (set RED_AI_MODEL_URL to attach a local model)")
    else:
        healthy, detail = provider.health()
        tag = "ok" if healthy else "warn"
        print(f"  [{tag}] brain {provider.get_model_info()['name']}: {detail}")
    try:
        print(f"  [ok] operators registered: {Keyring(root).ids() or '(none)'}")
    except Exception as e:
        print(f"  [warn] operators: {e}")
    print(f"  [ok] simulation levels available: {list(LEVELS)}")
    print("READY" if ok else "NOT READY")
    if not ok:
        raise SystemExit(1)


def _authorize_run_read(root: Path, run_dir: Path, operator_id: str) -> None:
    """Need-to-know gate for a run's artifacts: read the run's own scope from its
    evidence and refuse an operator who is not an authorized reader. A run whose
    scope carries no reader restriction is legacy-open (stated limit)."""
    from red_ai.control.evidence import read_verified
    events = read_verified(Path(run_dir) / "events.jsonl")
    scope_dict = events[-1]["payload"].get("scope") if events else None
    if not isinstance(scope_dict, dict):
        return
    authorize_read(Scope.from_dict(scope_dict), operator_id, Keyring(root))


def cmd_engage(root: Path, args) -> int:
    """Live network engagement: recon -> bridge -> exploit -> capture, one command.

    This is the entrypoint an operator runs ON A MACHINE WITH A ROUTE TO THE TARGET
    (e.g. connected to the TryHackMe/HackTheBox VPN). It authorizes the engagement
    up front (operator identity + owner attestation + environment), discovers the
    surface with recon, promotes it across the bridge, then runs the gated exploit
    engine to capture the declared flag FORM. Every step is gated and every event
    hash-linked; the brain is not involved (pure deterministic capability)."""
    from red_ai.engage import engage_core, EngageError

    verbose = not args.quiet
    if verbose:
        print(f"[{now().strftime('%H:%M:%S')}] [engage] target={args.target} ports={args.ports} "
              f"env={args.env} operator={args.operator}", flush=True)
    try:
        res = engage_core(root=root, target=args.target, ports=args.ports,
                          flag_pattern=args.flag_pattern, env=args.env,
                          attestation=args.attestation, allow_production=args.allow_production,
                          max_steps=args.max_steps, max_seconds=args.max_seconds,
                          operator=args.operator, audit=args.audit, verbose=verbose)
    except EngageError as e:
        print(f"RED-AI: {e}", file=sys.stderr)
        return 1

    if res["status"] == "no_web_surface":
        print("RED-AI: no reachable web surface discovered -- nothing to hunt. "
              "(Web flag capture is the capability shipped today; see docs/THM_RUNBOOK.md.)")
        print(f"    recon evidence: {Path(res['recon_out']).resolve()}")
        return 0

    print()
    xsum = res.get("summary") or {}
    if res["captured"] and args.audit:
        vulns = xsum.get("findings") or []
        print(f"RED-AI: {len(vulns)} VULNERABILITIES CONFIRMED on {args.target} (audit mode)")
        for f in vulns:
            print(f"    • {str(f.get('technique','')).replace('_',' '):18} "
                  f"{f.get('path',''):22} -> {f.get('flag_value') or '(read)'}")
    elif res["captured"]:
        print(f"RED-AI: FLAG CAPTURED on {args.target}  ->  {res['flag_value'] or '(file read)'}")
        print(f"    reproduced: {res['rate']:.0%}  ·  steps: {res['steps']}")
    else:
        print(f"RED-AI: no flag captured ({res['outcome']}). "
              f"Not broken in {res['steps']} step(s) -- this is signal, not 'secure'.")
    print(f"    recon evidence:   {Path(res['recon_out']).resolve()}")
    print(f"    exploit evidence: {Path(res['exploit_out']).resolve()}")
    print(f"    verify:  python -m red_ai verify {res['exploit_out']}")
    return 0


def cmd_crypto(args) -> int:
    """Audit authorized ciphertext samples for crypto misuse and recover plaintext
    as hard proof. Runs offline; proves weakness on the client's own data."""
    from red_ai.crypto.analyze import analyze_samples
    lines = [ln for ln in args.samples.read_text(encoding="utf-8").splitlines() if ln.strip()]
    rsa = None
    if args.rsa_n and args.rsa_e and args.rsa_c:
        rsa = {"n": args.rsa_n, "e": args.rsa_e, "c": args.rsa_c}
    rep = analyze_samples(lines, rsa=rsa)
    print(f"RED-AI crypto audit — {rep['samples']} sample(s)")
    print(f"  VERDICT: {rep['verdict']}\n")
    if not rep["findings"]:
        print("  No weakness demonstrated. (Absence of a break is NOT a proof of safety.)")
        return 0
    for f in rep["findings"]:
        print(f"  [{f['severity'].upper():8}] {f['class']} — {f['method']}")
        if f.get("recovered"):
            print(f"     RECOVERED PLAINTEXT (proof): {f['recovered']!r}")
        print(f"     evidence   : {f['evidence']}")
        print(f"     remediation: {f['remediation']}")
        print(f"     reference  : {f['reference']}  (the why — not the proof)\n")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="red_ai", description="RED-AI — offline, evidence-first AI security testing")
    p.add_argument("--data-dir", type=Path, default=Path("data"))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init-demo")
    d = sub.add_parser("demo"); d.add_argument("--open", action="store_true")
    r = sub.add_parser("run"); r.add_argument("--scope", type=Path, required=True); r.add_argument("--level", choices=LEVELS, default="naive"); r.add_argument("--memory", action="store_true"); r.add_argument("--operator", default=os.environ.get("RED_AI_OPERATOR", DEFAULT_OPERATOR)); r.add_argument("--target-url"); r.add_argument("--target-api", choices=["ollama", "openai"], default="ollama"); r.add_argument("--target-model"); r.add_argument("--target-system"); r.add_argument("--target-key")
    rep = sub.add_parser("report"); rep.add_argument("run_dir", type=Path); rep.add_argument("--operator", default=os.environ.get("RED_AI_OPERATOR", DEFAULT_OPERATOR))
    ver = sub.add_parser("verify"); ver.add_argument("run_dir", type=Path); ver.add_argument("--operator", default=os.environ.get("RED_AI_OPERATOR", DEFAULT_OPERATOR))
    pr = sub.add_parser("promote"); pr.add_argument("run_dir", type=Path); pr.add_argument("--finding", required=True); pr.add_argument("--reviewer", required=True); pr.add_argument("--approve", action="store_true", required=True, help="Attest you reviewed the evidence")
    rv = sub.add_parser("revoke"); rv.add_argument("case_id"); rv.add_argument("--reviewer", required=True)
    ln = sub.add_parser("learn", help="propose generic V0 upgrades from local reviewed memory (human-gated)")
    ln.add_argument("--memory", type=Path, default=None, help="reviewed-memory sqlite (default: <data>/memory.sqlite)")
    ln.add_argument("--min", type=int, default=2, dest="min_targets", help="min distinct targets for a candidate")
    ln.add_argument("--export", action="store_true", help="write upstream_candidates.json + UPGRADE_REVIEW.md")
    ln.add_argument("--out", type=Path, default=None, help="output dir for --export (default: <data>/upgrades)")
    eng = sub.add_parser("engine", help="run through the unified control plane (knowledge+routing+hypotheses+learning)")
    eng.add_argument("--scope", type=Path, required=True)
    eng.add_argument("--level", choices=LEVELS, default="naive")
    eng.add_argument("--operator", default=os.environ.get("RED_AI_OPERATOR", DEFAULT_OPERATOR))
    en = sub.add_parser("engage", help="live network engagement: recon -> exploit -> capture the flag (authorized)")
    en.add_argument("--target", required=True, help="host or IP of the authorized target (e.g. a THM/HTB box)")
    en.add_argument("--ports", default="80,8080,8000,8888,443", help="ports to recon (default common web ports)")
    en.add_argument("--flag-pattern", default=r"(?:THM|FLAG|HTB|flag)\{[^}]{1,128}\}|\b[0-9a-f]{32}\b",
                    help="regex describing the flag FORM to capture (default: THM/HTB/flag{...} or a 32-hex)")
    en.add_argument("--env", choices=["owned", "authorized_lab", "production"], default="authorized_lab")
    en.add_argument("--attestation", default="Authorized lab/CTF engagement (operator-attested).",
                    help="authorization statement recorded in the evidence")
    en.add_argument("--allow-production", action="store_true", help="required to engage a production target")
    en.add_argument("--max-steps", type=int, default=400)
    en.add_argument("--max-seconds", type=int, default=900)
    en.add_argument("--audit", action="store_true", help="find ALL vulnerabilities (don't stop at the first flag)")
    en.add_argument("--operator", default=os.environ.get("RED_AI_OPERATOR", DEFAULT_OPERATOR))
    en.add_argument("--quiet", action="store_true", help="suppress the live progress stream")
    cr = sub.add_parser("crypto", help="crypto-misuse audit: recover plaintext from weak sample ciphertexts")
    cr.add_argument("--samples", type=Path, required=True, help="file with one ciphertext sample per line (hex/base64/raw)")
    cr.add_argument("--rsa-n", help="RSA modulus (dec or 0x-hex) for a weak-RSA check")
    cr.add_argument("--rsa-e", help="RSA public exponent")
    cr.add_argument("--rsa-c", help="RSA ciphertext integer")
    web = sub.add_parser("web", help="launch the local dashboard (opens in your browser)")
    web.add_argument("--host", default="127.0.0.1", help="bind address (default localhost; keep it local)")
    web.add_argument("--port", type=int, default=8787)
    web.add_argument("--no-open", action="store_true", help="do not auto-open the browser")
    web.add_argument("--open", action="store_true", help="(default) open the dashboard in your browser")
    sub.add_parser("install", help="create a click-to-open shortcut for your OS (Start menu / app menu)")
    op = sub.add_parser("operator", help="manage operator identities (keys)")
    op.add_argument("op_action", choices=["add", "list"]); op.add_argument("op_id", nargs="?")
    sub.add_parser("doctor")
    sub.add_parser("stop"); sub.add_parser("resume")
    args = p.parse_args(argv)
    root = args.data_dir.resolve(); root.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "init-demo":
            init_demo(root); print(f"Signed demo scopes written to {root} (valid 24h).")
        elif args.command == "demo":
            init_demo(root); profile = demo_profile(); last = None
            key = key_at(root)
            for level in LEVELS:
                scope = verify_scope(json.loads((root / f"sim-{level}.scope.json").read_text(encoding="utf-8")), key)
                last = execute(scope, root, level, profile)
            if args.open and last:
                import webbrowser; webbrowser.open((last / "report.html").as_uri())
        elif args.command == "run":
            keyring = Keyring(root)
            scope = verify_scope(json.loads(args.scope.read_text(encoding="utf-8")), keyring.key(args.operator))
            authorize_invocation(scope, args.operator, keyring)
            adapter = None
            if args.target_url:
                if not args.target_model:
                    print("--target-url requires --target-model", file=sys.stderr); return 1
                from red_ai.targets.http_target import HTTPTargetAdapter
                adapter = HTTPTargetAdapter(base_url=args.target_url, model=args.target_model,
                                            api=args.target_api, system=args.target_system,
                                            api_key=args.target_key)
                print(f"    target: {adapter.name} @ {args.target_url} (LIVE endpoint)")
            execute(scope, root, args.level, use_memory=args.memory, adapter=adapter)
        elif args.command == "report":
            _authorize_run_read(root, args.run_dir, args.operator)
            print("report:", write_report(args.run_dir).resolve())
        elif args.command == "verify":
            _authorize_run_read(root, args.run_dir, args.operator)
            from red_ai.control.evidence import read_verified
            ev = read_verified(args.run_dir / "events.jsonl")
            print(f"Verified {len(ev)} ordered events. Final hash: {ev[-1]['hash']}")
        elif args.command == "promote":
            store = CaseStore(root / "memory.sqlite")
            try:
                case_id = store.promote((args.run_dir / "events.jsonl").resolve(), args.finding, args.reviewer)
                print(f"Promoted reviewed case: {case_id}")
            finally:
                store.close()
        elif args.command == "revoke":
            store = CaseStore(root / "memory.sqlite")
            try:
                store.revoke(args.case_id, args.reviewer)
                print("Case revoked; retained in audit history, excluded from retrieval.")
            finally:
                store.close()
        elif args.command == "learn":
            mem = args.memory or (root / "memory.sqlite")
            if not mem.exists():
                print(f"No reviewed memory at {mem}. Promote findings first (red_ai promote).")
                return 0
            store = CaseStore(mem)
            try:
                candidates = propose_upgrades(store, min_distinct_targets=args.min_targets)
            finally:
                store.close()
            print(f"{len(candidates)} upstream candidate(s) proposed (>= {args.min_targets} distinct targets).")
            for c in candidates:
                print(f"  {c.candidate_id}  {c.generic.category}/{c.generic.technique}"
                      f"  (obs={c.provenance.observations}, targets={c.provenance.distinct_targets})")
            if args.export:
                out_dir = args.out or (root / "upgrades")
                paths = write_upgrade_review(candidates, out_dir)
                print(f"    upstream (generic only): {paths['upstream_json'].resolve()}")
                print(f"    review report (keep local): {paths['review_md'].resolve()}")
        elif args.command == "engine":
            keyring = Keyring(root)
            scope = verify_scope(json.loads(args.scope.read_text(encoding="utf-8")), keyring.key(args.operator))
            authorize_invocation(scope, args.operator, keyring)
            execute_engine(scope, root, args.level)
        elif args.command == "engage":
            return cmd_engage(root, args)
        elif args.command == "web":
            from red_ai.web.server import serve
            serve(host=args.host, port=args.port, data_dir=root, open_browser=not args.no_open)
        elif args.command == "crypto":
            return cmd_crypto(args)
        elif args.command == "install":
            from red_ai.install import install_shortcut
            res = install_shortcut()
            osname = {"Windows": "Windows Start menu", "Darwin": "macOS Applications",
                      "Linux": "Linux app menu"}.get(res["system"], res["system"])
            print(f"RED-AI: installed a click-to-open launcher for {osname}:")
            for p in res["created"]:
                print(f"    {p}")
            print("Click 'RED-AI Dashboard' to open the dashboard in your browser.")
        elif args.command == "operator":
            keyring = Keyring(root)
            if args.op_action == "add":
                if not args.op_id:
                    print("operator add requires an id", file=sys.stderr); return 1
                keyring.create(args.op_id)
                print(f"Created operator '{args.op_id}' (key stored locally, chmod 600).")
            else:
                ids = keyring.ids()
                print("Operators:", ", ".join(ids) if ids else "(none)")
        elif args.command == "doctor":
            doctor(root)
        elif args.command == "stop":
            (root / "STOP").touch(); print("Kill switch active; runs will halt and future runs are denied.")
        elif args.command == "resume":
            (root / "STOP").unlink(missing_ok=True); print("Kill switch cleared.")
    except (ValueError, KeyError, TypeError, OSError, AccessDenied) as e:
        print(f"RED-AI: {e}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
