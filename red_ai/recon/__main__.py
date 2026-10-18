"""Recon engine CLI — authorized network reconnaissance (separate from the LLM
engine). Offline; it talks only to the hosts your signed scope authorizes.

  python -m red_ai.recon init  --host 127.0.0.1 --ports 1-1024 --attest "I own this host"
  python -m red_ai.recon scan  --scope data/recon/<id>.scope.json
  python -m red_ai.recon verify data/recon/runs/<run>
"""
from __future__ import annotations

import argparse
from datetime import timedelta
import json
from pathlib import Path
import sys

from red_ai.contracts.scope import now
from red_ai.cli import key_at  # reuse the same operator key machinery
from red_ai.recon.scope import ReconScope, sign_recon_scope, verify_recon_scope
from red_ai.recon.controller import ReconController
from red_ai.recon.report import write_report
from red_ai.intelligent.providers import make_provider


def _run_root(root: Path) -> Path:
    return root / "runs" / (now().strftime("%Y%m%dT%H%M%S") + "-recon")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="red_ai.recon")
    p.add_argument("--data-dir", type=Path, default=Path("data") / "recon")
    sub = p.add_subparsers(dest="command", required=True)
    i = sub.add_parser("init")
    i.add_argument("--host", action="append", required=True, help="repeatable")
    i.add_argument("--ports", default="1-1024")
    i.add_argument("--attest", required=True, help="your authorization statement")
    i.add_argument("--env", default="owned", choices=["owned", "authorized_lab", "production"])
    i.add_argument("--allow-production", action="store_true")
    i.add_argument("--identify", action="store_true", help="also identify service/version on open ports (active-safe probe)")
    i.add_argument("--web", action="store_true", help="also enumerate the web surface of open ports (read-only GETs)")
    i.add_argument("--out", type=Path, default=None, help="where to write the signed scope")
    s = sub.add_parser("scan"); s.add_argument("--scope", type=Path, required=True); s.add_argument("--verbose", "-v", action="store_true", help="stream each step live to the terminal")
    v = sub.add_parser("verify"); v.add_argument("run_dir", type=Path)
    args = p.parse_args(argv)
    root = args.data_dir.resolve(); root.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "init":
            key = key_at(root.parent, create=True)
            scope = ReconScope.build(
                scope_id=f"recon-{now().strftime('%Y%m%dT%H%M%S')}",
                owner="Local operator", authorised_by="Local operator",
                hosts=args.host, ports=args.ports, attestation=args.attest,
                owner_attested=True, environment=args.env,
                allow_production=args.allow_production,
                identify_services=args.identify,
                enumerate_web=args.web,
                valid_from=(now() - timedelta(minutes=1)).isoformat(),
                valid_until=(now() + timedelta(hours=2)).isoformat())
            path = args.out or (root / f"{scope.scope_id}.scope.json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(sign_recon_scope(scope, key), indent=2), encoding="utf-8")
            print(f"Signed recon scope: {path}")
            print(f"  hosts={list(scope.hosts)} ports={len(scope.ports)} env={scope.environment}")
        elif args.command == "scan":
            key = key_at(root.parent)
            scope = verify_recon_scope(json.loads(args.scope.read_text(encoding="utf-8")), key)
            provider = make_provider()
            if provider is not None:
                print(f"  brain: {provider.get_model_info()['name']} (annotation only)")
            out = _run_root(root)
            summary = ReconController(scope, out, provider=provider, cancel_file=root / "STOP", verbose=args.verbose).run()
            report = write_report(out)
            print(f"[recon] {summary['halt_reason']} probes={summary['probes']} "
                  f"open={len(summary['open'])} states={summary['counts']}")
            for f in summary["open"]:
                ver = f" [{f.get('service_detected') or f['service']} {f['version']}]" if f.get("version") else ""
                print(f"    {f['severity'].upper():8} {f['host']}:{f['port']} {f['service']}{ver}")
            print(f"    report: {report.resolve()}")
        elif args.command == "verify":
            from red_ai.control.evidence import read_verified
            ev = read_verified(args.run_dir / "events.jsonl")
            print(f"Verified {len(ev)} ordered events. Final hash: {ev[-1]['hash']}")
    except (ValueError, KeyError, TypeError, OSError) as e:
        print(f"RED-AI recon: {e}", file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
