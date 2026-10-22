"""Recon engagement controller: the deterministic loop for authorized scanning.

Mirrors the LLM controller's discipline on the network side. It opens a
hash-linked journal, gates every (host, port) against the signed ReconScope
before a socket opens, scans only authorized targets, derives severity from the
stated service table, optionally lets the brain annotate (never score), re-probes
open ports to report a stable result, and writes a verifiable record.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from red_ai.contracts.scope import now, timestamp
from red_ai.control.evidence import Journal
from red_ai.recon.scope import ReconScope
from red_ai.recon.gate import recon_gate, HALTING
from red_ai.recon.scanner import TcpConnectScanner, PortState
from red_ai.recon.services import classify
from red_ai.recon.analyst import annotate


class ReconController:
    def __init__(self, scope: ReconScope, output, *, scanner=None, provider=None,
                 cancel_file=None, banner_opener=None, verbose=False, web_opener=None,
                 on_event=None):
        self.scope = scope
        self.banner_opener = banner_opener
        self.verbose = verbose
        self.web_opener = web_opener
        self.on_event = on_event
        self.output = Path(output)
        self.scanner = scanner or TcpConnectScanner(
            timeout_ms=scope.timeout_ms, concurrency=scope.concurrency)
        self.provider = provider
        self.cancel_file = Path(cancel_file) if cancel_file else None
        self.probes = 0
        self.started = 0.0

    def _cancelled(self) -> bool:
        return bool(self.cancel_file and self.cancel_file.exists())

    def _expired(self) -> bool:
        return now() >= timestamp(self.scope.valid_until)

    def run(self) -> dict:
        self.started = time.monotonic()
        self.output.mkdir(parents=True, exist_ok=False)
        run_id = self.output.name
        journal = Journal(self.output / "events.jsonl", on_event=self.on_event)
        journal.append("run_started", {
            "run_id": run_id, "engine": "recon.tcp_connect", "scope": self.scope,
            "hosts": list(self.scope.hosts), "ports": len(self.scope.ports),
            "environment": self.scope.environment,
            "authorization": {"authorised_by": self.scope.authorised_by,
                              "attestation": self.scope.attestation,
                              "owner_attested": self.scope.owner_attested},
            "read_only": "TCP connect scan: handshake and close; no payloads, no changes",
            "control": "every probe gated against signed scope; model never authorizes or scores",
        })
        halt: Optional[str] = None
        authorized: list[tuple[str, int]] = []

        # Gate the full target matrix first; only authorized probes are scanned.
        for host in self.scope.hosts:
            for port in self.scope.ports:
                reason = recon_gate(self.scope, host, port, self.probes,
                                    time.monotonic() - self.started, self._cancelled())
                if reason in HALTING:
                    halt = reason
                    break
                if reason:
                    journal.append("gate", {"decision": "deny", "reason": reason,
                                            "host": host, "port": port})
                    continue
                authorized.append((host, port))
                self.probes += 1
            if halt:
                break

        results = []
        if not halt:
            journal.append("scan_started", {"authorized_probes": len(authorized)})
            if self.verbose:
                print(f"[{now().strftime('%H:%M:%S')}] [recon] scanning {len(authorized)} authorized target(s)...", flush=True)
            results = self.scanner.scan(authorized)
            for r in results:
                journal.append("probe", {"host": r.host, "port": r.port,
                                         "state": r.state, "latency_ms": r.latency_ms,
                                         "detail": r.detail})
                if self.verbose and r.state is PortState.OPEN:
                    print(f"[{now().strftime('%H:%M:%S')}] [recon]   PROBE {r.host}:{r.port} -> {r.state.value} ({r.latency_ms}ms)", flush=True)

        findings = self._findings(results, journal)
        repro = self._reproduce(findings, journal) if not halt else {}
        for f in findings:
            f["reproduction_rate"] = repro.get((f["host"], f["port"]))

        summary = {
            "run_id": run_id, "engine": "recon.tcp_connect",
            "environment": self.scope.environment, "hosts": list(self.scope.hosts),
            "ports_authorized": len(self.scope.ports), "probes": self.probes,
            "halt_reason": halt or "scan_complete",
            "open": [f for f in findings],
            "counts": {s.value: sum(1 for r in results if r.state is s) for s in PortState},
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "brain": (self.provider.get_model_info().get("name") if self.provider else None),
        }
        journal.append("run_finished", summary)
        journal.close()
        return summary

    def _findings(self, results, journal) -> list[dict]:
        findings = []
        for r in results:
            if r.state is not PortState.OPEN:
                continue
            service, severity, remediation = classify(r.port, self.scope.environment)
            note = annotate(self.provider, r.host, r.port, service,
                            severity.value, self.scope.environment)
            finding = {
                "host": r.host, "port": r.port, "service": service,
                "severity": severity.value, "severity_rank": severity.rank,
                "severity_source": f"services.SERVICE_RISK[{r.port}] + environment={self.scope.environment}",
                "remediation": remediation, "analyst_note": note,
            }
            if self.scope.identify_services:
                from red_ai.recon.banner import grab_banner, fingerprint, exposure_leads, unauth_exposure
                raw = grab_banner(r.host, r.port, self.scope.timeout_ms, self.banner_opener)
                svc_detected, version = fingerprint(raw) if raw else (None, None)
                leads = exposure_leads(version) + unauth_exposure(svc_detected, version)
                # SMB/RDP don't volunteer a banner: a read-only negotiate probe tells us
                # whether SMBv1 is enabled (EternalBlue) or RDP lacks NLA (BlueKeep).
                from red_ai.recon.smb_rdp import fingerprint_smb_rdp
                sr = fingerprint_smb_rdp(r.host, r.port, self.scope.timeout_ms)
                if sr and sr.get("service"):
                    svc_detected = svc_detected or sr["service"]
                    finding["smb_rdp"] = {k: v for k, v in sr.items() if k != "leads"}
                    leads += sr.get("leads", [])
                finding["service_detected"] = svc_detected
                finding["version"] = version
                finding["version_leads"] = leads
            if self.scope.enumerate_web:
                from red_ai.recon.web import enumerate_web
                web = enumerate_web(r.host, r.port, opener=self.web_opener,
                                    timeout_ms=self.scope.timeout_ms * 5)
                finding["web"] = web
                journal.append("web_enum", {"host": r.host, "port": r.port,
                                            "root": web["root"],
                                            "paths": web["paths"],
                                            "web_findings": web["findings"],
                                            "web_leads": web["leads"],
                                            "disclosed": web.get("disclosed", []),
                                            "linked": web.get("linked", []),
                                            "params": web.get("params", [])})
                if self.verbose:
                    rt = web["root"]
                    print(f"[{now().strftime('%H:%M:%S')}] [recon]   WEB  {r.host}:{r.port} root={rt.get('status')} "
                          f"server={rt.get('server')} title={rt.get('title')!r}", flush=True)
                    for wf in web["findings"]:
                        print(f"[{now().strftime('%H:%M:%S')}] [recon]     EXPOSED {wf['path']} ({wf['status']}) "
                              f"sev={wf['severity']} - {wf['meaning']}", flush=True)
                    for wl in web["leads"]:
                        print(f"[{now().strftime('%H:%M:%S')}] [recon]     LEAD    {wl['path']} ({wl['status']}) - {wl['meaning']}", flush=True)
            if self.scope.assess_tls:
                from red_ai.recon.tls import assess_tls
                tls = assess_tls(r.host, r.port, timeout_ms=self.scope.timeout_ms * 5)
                if tls["is_tls"]:
                    finding["tls"] = tls
                    journal.append("tls_posture", {"host": r.host, "port": r.port,
                                                   "accepted": [k for k, v in tls["protocols"].items()
                                                                if v["status"] == "accepted"],
                                                   "cert": tls["cert"], "findings": tls["findings"],
                                                   "reproduction": tls["reproduction"]})
                    if self.verbose:
                        for tf in tls["findings"]:
                            print(f"[{now().strftime('%H:%M:%S')}] [recon]     TLS {tf['severity'].upper()} "
                                  f"{r.host}:{r.port} {tf['title']}", flush=True)
            findings.append(finding)
            journal.append("finding", finding)
            if self.verbose:
                _det = finding.get("service_detected") or finding.get("service")
                _ver = finding.get("version")
                _extra = f" [{_det} {_ver}]" if _ver else ""
                _leads = finding.get("version_leads") or []
                print(f"[{now().strftime('%H:%M:%S')}] [recon]   FINDING {finding['host']}:{finding['port']} {finding['service']} "
                      f"sev={finding['severity']}{_extra}" + (f"  ({len(_leads)} lead/s)" if _leads else ""),
                      flush=True)
        findings.sort(key=lambda f: (-f["severity_rank"], f["port"]))
        return findings

    def _reproduce(self, findings, journal) -> dict:
        rates = {}
        if self.scope.replays <= 0:
            return rates
        for f in findings:
            hits = 0
            for _ in range(self.scope.replays):
                res = self.scanner.scan([(f["host"], f["port"])])
                if res and res[0].state is PortState.OPEN:
                    hits += 1
            rate = hits / self.scope.replays
            rates[(f["host"], f["port"])] = rate
            journal.append("reproduction", {"host": f["host"], "port": f["port"],
                                            "hits": hits, "trials": self.scope.replays, "rate": rate})
            if self.verbose:
                print(f"[{now().strftime('%H:%M:%S')}] [recon]   REPRODUCE {f['host']}:{f['port']} {hits}/{self.scope.replays} = {rate}", flush=True)
        return rates
