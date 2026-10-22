"""Firewall / network-exposure posture — derived from recon port states.

A TCP connect scan already tells us, per port, whether it is OPEN (listening and
reachable), CLOSED (host answered with RST — reachable, *not* filtered), or
FILTERED (no answer within the timeout — a firewall silently dropped it). That
distinction is exactly a firewall-effectiveness signal, so this module reads the
recon summary and reports:

  * whether a firewall is actively dropping traffic (filtered) vs. the host
    answering on every port (closed = no packet filtering in front of it),
  * which *sensitive* services are exposed to the network (RDP, SMB, DB ports,
    etc.) — the doors ransomware and lateral movement use,
  * a plain-language posture label and the evidence behind it.

Pure function over recon's stated output: it invents no new traffic and makes no
claim recon did not observe.
"""
from __future__ import annotations

# Ports whose exposure to a network is a finding in its own right (not web).
SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "MSRPC", 139: "NetBIOS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}


def assess_firewall(recon_summary: dict) -> dict:
    """Return a firewall/exposure posture dict from a recon summary.

    Shape: {posture, severity, counts, scanned, exposed_sensitive, evidence,
    recommendations}. Never raises; a summary with no data yields 'unknown'.
    """
    counts = (recon_summary or {}).get("counts", {}) or {}
    open_n = int(counts.get("open", 0))
    closed_n = int(counts.get("closed", 0))
    filtered_n = int(counts.get("filtered", 0))
    scanned = open_n + closed_n + filtered_n + int(counts.get("error", 0))

    # Which open services are sensitive (network-exposed, not a web app)?
    exposed = []
    for f in (recon_summary or {}).get("open", []) or []:
        port = f.get("port")
        if port in SENSITIVE_PORTS:
            exposed.append({"port": port, "service": SENSITIVE_PORTS[port],
                            "detected": f.get("service_detected") or f.get("service")})

    # Posture from the filtered-vs-closed balance of non-open ports.
    non_open = closed_n + filtered_n
    filt_ratio = (filtered_n / non_open) if non_open else 0.0
    if scanned == 0:
        posture, severity, evidence = ("unknown", "info",
            "no ports scanned — cannot assess firewall posture")
    elif open_n and not filtered_n and not closed_n:
        posture, severity, evidence = ("permissive", "medium",
            f"all {open_n} probed port(s) answered OPEN; nothing filtered — no evidence of packet filtering")
    elif filt_ratio >= 0.8:
        posture, severity, evidence = ("filtering", "info",
            f"{filtered_n}/{non_open} non-open ports were FILTERED (silently dropped) — "
            "a firewall is actively filtering; only explicitly-allowed ports are reachable")
    elif filt_ratio <= 0.2 and closed_n:
        posture, severity, evidence = ("no-filtering", "medium",
            f"{closed_n}/{non_open} non-open ports answered CLOSED (RST), {filtered_n} filtered — "
            "the host is answering on closed ports, so there is little/no stateful packet filtering in front of it")
    else:
        posture, severity, evidence = ("partial-filtering", "low",
            f"mixed: {filtered_n} filtered, {closed_n} closed of {non_open} non-open ports — "
            "some filtering, but not uniform")

    if exposed:                      # exposure raises the severity floor
        severity = "high" if severity in ("info", "low", "medium") else severity

    recs = []
    if exposed:
        names = ", ".join(f"{e['service']}:{e['port']}" for e in exposed)
        recs.append(f"Restrict network exposure of sensitive service(s) {names} — "
                    "put them behind the firewall/VPN; do not expose to untrusted networks.")
    if posture in ("permissive", "no-filtering"):
        recs.append("Add default-deny stateful filtering so only explicitly-allowed ports are reachable; "
                    "unsolicited traffic to all other ports should be dropped, not answered.")
    if posture == "filtering" and not exposed:
        recs.append("Firewall filtering looks healthy for the scanned range; keep the allow-list minimal.")

    return {
        "type": "firewall_posture", "posture": posture, "severity": severity,
        "counts": {"open": open_n, "closed": closed_n, "filtered": filtered_n, "scanned": scanned},
        "exposed_sensitive": exposed, "evidence": evidence, "recommendations": recs,
    }
