"""Stated service -> exposure-risk map. Deterministic, auditable, no black box.

Severity for an open port is derived from THIS table plus the scope environment,
never from a model. The table encodes a defensible default: services that are
dangerous to expose to a network (remote admin, SMB, databases, unauthenticated
management) rank higher. An operator can read and amend it; a finding always
cites the exact rule it came from. A model may add a human-readable note (see
the analyst), but it can never move a severity.
"""
from __future__ import annotations

from red_ai.contracts.domain import Severity

# port -> (service, base_severity, why-exposure-matters / remediation hint)
SERVICE_RISK: dict[int, tuple[str, Severity, str]] = {
    21:   ("FTP", Severity.HIGH, "cleartext auth and files; prefer SFTP/FTPS or close"),
    22:   ("SSH", Severity.MEDIUM, "remote admin; restrict by source, keys only, no password auth"),
    23:   ("Telnet", Severity.CRITICAL, "cleartext remote admin; must not be exposed, disable it"),
    25:   ("SMTP", Severity.MEDIUM, "mail relay; ensure no open relay, restrict source"),
    53:   ("DNS", Severity.MEDIUM, "restrict recursion; avoid exposing resolver to untrusted nets"),
    80:   ("HTTP", Severity.MEDIUM, "cleartext web; redirect to TLS and review the app behind it"),
    110:  ("POP3", Severity.MEDIUM, "cleartext mail retrieval; prefer TLS"),
    135:  ("MSRPC", Severity.HIGH, "Windows RPC endpoint mapper; do not expose beyond host/LAN"),
    139:  ("NetBIOS", Severity.HIGH, "legacy Windows file/session; block at the host firewall"),
    143:  ("IMAP", Severity.MEDIUM, "cleartext mail; prefer TLS"),
    389:  ("LDAP", Severity.HIGH, "directory data; require TLS and restrict source"),
    445:  ("SMB", Severity.CRITICAL, "Windows file sharing; a top ransomware/lateral-movement vector, do not expose"),
    1433: ("MSSQL", Severity.HIGH, "database; never expose to untrusted networks, restrict + authenticate"),
    1521: ("Oracle", Severity.HIGH, "database listener; restrict source and patch"),
    3306: ("MySQL", Severity.HIGH, "database; bind to localhost or restrict by firewall"),
    3389: ("RDP", Severity.CRITICAL, "remote desktop; a top brute-force/ransomware vector, gateway + MFA + restrict source"),
    5432: ("PostgreSQL", Severity.HIGH, "database; bind to localhost or restrict by firewall"),
    5900: ("VNC", Severity.HIGH, "remote desktop, often weak auth; tunnel and restrict"),
    6379: ("Redis", Severity.CRITICAL, "often unauthenticated; never expose, bind to localhost + require auth"),
    8080: ("HTTP-alt", Severity.MEDIUM, "web/app or proxy; review the service and move behind TLS"),
    9200: ("Elasticsearch", Severity.CRITICAL, "frequently unauthenticated data store; never expose"),
    11211:("Memcached", Severity.HIGH, "unauthenticated; amplification risk, bind to localhost"),
    11434:("Ollama", Severity.MEDIUM, "local LLM API; if it must stay, bind to localhost and never expose to the LAN/Internet"),
    27017:("MongoDB", Severity.CRITICAL, "historically unauthenticated; never expose, enable auth + bind local"),
}

_DEFAULT = ("unknown service", Severity.LOW, "identify the service and confirm it should be reachable")


def classify(port: int, environment: str) -> tuple[str, Severity, str]:
    """Return (service, severity, remediation). Exposure on a production host is
    one rank more severe than the same port in an owned/lab environment."""
    service, severity, hint = SERVICE_RISK.get(port, _DEFAULT)
    if environment == "production" and severity.rank < Severity.CRITICAL.rank:
        from red_ai.contracts.domain import severity_from_rank
        severity = severity_from_rank(severity.rank + 1)
    return service, severity, hint
