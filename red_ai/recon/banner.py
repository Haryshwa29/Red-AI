"""
Service / version identification for the recon engine (opt-in).

scanner.py is strictly PASSIVE -- handshake and close, zero application bytes.
This is the next, SEPARATE step: a light, non-destructive SERVICE PROBE that
identifies what is listening on an ALREADY-authorized open port, and flags
version-specific exposures as human-routed leads (never confirmed vulns).

It stays opt-in (ReconScope.identify_services, default False) so the pure
read-only connect-scan guarantee remains available unchanged. What a probe sends
is deliberately minimal and benign:
  * web ports -> a single root request `GET / HTTP/1.0` (what a browser does
    loading the homepage): no crawling, no parameters, no payloads;
  * everything else -> nothing is sent; the engine only READS the greeting the
    service volunteers on connect (SSH/FTP/SMTP announce themselves).
It never sends an exploit, never mutates state, never follows links, and skips
TLS ports (no plaintext probe). This is an ACTIVE-SAFE identification step, not
exploitation -- stated, not hidden.

Fingerprinting is a stated pattern table (auditable, no model). Exposure notes
are LEADS in RED-AI's sense -- "this version is associated with a known issue; a
human should verify", with the why -- never "I found a vulnerability".
"""
from __future__ import annotations

import re
import socket
from typing import Callable, Optional

# Injectable for hermetic tests: (host, port, timeout_s, send) -> raw bytes | None
BannerOpener = Callable[[str, int, float, Optional[bytes]], Optional[bytes]]

_HTTP_PORTS = {80, 591, 8000, 8008, 8080, 8888}
_MAX = 4096


def _socket_opener(host, port, timeout_s, send):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((host, port))
            if send:
                s.sendall(send)
            return s.recv(_MAX)
        finally:
            s.close()
    except OSError:
        return None


def grab_banner(host: str, port: int, timeout_ms: int,
                opener: Optional[BannerOpener] = None) -> Optional[bytes]:
    """Read a service banner from an already-authorized open port. Web ports get
    a single benign root GET; others send nothing and read the volunteered
    greeting. Never raises -> None on any failure."""
    opener = opener or _socket_opener
    send = None
    if port in _HTTP_PORTS:
        send = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: RED-AI-recon/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
    elif port == 6379:            # Redis volunteers nothing: ask it to identify itself
        send = b"INFO server\r\n"
    elif port == 11211:           # Memcached
        send = b"version\r\n"
    try:
        raw = opener(host, port, timeout_ms / 1000.0, send)
    except Exception:
        return None
    return raw or None


# -- fingerprint: stated patterns, service + version from a banner -----------

_PATTERNS = [
    (re.compile(r"^SSH-\d+\.\d+-(?P<v>\S+)", re.I), "SSH"),
    (re.compile(r"^220[- ].*?(?P<v>(?:vsftpd|ProFTPD|Pure-FTPd|FileZilla|Microsoft FTP)[\w .\-]*)", re.I), "FTP"),
    (re.compile(r"^220[- ](?P<v>\S+\s+ESMTP\s+\S+)", re.I), "SMTP"),
    (re.compile(r"^RFB (?P<v>\d{3}\.\d{3})", re.I), "VNC"),
    (re.compile(r"redis_version:(?P<v>[0-9][\w.\-]*)", re.I), "Redis"),
    (re.compile(r"^VERSION (?P<v>[0-9][\w.\-]+)", re.I), "Memcached"),
    (re.compile(r"Server:\s*(?P<v>[^\r\n]+)", re.I), "HTTP"),
]


def fingerprint(banner: bytes) -> "tuple[Optional[str], Optional[str]]":
    """(service, version) from a banner, by stated patterns. Unknown service ->
    (None, first non-empty line) so the operator still sees the raw greeting."""
    if not banner:
        return None, None
    # Binary protocols first (no clean text line).
    if banner[:1] == b"\xff":                       # Telnet: IAC negotiation byte
        return "Telnet", None
    # MySQL/MariaDB handshake packet: [3-byte len][seq=0][protover 9|10][version \x00…]
    if len(banner) > 6 and banner[3] == 0 and banner[4] in (9, 10):
        ver = banner[5:].split(b"\x00", 1)[0].decode("utf-8", "replace")
        if re.match(r"^\d+\.\d+", ver):
            return ("MariaDB" if "mariadb" in ver.lower() else "MySQL"), ver
    text = banner.decode("utf-8", "replace")
    for rx, service in _PATTERNS:
        m = rx.search(text)
        if m:
            return service, m.group("v").strip()
    # Redis/other servers that answer an error instead of a version string.
    if text.startswith(("-NOAUTH", "+PONG")) or "-NOAUTH Authentication required" in text:
        return "Redis", None
    if text.startswith("-ERR") and "unknown command" in text.lower():
        return "Redis", None
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), None)
    return None, first


# -- version exposure leads (human-routed; illustrative, NOT exhaustive) -----

# (substring to match in the version string, lead note). A LEAD, never a finding.
KNOWN_EXPOSURES = [
    ("vsftpd 2.3.4", "vsftpd 2.3.4 shipped with a known malicious backdoor (CVE-2011-2523); "
                     "a human should verify whether this build is the backdoored one and test a guided PoC in the lab."),
    ("openssh_7.", "Several OpenSSH 7.x builds allow username enumeration (CVE-2018-15473); "
                   "confirm the exact version and whether enumeration is reachable."),
    ("apache/2.4.49", "Apache 2.4.49 is vulnerable to path traversal and possible RCE (CVE-2021-41773); "
                      "verify and run a human-guided PoC in the lab, do not assume exploitability."),
    ("apache/2.4.50", "Apache 2.4.50 only partially fixed CVE-2021-41773 and remained exploitable "
                      "(CVE-2021-42013); verify the exact build."),
]


def exposure_leads(version: Optional[str]) -> list:
    if not version:
        return []
    v = version.lower()
    return [note for sub, note in KNOWN_EXPOSURES if sub in v]


def unauth_exposure(service: Optional[str], version: Optional[str]) -> list:
    """Leads for data stores that answered our probe with no authentication at all.

    Redis/Memcached volunteer nothing on connect, so a usable reply to a benign
    INFO/version probe means the service is reachable *unauthenticated* — a real
    exposure, routed as a human-verifiable lead (not auto-escalated)."""
    if service == "Redis":
        return ["Redis answered an INFO probe with no authentication — the data store is reachable "
                "unauthenticated; set `requirepass` and bind to localhost/VPN, do not expose it."]
    if service == "Memcached":
        return ["Memcached answered a version probe unauthenticated — exposed cache and a UDP "
                "amplification vector; bind to localhost, disable UDP, and firewall the port."]
    return []
