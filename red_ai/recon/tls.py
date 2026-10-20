"""TLS / crypto posture assessment — prove weak transport encryption on the
target's OWN endpoint, with reproduced live evidence, not a citation.

This is the honest form of "break the encryption": RED-AI does not brute-force
AES or TLS 1.3 (nobody can). Instead it demonstrates that *this server* will
negotiate deprecated protocols / weak ciphers / no forward secrecy, and that a
standard client rejects its certificate. The proof is the server's own behaviour,
captured and re-probed for a measured reproduction rate; the standard/CVE
reference is attached as the *why it matters*, never as the proof itself.

Non-destructive: only TLS handshakes (no data written to the application). Pure
stdlib ``ssl``. ``classify`` is a pure function; the network probes are injectable
so the whole thing is hermetically testable. Never raises past the caller.
"""
from __future__ import annotations

import socket
import ssl
from typing import Callable, Optional

from red_ai.contracts.domain import Severity

# Protocols below TLS 1.2 are deprecated (RFC 8996). SSLv3 = POODLE (CVE-2014-3566).
_WEAK_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}
# Cipher name tokens that mark a weak negotiated suite.
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "-DES", "NULL", "EXPORT", "EXP-",
                       "MD5", "ANON", "ADH", "AECDH", "RC2")
# Forward-secrecy key exchanges.
_PFS_TOKENS = ("ECDHE", "DHE")

# (label, ssl.TLSVersion) newest→oldest. SSLv3 is almost never attemptable.
_VERSIONS = [
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
]

_REF = {
    "protocol": "RFC 8996 (deprecates TLS 1.0/1.1) · NIST SP 800-52r2",
    "sslv3": "RFC 7568 · POODLE CVE-2014-3566",
    "cipher": "NIST SP 800-52r2 (approved cipher suites)",
    "rc4": "RFC 7465 (prohibits RC4)",
    "3des": "Sweet32 CVE-2016-2183",
    "pfs": "NIST SP 800-52r2 §3.3.1 (require ECDHE/DHE)",
    "cert": "RFC 5280 (certificate validation)",
}

# (status, cipher-tuple|None, error) ; cipher-tuple is ssl's (name, protocol, bits)
Prober = Callable[[str, int, object, float], "tuple[str, Optional[tuple], Optional[str]]"]
CertFetcher = Callable[[str, int, float], dict]


def _default_prober(host, port, version, timeout):
    """Force one protocol version and report whether the server accepts it."""
    if version is None:
        return ("untestable", None, "version not supported by local TLS library")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return ("untestable", None, "version disabled in local TLS library")
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")  # let the SERVER reveal weak suites
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, port), timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ("accepted", ss.cipher(), None)
    except ssl.SSLError as e:
        return ("rejected", None, str(e))
    except (OSError, socket.timeout) as e:
        return ("error", None, str(e))


def _default_cert_fetcher(host, port, timeout):
    """A standard verifying client's verdict on the server's certificate.

    If verification fails, the error string *is* demonstrable proof ('self-signed
    certificate', 'certificate has expired', 'Hostname mismatch')."""
    out = {"valid": None, "error": None, "subject": None, "not_after": None}
    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout) as s:
            with vctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert() or {}
                out["valid"] = True
                out["not_after"] = cert.get("notAfter")
                sub = dict(x[0] for x in cert.get("subject", ())) if cert.get("subject") else {}
                out["subject"] = sub.get("commonName")
    except ssl.SSLCertVerificationError as e:
        out["valid"] = False
        out["error"] = str(e)
    except (ssl.SSLError, OSError, socket.timeout) as e:
        out["valid"] = None
        out["error"] = str(e)
    return out


def _cipher_is_weak(name: str) -> bool:
    up = (name or "").upper()
    return any(tok in up for tok in _WEAK_CIPHER_TOKENS)


def _has_pfs(name: str) -> bool:
    up = (name or "").upper()
    return any(tok in up for tok in _PFS_TOKENS)


def classify(host: str, port: int, protocols: dict, cert: dict) -> list:
    """Pure: turn probe results + cert verdict into findings. Each finding leads
    with the live evidence; ``reference`` is the standard it violates."""
    findings: list[dict] = []

    def add(title, sev, evidence, remediation, reference):
        findings.append({"title": title, "severity": sev.value, "severity_rank": sev.rank,
                         "evidence": evidence, "remediation": remediation, "reference": reference})

    accepted = {name: info for name, info in protocols.items() if info.get("status") == "accepted"}

    # 1) deprecated protocol versions actually accepted by THIS server
    for name in accepted:
        if name in _WEAK_PROTOCOLS:
            csuite = (accepted[name].get("cipher") or ("?",))[0]
            sev = Severity.HIGH if name in ("SSLv3", "TLSv1") else Severity.MEDIUM
            add(f"Server accepts deprecated {name}", sev,
                f"{host}:{port} completed a {name} handshake (cipher {csuite})",
                f"Disable {name}; require TLS 1.2+ (prefer 1.3).",
                _REF["sslv3"] if name == "SSLv3" else _REF["protocol"])

    # 2) weak negotiated cipher suites
    for name, info in accepted.items():
        cipher = info.get("cipher") or ("", "", 0)
        cname = cipher[0] or ""
        if _cipher_is_weak(cname):
            ref = _REF["rc4"] if "RC4" in cname.upper() else (
                  _REF["3des"] if "3DES" in cname.upper() or "DES" in cname.upper() else _REF["cipher"])
            add(f"Weak cipher negotiated on {name}", Severity.HIGH,
                f"{host}:{port} negotiated {cname} over {name}",
                "Remove RC4/3DES/DES/EXPORT/NULL/MD5 suites; use AES-GCM / ChaCha20.", ref)

    # 3) no forward secrecy on any accepted protocol
    if accepted and not any(_has_pfs((i.get("cipher") or ("",))[0]) for i in accepted.values()):
        sample = next(iter(accepted.values())).get("cipher") or ("?",)
        add("No forward secrecy", Severity.MEDIUM,
            f"{host}:{port} negotiated non-ECDHE/DHE key exchange ({sample[0]}); "
            "a later key compromise decrypts recorded sessions",
            "Require ECDHE (or DHE) key exchange.", _REF["pfs"])

    # 4) certificate validation — a standard client's live verdict
    if cert.get("valid") is False:
        err = cert.get("error") or ""
        low = err.lower()
        if "self-signed" in low or "self signed" in low:
            add("Certificate is self-signed", Severity.MEDIUM,
                f"a verifying client rejects {host}:{port}: {err}",
                "Install a certificate from a trusted CA.", _REF["cert"])
        elif "expired" in low:
            add("Certificate has expired", Severity.HIGH,
                f"a verifying client rejects {host}:{port}: {err}",
                "Renew the certificate.", _REF["cert"])
        elif "hostname mismatch" in low or "doesn't match" in low or "match either" in low:
            add("Certificate hostname mismatch", Severity.MEDIUM,
                f"a verifying client rejects {host}:{port}: {err}",
                "Issue a certificate whose SAN matches the hostname.", _REF["cert"])
        else:
            add("Certificate fails validation", Severity.MEDIUM,
                f"a verifying client rejects {host}:{port}: {err}",
                "Fix the certificate chain so standard clients validate it.", _REF["cert"])

    findings.sort(key=lambda f: -f["severity_rank"])
    return findings


def assess_tls(host: str, port: int, *, timeout_ms: int = 4000, replays: int = 3,
               prober: Optional[Prober] = None,
               cert_fetcher: Optional[CertFetcher] = None) -> dict:
    """Assess one endpoint. Returns {is_tls, protocols, cert, findings, reproduction}.
    Non-destructive; never raises."""
    prober = prober or _default_prober
    cert_fetcher = cert_fetcher or _default_cert_fetcher
    timeout = timeout_ms / 1000.0

    protocols: dict[str, dict] = {}
    for name, version in _VERSIONS:
        status, cipher, err = prober(host, port, version, timeout)
        protocols[name] = {"status": status, "cipher": cipher, "error": err}

    is_tls = any(p["status"] == "accepted" for p in protocols.values())
    if not is_tls:
        return {"host": host, "port": port, "is_tls": False, "protocols": protocols,
                "cert": {}, "findings": [], "reproduction": {}}

    cert = cert_fetcher(host, port, timeout)
    findings = classify(host, port, protocols, cert)

    # Reproduce the weak-protocol evidence: re-probe each accepted weak protocol.
    reproduction = {}
    trials = max(1, replays)
    for name in [n for n, p in protocols.items() if p["status"] == "accepted" and n in _WEAK_PROTOCOLS]:
        version = dict(_VERSIONS)[name]
        hits = sum(1 for _ in range(trials)
                   if prober(host, port, version, timeout)[0] == "accepted")
        reproduction[name] = {"hits": hits, "trials": trials, "rate": hits / trials}

    return {"host": host, "port": port, "is_tls": True, "protocols": protocols,
            "cert": cert, "findings": findings, "reproduction": reproduction}
