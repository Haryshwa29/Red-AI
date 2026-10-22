"""Email-authentication posture — SPF / DKIM / DMARC (domain spoofability).

This is the *technical* anti-phishing assessment: it never crafts a lure or
touches a person. It reads a domain's published email-authentication policy and
reports whether the domain can be spoofed — the single biggest technical weak
link that lets phishing land in inboxes:

  * SPF    — is a sender policy published, and does it end in a hard `-all`?
  * DMARC  — is a policy published, and is it enforcing (`p=quarantine|reject`)
             rather than monitor-only (`p=none`) or absent?
  * DKIM   — are signing selectors discoverable? (best-effort; selectors are
             not enumerable, so absence is reported as inconclusive, not a fail.)

All lookups are plain DNS TXT reads. The policy parsing is the valuable, testable
part; the resolver is injectable (``txt_lookup``) so it runs offline in tests and
uses a minimal stdlib UDP resolver in the field (zero third-party deps).
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

TxtLookup = Callable[[str], list]

_COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1",
                          "dkim", "mail", "s1", "s2", "mandrill", "mx")


# --------------------------------------------------------------------------- #
# Minimal stdlib DNS TXT resolver (best-effort; injectable for tests/offline).
# --------------------------------------------------------------------------- #
def _dns_txt(name: str, server: str = "1.1.1.1", timeout: float = 3.0) -> list:
    import socket
    qid = 0x1337
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    packet = header + q + struct.pack(">HH", 16, 1)   # QTYPE=TXT, QCLASS=IN
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(packet, (server, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
    except OSError:
        return []
    return _parse_txt(data)


def _parse_txt(data: bytes) -> list:
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        i = 12
        while data[i] != 0:                       # skip QNAME
            i += data[i] + 1
        i += 5                                     # null + QTYPE + QCLASS
        out = []
        for _ in range(ancount):
            if data[i] & 0xC0 == 0xC0:
                i += 2                             # compressed name pointer
            else:
                while data[i] != 0:
                    i += data[i] + 1
                i += 1
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            rdata = data[i:i + rdlen]
            i += rdlen
            if rtype == 16:                        # TXT: one or more length-prefixed strings
                j, parts = 0, []
                while j < len(rdata):
                    ln = rdata[j]; j += 1
                    parts.append(rdata[j:j + ln].decode("utf-8", "replace")); j += ln
                out.append("".join(parts))
        return out
    except Exception:
        return []


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #
def _spf(records: list) -> dict:
    rec = next((r for r in records if r.lower().startswith("v=spf1")), None)
    if not rec:
        return {"present": False, "all": None, "policy": "missing", "record": None}
    low = rec.lower()
    qualifier = next((q for q, m in (("-", "-all"), ("~", "~all"), ("?", "?all"), ("+", "+all")) if m in low), None)
    policy = {"-": "hardfail", "~": "softfail", "?": "neutral", "+": "pass-all"}.get(qualifier, "no-all")
    return {"present": True, "all": qualifier, "policy": policy, "record": rec}


def _dmarc(records: list) -> dict:
    rec = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
    if not rec:
        return {"present": False, "p": None, "record": None}
    tags = dict(t.strip().split("=", 1) for t in rec.split(";") if "=" in t)
    return {"present": True, "p": (tags.get("p") or tags.get("P") or "").strip().lower() or None,
            "pct": tags.get("pct"), "record": rec}


def assess_email_auth(domain: str, txt_lookup: Optional[TxtLookup] = None) -> dict:
    """Return the email-auth posture for a domain: {domain, spf, dmarc, dkim,
    spoofable, severity, evidence, recommendations}."""
    lookup = txt_lookup or _dns_txt
    spf = _spf(lookup(domain))
    dmarc = _dmarc(lookup(f"_dmarc.{domain}"))
    dkim_selectors = [sel for sel in _COMMON_DKIM_SELECTORS
                      if any("v=dkim1" in r.lower() or "k=rsa" in r.lower()
                             for r in lookup(f"{sel}._domainkey.{domain}"))]

    enforcing_dmarc = dmarc["present"] and dmarc["p"] in ("quarantine", "reject")
    # A domain is spoofable if DMARC isn't enforcing — SPF alone doesn't stop
    # header-From spoofing. Missing SPF or +all makes it worse.
    spoofable = not enforcing_dmarc
    reasons = []
    if not dmarc["present"]:
        reasons.append("no DMARC record — receivers have no policy, so the domain can be spoofed")
    elif dmarc["p"] == "none":
        reasons.append("DMARC p=none (monitor only) — failures are not rejected; domain is spoofable")
    if not spf["present"]:
        reasons.append("no SPF record — no sender IPs are authorized")
    elif spf["policy"] == "pass-all":
        reasons.append("SPF ends in +all — every sender passes (misconfigured)")
    elif spf["policy"] in ("softfail", "neutral", "no-all"):
        reasons.append(f"SPF is {spf['policy']} (not a strict -all)")
    if not dkim_selectors:
        reasons.append("no common DKIM selector found (inconclusive — selectors aren't enumerable)")

    severity = "high" if (not dmarc["present"] or dmarc["p"] == "none") else \
               "low" if enforcing_dmarc else "medium"
    recs = []
    if not enforcing_dmarc:
        recs.append("Publish an enforcing DMARC policy (p=quarantine, then p=reject) once SPF/DKIM align.")
    if not spf["present"] or spf["policy"] != "hardfail":
        recs.append("Publish an SPF record ending in -all listing only authorized senders.")
    if not dkim_selectors:
        recs.append("Sign outbound mail with DKIM and verify a selector is published.")

    return {
        "type": "email_auth_posture", "domain": domain, "spf": spf, "dmarc": dmarc,
        "dkim_selectors": dkim_selectors, "spoofable": spoofable, "severity": severity,
        "evidence": "; ".join(reasons) or "SPF present and DMARC enforcing",
        "recommendations": recs,
    }
