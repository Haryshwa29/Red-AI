"""SMB and RDP deep fingerprinting — read-only negotiate probes.

Neither protocol volunteers a banner, so the generic prober can only say "port
open". This module sends ONE benign protocol negotiation — the same first packet
any legitimate client sends — and parses the reply for the two facts that drive
real exposure decisions:

  * SMB (445/139): is **SMBv1** still enabled? SMBv1 is the precondition for the
    EternalBlue / MS17-010 family (WannaCry, NotPetya). We advertise *only* the
    SMBv1 dialect, so an SMBv1 negotiate response means it is genuinely on.
  * RDP (3389): is **Network Level Authentication (NLA)** required? RDP reachable
    without NLA exposes the pre-auth surface of BlueKeep (CVE-2019-0708) and
    makes brute force/credential attacks far cheaper.

A negotiate request authenticates nothing, opens no session, and changes no
state. No exploit, no credentials — identification only. Findings are routed as
human-verifiable LEADS (a version/config signal to confirm), never auto-confirmed
vulnerabilities.
"""
from __future__ import annotations

import socket
from typing import Callable, Optional

RawOpener = Callable[[str, int, float, bytes], Optional[bytes]]


def _socket_opener(host: str, port: int, timeout_s: float, send: bytes) -> Optional[bytes]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((host, port))
            s.sendall(send)
            return s.recv(4096)
        finally:
            s.close()
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# SMB — SMBv1 negotiate advertising only the "NT LM 0.12" dialect.
# --------------------------------------------------------------------------- #
def _smb1_negotiate() -> bytes:
    header = bytes([
        0xFF, 0x53, 0x4D, 0x42,          # \xffSMB
        0x72,                            # command: Negotiate Protocol
        0x00, 0x00, 0x00, 0x00,          # NT status = success
        0x18,                            # flags
        0x01, 0x28,                      # flags2
        0x00, 0x00,                      # PID high
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # signature
        0x00, 0x00,                      # reserved
        0x00, 0x00,                      # TID
        0x2F, 0x4B,                      # PID low
        0x00, 0x00,                      # UID
        0x00, 0x00,                      # MID
    ])
    dialect = b"\x02NT LM 0.12\x00"
    body = header + b"\x00" + len(dialect).to_bytes(2, "little") + dialect
    return b"\x00" + len(body).to_bytes(3, "big") + body   # NetBIOS session header


def probe_smb(host: str, port: int = 445, timeout_ms: int = 3000,
              opener: Optional[RawOpener] = None) -> dict:
    """Return {service, smbv1, leads}. service is None if nothing SMB answered."""
    opener = opener or _socket_opener
    try:
        resp = opener(host, port, timeout_ms / 1000.0, _smb1_negotiate())
    except Exception:
        resp = None
    out = {"service": None, "smbv1": False, "leads": []}
    if not resp or len(resp) < 9:
        return out
    sig = resp[4:8]
    if sig == b"\xffSMB":
        out["service"] = "SMB"
        # negotiate response (0x72) with success status and a chosen dialect (not 0xFFFF)
        status_ok = resp[9:13] == b"\x00\x00\x00\x00"
        dialect_idx = resp[37:39] if len(resp) >= 39 else b"\xff\xff"
        if resp[8] == 0x72 and status_ok and dialect_idx != b"\xff\xff":
            out["smbv1"] = True
            out["leads"].append(
                "SMBv1 is ENABLED — this is the precondition for the EternalBlue / MS17-010 "
                "family (WannaCry, NotPetya). Disable SMBv1; confirm the patch level in the lab.")
    elif sig == b"\xfeSMB":
        out["service"] = "SMB"   # SMB2+ only; SMBv1 appears disabled
    return out


# --------------------------------------------------------------------------- #
# RDP — X.224 Connection Request carrying an RDP Negotiation Request.
# --------------------------------------------------------------------------- #
_PROTOCOL_SSL = 0x01
_PROTOCOL_HYBRID = 0x02       # CredSSP / NLA
_PROTOCOL_HYBRID_EX = 0x08


def _rdp_connection_request() -> bytes:
    neg_req = b"\x01\x00\x08\x00" + (_PROTOCOL_SSL | _PROTOCOL_HYBRID).to_bytes(4, "little")
    x224_body = b"\xe0" + b"\x00\x00" + b"\x00\x00" + b"\x00" + neg_req   # CR, dst, src, class
    x224 = bytes([len(x224_body)]) + x224_body
    return b"\x03\x00" + (4 + len(x224)).to_bytes(2, "big") + x224        # TPKT


def probe_rdp(host: str, port: int = 3389, timeout_ms: int = 3000,
              opener: Optional[RawOpener] = None) -> dict:
    """Return {service, nla_required, selected_protocol, leads}."""
    opener = opener or _socket_opener
    try:
        resp = opener(host, port, timeout_ms / 1000.0, _rdp_connection_request())
    except Exception:
        resp = None
    out = {"service": None, "nla_required": None, "selected_protocol": None, "leads": []}
    if not resp or resp[0] != 0x03:          # not a TPKT reply -> not RDP/TPKT
        return out
    out["service"] = "RDP"
    # RDP Negotiation Response sits after TPKT(4) + X.224 CC header(7) = offset 11.
    if len(resp) >= 19 and resp[11] == 0x02:          # RDP_NEG_RSP
        selected = int.from_bytes(resp[15:19], "little")
        out["selected_protocol"] = selected
        out["nla_required"] = bool(selected & (_PROTOCOL_HYBRID | _PROTOCOL_HYBRID_EX))
        if not out["nla_required"]:
            out["leads"].append(
                "RDP does NOT require Network Level Authentication (NLA) — the pre-auth surface "
                "is exposed (BlueKeep CVE-2019-0708 class). Require NLA and restrict access.")
    elif len(resp) >= 19 and resp[11] == 0x03:        # RDP_NEG_FAILURE
        out["selected_protocol"] = int.from_bytes(resp[15:19], "little")
    return out


def fingerprint_smb_rdp(host: str, port: int, timeout_ms: int = 3000,
                        opener: Optional[RawOpener] = None) -> "dict | None":
    """Dispatch by port: 445/139 -> SMB, 3389 -> RDP. None if not applicable."""
    if port in (445, 139):
        return probe_smb(host, port, timeout_ms, opener)
    if port == 3389:
        return probe_rdp(host, port, timeout_ms, opener)
    return None
