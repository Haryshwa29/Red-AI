"""Minimal, correct RFC 6455 WebSocket server — pure stdlib, zero dependencies.

RED-AI ships no third-party packages, so the live dashboard's realtime transport
is implemented here directly: the opening-handshake accept key, server→client
frame encoding (never masked), client→server frame decoding (always masked), and
ping/pong/close control frames. It is deliberately small: text frames, one client
per connection, no extensions or fragmentation reassembly beyond what a browser
sends for small JSON messages.

``WSConnection`` wraps a handler's rfile/wfile with a send-lock so the engagement
thread can push events while the handler thread blocks reading client control
messages.
"""
from __future__ import annotations

import base64
import hashlib
import threading

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BIN = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def accept_key(sec_websocket_key: str) -> str:
    """The Sec-WebSocket-Accept value for a given Sec-WebSocket-Key."""
    digest = hashlib.sha1((sec_websocket_key + _GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def encode_frame(payload: bytes, opcode: int = OP_TEXT) -> bytes:
    """A server→client frame (FIN set, never masked)."""
    b0 = 0x80 | (opcode & 0x0F)
    n = len(payload)
    if n < 126:
        header = bytes([b0, n])
    elif n < 65536:
        header = bytes([b0, 126]) + n.to_bytes(2, "big")
    else:
        header = bytes([b0, 127]) + n.to_bytes(8, "big")
    return header + payload


def encode_text(s: str) -> bytes:
    return encode_frame(s.encode("utf-8"), OP_TEXT)


def encode_close() -> bytes:
    return encode_frame(b"", OP_CLOSE)


def read_frame(rfile) -> "tuple[int, bytes] | None":
    """Read one client frame from a binary file object. Returns (opcode, payload)
    or None on EOF/short read. Client frames are masked; payload is unmasked here."""
    hdr = rfile.read(2)
    if not hdr or len(hdr) < 2:
        return None
    b0, b1 = hdr[0], hdr[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        ext = rfile.read(2)
        if len(ext) < 2:
            return None
        length = int.from_bytes(ext, "big")
    elif length == 127:
        ext = rfile.read(8)
        if len(ext) < 8:
            return None
        length = int.from_bytes(ext, "big")
    mask = rfile.read(4) if masked else b""
    data = rfile.read(length) if length else b""
    if len(data) < length:
        return None
    if masked and mask:
        data = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
    return opcode, data


class WSConnection:
    """A live WebSocket connection over a handler's rfile/wfile. Thread-safe send."""

    def __init__(self, rfile, wfile):
        self.rfile = rfile
        self.wfile = wfile
        self._lock = threading.Lock()
        self.open = True

    def send(self, text: str) -> bool:
        if not self.open:
            return False
        with self._lock:
            try:
                self.wfile.write(encode_text(text))
                self.wfile.flush()
                return True
            except Exception:
                self.open = False
                return False

    def recv(self) -> "str | None":
        """Block for the next client text message. Transparently answers pings and
        returns None when the client closes or the socket dies."""
        while self.open:
            fr = read_frame(self.rfile)
            if fr is None:
                self.open = False
                return None
            opcode, data = fr
            if opcode == OP_CLOSE:
                self.close()
                return None
            if opcode == OP_PING:
                with self._lock:
                    try:
                        self.wfile.write(encode_frame(data, OP_PONG))
                        self.wfile.flush()
                    except Exception:
                        self.open = False
                        return None
                continue
            if opcode == OP_PONG:
                continue
            if opcode in (OP_TEXT, OP_BIN, OP_CONT):
                try:
                    return data.decode("utf-8", "replace")
                except Exception:
                    return ""
        return None

    def close(self) -> None:
        if not self.open:
            return
        with self._lock:
            try:
                self.wfile.write(encode_close())
                self.wfile.flush()
            except Exception:
                pass
        self.open = False


def is_ws_upgrade(headers) -> bool:
    """True if these request headers ask for a WebSocket upgrade."""
    up = (headers.get("Upgrade") or "").lower()
    conn = (headers.get("Connection") or "").lower()
    return "websocket" in up and "upgrade" in conn and bool(headers.get("Sec-WebSocket-Key"))
