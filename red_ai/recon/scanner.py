"""Deterministic TCP connect scanner. Read-only: handshake and close.

A connect scan asks the OS to complete a normal TCP handshake and immediately
closes it. It sends no application payload, so it cannot exploit or alter the
service -- it only learns open/closed/filtered. That is the whole capability of
this engine in this build, and the ceiling is deliberate.

The scanner is a pure observer: it takes a (host, port) that the gate has
ALREADY authorized and returns a result. It never consults the scope and never
decides what to scan -- that separation is what lets the controller enforce
authorization in exactly one place.
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"   # no response within timeout (firewall/drop)
    ERROR = "error"


@dataclass(frozen=True)
class ProbeResult:
    host: str
    port: int
    state: PortState
    latency_ms: int
    detail: str = ""


def probe(host: str, port: int, timeout_ms: int,
          connect: Callable[[str, int, float], int] | None = None) -> ProbeResult:
    """Single connect probe. ``connect`` is injectable for hermetic tests; the
    default uses ``socket.connect_ex``."""
    start = time.monotonic()
    try:
        if connect is not None:
            rc = connect(host, port, timeout_ms / 1000.0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_ms / 1000.0)
            try:
                rc = s.connect_ex((host, port))
            finally:
                s.close()
    except socket.timeout:
        return ProbeResult(host, port, PortState.FILTERED, _ms(start), "timeout")
    except OSError as exc:
        return ProbeResult(host, port, PortState.ERROR, _ms(start), str(exc))
    latency = _ms(start)
    if rc == 0:
        return ProbeResult(host, port, PortState.OPEN, latency)
    # Timeout surfaces as a non-zero rc on some stacks; treat the slow case as
    # filtered, a fast refusal as closed.
    if latency >= timeout_ms:
        return ProbeResult(host, port, PortState.FILTERED, latency, f"rc={rc}")
    return ProbeResult(host, port, PortState.CLOSED, latency, f"rc={rc}")


def _ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


@dataclass
class TcpConnectScanner:
    timeout_ms: int = 800
    concurrency: int = 64
    connect: Callable[[str, int, float], int] | None = None
    name: str = "tcp-connect"

    def scan(self, targets: Iterable[tuple[str, int]]) -> list[ProbeResult]:
        targets = list(targets)
        if not targets:
            return []
        workers = max(1, min(self.concurrency, len(targets)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = pool.map(
                lambda t: probe(t[0], t[1], self.timeout_ms, self.connect), targets
            )
            return list(results)
