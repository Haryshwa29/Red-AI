"""Append-only, hash-linked evidence journal.

Each event records its sequence, a hash of the previous event, and its own
hash. ``read_verified`` recomputes the chain and refuses a trace that was
altered relative to a trusted copy. This is tamper *detection*, not an
immutable vault: local files remain writable, so a hash chain without an
external trust anchor cannot prevent wholesale rewriting. That limit is stated,
not hidden.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from pathlib import Path

from red_ai.contracts.scope import canonical, now


def jsonable(obj):
    """Recursively convert dataclasses / datetimes / enums to JSON-safe values."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return jsonable(asdict(obj))
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    return obj


class Journal:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("x", encoding="utf-8")
        self.previous = "0" * 64
        self.sequence = 0

    def append(self, kind: str, payload) -> dict:
        event = {"sequence": self.sequence, "timestamp": now().isoformat(), "kind": kind,
                 "previous_hash": self.previous, "payload": jsonable(payload)}
        event["hash"] = hashlib.sha256(canonical(event).encode()).hexdigest()
        self.handle.write(canonical(event) + "\n")
        self.handle.flush()
        self.previous = event["hash"]
        self.sequence += 1
        return event

    def close(self):
        self.handle.close()


def read_verified(path) -> list[dict]:
    previous = "0" * 64
    events: list[dict] = []
    for sequence, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        event = json.loads(line)
        digest = event.pop("hash")
        if (event["sequence"] != sequence or event["previous_hash"] != previous
                or hashlib.sha256(canonical(event).encode()).hexdigest() != digest):
            raise ValueError(f"Evidence integrity failed at event {sequence}")
        event["hash"] = digest
        previous = digest
        events.append(event)
    if not events or events[0]["kind"] != "run_started" or events[-1]["kind"] != "run_finished":
        raise ValueError("Evidence is incomplete; retain it for review, but do not replay or promote")
    return events
