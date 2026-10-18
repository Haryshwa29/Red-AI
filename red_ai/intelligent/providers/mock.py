"""Deterministic, offline model provider for tests and `doctor`.

MockProvider never calls a network. Given the same messages and seed it returns
the same text, so a model-driven skill can be exercised reproducibly without a
real model. Real backends (local inference server, OpenAI-compatible HTTP via
stdlib urllib) implement the same ModelProvider shape and drop in unchanged.
"""
from __future__ import annotations

import hashlib
from typing import Sequence

from red_ai.contracts.domain import Message
from red_ai.intelligent.providers.base import BaseProvider


class MockProvider(BaseProvider):
    name = "mock-provider"

    def __init__(self, canned: str | None = None, seed: int = 0) -> None:
        self._canned = canned
        self._seed = seed

    def generate(self, messages: Sequence[Message], **options) -> str:
        if self._canned is not None:
            return self._canned
        last = next((m.content for m in reversed(list(messages)) if m.role == "user"), "")
        digest = hashlib.sha256(f"{self._seed}:{last}".encode()).hexdigest()[:8]
        return f"[mock-provider:{digest}] rephrased: {last}"

    def get_model_info(self) -> dict:
        return {"name": self.name, "kind": "mock", "seed": self._seed, "supports_tools": False}
