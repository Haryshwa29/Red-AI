"""ModelProvider base helpers. The Protocol itself lives in contracts.interfaces.

A provider is RED-AI's own model backend, used by model-driven skills to craft
or mutate attacks. It is deliberately abstracted so a local inference server, an
OpenAI-compatible endpoint, or a deterministic mock are interchangeable, and so
the test suite never needs a network or a paid API.
"""
from __future__ import annotations

from typing import Sequence

from red_ai.contracts.domain import Message


class BaseProvider:
    """Convenience base; concrete providers override ``generate``."""
    name = "base"

    def generate(self, messages: Sequence[Message], **options) -> str:
        raise NotImplementedError

    def supports_tools(self) -> bool:
        return False

    def get_model_info(self) -> dict:
        return {"name": self.name, "kind": "base", "supports_tools": self.supports_tools()}
