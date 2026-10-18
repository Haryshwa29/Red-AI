"""Model-provider seam.

``MockProvider`` is the default brain: deterministic, offline, no sockets, used
by ``doctor`` and the whole test suite. ``HTTPModelProvider`` is the real local
backend your installed model plugs into. ``make_provider`` builds one from
explicit config or from environment, returning ``None`` when nothing is
configured so callers transparently fall back to the deterministic planner.
"""
from __future__ import annotations

import os
from typing import Optional

from red_ai.intelligent.providers.base import BaseProvider
from red_ai.intelligent.providers.mock import MockProvider
from red_ai.intelligent.providers.http import HTTPModelProvider, ProviderError, discover_ollama_model

__all__ = [
    "BaseProvider",
    "MockProvider",
    "HTTPModelProvider",
    "ProviderError",
    "make_provider",
    "discover_ollama_model",
    "brain_target_overlap",
]


def make_provider(
    url: Optional[str] = None,
    model: Optional[str] = None,
    api: Optional[str] = None,
) -> Optional[BaseProvider]:
    """Build the brain from args or environment, or return ``None``.

    Environment (used when an argument is omitted):
        RED_AI_MODEL_URL   e.g. http://localhost:11434
        RED_AI_MODEL       e.g. dolphin-mistral
        RED_AI_MODEL_API   ollama | openai   (default: ollama)
        RED_AI_MODEL_KEY   optional bearer token for openai-compatible servers

    Returns ``None`` when no URL is configured. A URL without a model name is a
    misconfiguration and raises, rather than silently guessing a model.
    """
    url = url or os.environ.get("RED_AI_MODEL_URL")
    if not url:
        return None
    model = model or os.environ.get("RED_AI_MODEL")
    api = api or os.environ.get("RED_AI_MODEL_API", "ollama")
    if not model:
        # Interchangeable brain: if the operator didn't name a model, ask an
        # Ollama server what it has and take the first. Keeps RED-AI model-agnostic.
        if api == "ollama":
            model = discover_ollama_model(url)
        if not model:
            raise ValueError(
                "RED_AI_MODEL_URL is set but no model found "
                "(set RED_AI_MODEL, or ensure the Ollama server has a model pulled)."
            )
    return HTTPModelProvider(
        base_url=url, model=model, api=api,
        api_key=os.environ.get("RED_AI_MODEL_KEY"),
    )



def brain_target_overlap(brain_model_name, target_model_id):
    """Disclosure helper: is the attached brain the same model as a declared
    target? Returns True/False when both identities are known, else None
    (unknown -- simulation targets have no model identity). Fails toward
    disclosure: a provider prefix like 'ollama:' is stripped and a substring
    match counts, because over-disclosing a brain == target overlap is the safe
    direction. The *finding* is unaffected either way -- the coverage floor and
    evidence-first detection make the verdict independent of brain ordering; this
    only annotates the report so the overlap is auditable."""
    if not brain_model_name or not target_model_id:
        return None
    a = str(brain_model_name).lower().rsplit(":", 1)[-1].strip()
    b = str(target_model_id).lower().rsplit(":", 1)[-1].strip()
    if not a or not b:
        return None
    return a == b or a in b or b in a
