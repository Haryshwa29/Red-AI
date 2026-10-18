"""Local model backend for RED-AI: an offline-first ``ModelProvider``.

This is the seam your own model plugs into. It speaks two wire formats over
plain ``urllib`` (stdlib only, no third-party client):

  * ``ollama``  -> POST {base_url}/api/chat                (Ollama native)
  * ``openai``  -> POST {base_url}/v1/chat/completions     (OpenAI-compatible:
                   llama.cpp server, vLLM, LM Studio, text-generation-webui, ...)

Design stance
-------------
"Offline" in RED-AI means **no internet egress and no paid API** -- not "no
sockets". A model running on ``localhost`` (Ollama on :11434, llama.cpp on
:8080) is local compute, not a network dependency, and needs no API key. So
this provider defaults to localhost, refuses nothing by policy here (the gate
is the authority), and is never constructed by ``doctor`` or the test suite
unless an endpoint is explicitly configured -- the default brain stays the
deterministic ``MockProvider`` so the suite stays hermetic.

Determinism
-----------
``temperature`` defaults to 0.0 and a ``seed`` is sent when the backend accepts
one, so a given (model, messages) pair is as reproducible as the backend
allows. RED-AI never *relies* on this: reproduction is measured by replaying
the stored attacker strings through the target, which is independent of how
those strings were produced. The seed is a courtesy, not a guarantee -- stated,
not hidden.

Failure contract
----------------
``generate`` raises ``ProviderError`` on transport/HTTP/parse failure. It never
returns a plausible-looking fake on error, because a model-driven planner must
be able to tell "the brain said X" from "the brain is unreachable" and fall
back to the deterministic planner rather than attack on hallucinated strategy.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Sequence

from red_ai.contracts.domain import Message
from red_ai.intelligent.providers.base import BaseProvider


class ProviderError(RuntimeError):
    """Raised when the backend cannot be reached or its reply cannot be parsed."""


# A transport is injectable so the test suite can exercise payload-building and
# response-parsing without a socket. Signature mirrors the real urllib path.
Transport = Callable[[str, bytes, dict, float], bytes]


def _urllib_transport(url: str, body: bytes, headers: dict, timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read()
    except urllib.error.HTTPError as exc:  # 4xx/5xx from the model server
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise ProviderError(f"model server returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:  # connection refused, DNS, timeout
        raise ProviderError(
            f"cannot reach model server at {url}: {exc.reason}. "
            "Is the local model running?"
        ) from exc


@dataclass
class HTTPModelProvider(BaseProvider):
    """``ModelProvider`` over a local OpenAI-compatible or Ollama HTTP endpoint."""

    base_url: str
    model: str
    api: str = "ollama"
    timeout: float = 60.0
    api_key: str | None = None
    temperature: float = 0.0
    seed: int = 0
    tools: bool = False
    transport: Transport = _urllib_transport

    def __post_init__(self) -> None:
        if self.api not in ("ollama", "openai"):
            raise ValueError("api must be 'ollama' or 'openai'")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL")
        self.base_url = self.base_url.rstrip("/")
        self.name = f"{self.api}:{self.model}"

    # -- wire format ----------------------------------------------------------

    def _endpoint(self) -> str:
        if self.api == "ollama":
            return f"{self.base_url}/api/chat"
        return f"{self.base_url}/v1/chat/completions"

    def _payload(self, messages: Sequence[Message], options: dict) -> dict:
        wire = [{"role": m.role, "content": m.content} for m in messages]
        temperature = float(options.get("temperature", self.temperature))
        seed = int(options.get("seed", self.seed))
        if self.api == "ollama":
            opts = {"temperature": temperature, "seed": seed}
            if "num_predict" in options:
                opts["num_predict"] = int(options["num_predict"])
            body = {"model": self.model, "messages": wire, "stream": False, "options": opts}
            # thinking models (gemma4, qwen3.x) emit a hidden reasoning pass that
            # we don't need for a one-line note; disabling it cuts latency sharply.
            if "think" in options:
                body["think"] = bool(options["think"])
            return body
        body = {
            "model": self.model,
            "messages": wire,
            "stream": False,
            "temperature": temperature,
        }
        if seed:
            body["seed"] = seed
        return body

    @staticmethod
    def _parse(api: str, raw: bytes) -> str:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProviderError(f"model server reply was not JSON: {exc}") from exc
        try:
            if api == "ollama":
                return data["message"]["content"]
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(
                f"unexpected {api} response shape: {json.dumps(data)[:300]}"
            ) from exc

    # -- ModelProvider --------------------------------------------------------

    def generate(self, messages: Sequence[Message], **options) -> str:
        body = json.dumps(self._payload(messages, options)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        raw = self.transport(self._endpoint(), body, headers, self.timeout)
        text = self._parse(self.api, raw)
        if not isinstance(text, str) or not text.strip():
            raise ProviderError("model server returned an empty completion")
        return text

    def supports_tools(self) -> bool:
        return self.tools

    def get_model_info(self) -> dict:
        return {
            "name": self.name,
            "kind": self.api,
            "endpoint": self._endpoint(),
            "model": self.model,
            "supports_tools": self.tools,
            "offline": self.base_url.startswith(("http://localhost", "http://127.0.0.1")),
        }

    def health(self) -> tuple[bool, str]:
        """Cheap reachability probe for ``doctor``. Never raises."""
        try:
            reply = self.generate([Message(role="user", content="ping")])
            return True, f"reachable; sample completion {len(reply)} chars"
        except ProviderError as exc:
            return False, str(exc)


def discover_ollama_model(base_url: str, timeout: float = 5.0) -> str | None:
    """Best-effort: return the first model an Ollama server lists, or None.

    Lets RED-AI attach to *whatever* local model the client already has, without
    the operator needing to know the exact tag -- the brain is interchangeable.
    GET {base_url}/api/tags ; never raises.
    """
    import json as _json, urllib.request as _r, urllib.error as _e
    url = base_url.rstrip("/") + "/api/tags"
    try:
        with _r.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (localhost)
            data = _json.loads(resp.read().decode("utf-8"))
        models = data.get("models") or []
        for m in models:
            name = m.get("name") or m.get("model")
            if name:
                return name
    except (_e.URLError, ValueError, KeyError, TypeError):
        return None
    return None
