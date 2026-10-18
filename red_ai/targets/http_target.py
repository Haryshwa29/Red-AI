"""
HTTPTargetAdapter: talk to a REAL chat / LLM-app endpoint as the system under test.

This is the first real-target connector (rung 1 of the autonomous-pentester
path). It lets the existing prompt-injection engine send its auditable
TemplateBank turns to a live endpoint instead of an in-process simulation. The
reasoning layer is unchanged -- only the transport boundary differs, which is the
entire point of the TargetAdapter protocol.

Wire formats (stdlib urllib only, mirrors providers/http.py):
  * ollama  -> POST {base_url}/api/chat
  * openai  -> POST {base_url}/v1/chat/completions   (llama.cpp / vLLM / LM Studio / an app gateway)

Egress & data residency. The adapter opens a socket to EXACTLY ONE place: the
authorized target URL -- the client's own in-network endpoint (the replica under
test). With the model provider's single sink, these remain the only two outbound
calls in the package; the no-egress story is unchanged.

Failure contract (the OPPOSITE of the model provider). A TargetAdapter must never
raise on target-side failure -- an errored exchange is inconclusive, never a
successful defence. Transport/HTTP/parse failures come back inside
``TargetResponse.error`` with empty content; the ladder then sees a non-giving,
errored turn and the planner keeps going.

Detection note (stated, not hidden). Tier-1 canary detection needs a KNOWN secret
to look for. In the intended deployment the client tests a sandbox/replica and
plants the onboarding canary in the test bot's system prompt -- then a genuine
system-prompt disclosure surfaces as a tier-1 match exactly as in simulation.
Against a pure black-box target with no planted canary, detection falls to tier-2
policy assertions and tier-3 semantic review (tier-3 is a declared gap), so a
black-box run reads "not broken under this coverage", never a safety proof.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from red_ai.contracts.domain import Message, TargetResponse

# Injectable transport -> hermetic tests with no socket. Returns (status, body);
# status 0 means the endpoint could not be reached at all.
Transport = Callable[[str, bytes, dict, float], "tuple[int, bytes]"]


def _urllib_transport(url: str, body: bytes, headers: dict, timeout: float):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return getattr(resp, "status", 200) or 200, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        return 0, str(getattr(exc, "reason", exc)).encode("utf-8", "replace")


@dataclass
class HTTPTargetAdapter:
    base_url: str
    model: str
    api: str = "ollama"
    system: Optional[str] = None          # optional system prompt (replica testing)
    api_key: Optional[str] = None
    timeout: float = 60.0
    transport: Transport = _urllib_transport
    name: str = field(default="", init=False)
    _turns: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.api not in ("ollama", "openai"):
            raise ValueError("api must be 'ollama' or 'openai'")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL")
        self.base_url = self.base_url.rstrip("/")
        self.name = f"http:{self.api}:{self.model}"

    # -- TargetAdapter --------------------------------------------------------

    def initialize(self) -> None:
        self._turns = 0

    def reset(self) -> None:
        # HTTP chat is stateless here: the controller re-sends the full
        # conversation on every send(), so a reset is just a fresh turn counter.
        # Server-side session isolation (if the app keeps state) is the
        # operator's deployment concern -- stated, not hidden.
        self._turns = 0

    def get_state(self) -> dict:
        return {"endpoint": self._endpoint(), "turns": self._turns, "api": self.api}

    def get_events(self) -> list:
        return []

    def cleanup(self) -> None:
        pass

    # -- wire -----------------------------------------------------------------

    def _endpoint(self) -> str:
        if self.api == "ollama":
            return f"{self.base_url}/api/chat"
        return f"{self.base_url}/v1/chat/completions"

    def _payload(self, messages: Sequence[Message]) -> dict:
        wire = []
        if self.system:
            wire.append({"role": "system", "content": self.system})
        wire += [{"role": m.role, "content": m.content} for m in messages]
        if self.api == "ollama":
            return {"model": self.model, "messages": wire, "stream": False,
                    "options": {"temperature": 0.0}}
        return {"model": self.model, "messages": wire, "stream": False, "temperature": 0.0}

    @staticmethod
    def _extract(api: str, raw: bytes) -> str:
        data = json.loads(raw.decode("utf-8"))
        if api == "ollama":
            return data["message"]["content"]
        return data["choices"][0]["message"]["content"]

    def send(self, messages: Sequence[Message]) -> TargetResponse:
        self._turns += 1
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps(self._payload(messages)).encode("utf-8")
        started = time.monotonic()
        try:
            status, raw = self.transport(self._endpoint(), body, headers, self.timeout)
        except Exception as exc:  # a transport must never escape the adapter
            return TargetResponse(content="", error=f"transport error: {exc}")
        latency = int((time.monotonic() - started) * 1000)
        if not status:
            return TargetResponse(content="", latency_ms=latency,
                                  error=f"cannot reach target: {raw.decode('utf-8','replace')[:300]}")
        if status >= 400:
            return TargetResponse(content="", latency_ms=latency,
                                  error=f"target HTTP {status}: {raw.decode('utf-8','replace')[:300]}")
        try:
            content = self._extract(self.api, raw)
        except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError) as exc:
            return TargetResponse(content="", latency_ms=latency,
                                  error=f"unparseable target reply: {exc}")
        if not isinstance(content, str):
            return TargetResponse(content="", latency_ms=latency,
                                  error="target reply content was not text")
        return TargetResponse(content=content, model=self.model, latency_ms=latency)
