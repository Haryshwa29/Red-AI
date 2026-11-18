"""
ToolAgentAdapter: a TargetAdapter over the graduated mock tool-using agents.

This is the third target family behind the TargetAdapter protocol (after the
in-process chat simulation and the live HTTP chat endpoint). The point of
building it is to demonstrate the property the protocol was designed for: the
reasoning layer -- planner, gate, detector ladder, adjudicator -- does not
change when the target changes. Only the transport and the telemetry shape
differ.

Tool-call telemetry rides in ``TargetResponse.raw["tool_calls"]`` and is also
exposed via ``get_events`` for a richer audit record. Detectors read that
structure directly; nothing in the Detector contract changed to carry it. The
adapter plants the profile's SYSTEM_PROMPT canary in the agent's hidden prompt
exactly as the chat simulation does, so a genuine tool-based exfiltration of
that prompt surfaces as a tier-1 (zero-false-positive) match, not a judgement.

A live tool-agent adapter (talking to a real MCP / function-calling endpoint and
reading its tool-call trace off the wire) is the next rung; it slots in here
behind the same protocol without touching the engine. Stated, not built.
"""
from __future__ import annotations

from typing import Sequence

from red_ai.contracts.domain import AssetCategory, Message, TargetProfile, TargetResponse
from red_ai.targets._agent_mocks import (
    GuardedToolAgent, HardenedToolAgent, NaiveToolAgent,
)

_LEVELS = {"naive": NaiveToolAgent, "guarded": GuardedToolAgent, "hardened": HardenedToolAgent}


class ToolAgentAdapter:
    """Implements contracts.interfaces.TargetAdapter."""

    def __init__(self, level: str, profile: TargetProfile) -> None:
        if level not in _LEVELS:
            raise ValueError(f"Unknown agent level {level!r}; use one of {sorted(_LEVELS)}")
        self.level = level
        self.name = f"tool-agent-{level}"
        self._cls = _LEVELS[level]
        self._canary = self._canary_for(profile)
        self._agent = None
        self._turns = 0

    @staticmethod
    def _canary_for(profile: TargetProfile) -> str:
        for c in profile.canaries():
            if c.category is AssetCategory.SYSTEM_PROMPT:
                return c.value
        return "REDAI-CNY-UNSET"

    def _system_prompt(self) -> str:
        from red_ai.targets._agent_mocks import _SECRET_AGENT_PROMPT
        return _SECRET_AGENT_PROMPT.format(canary=self._canary)

    # -- TargetAdapter --------------------------------------------------------

    def initialize(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._agent = self._cls(system_prompt=self._system_prompt())
        self._turns = 0

    def send(self, messages: Sequence[Message]) -> TargetResponse:
        if self._agent is None:
            self.reset()
        self._turns += 1
        return self._agent.send(list(messages))

    def get_state(self) -> dict:
        return {"level": self.level, "turns": self._turns,
                "tool_calls": len(self._agent.events()) if self._agent else 0}

    def get_events(self) -> list[dict]:
        return self._agent.events() if self._agent else []

    def cleanup(self) -> None:
        self._agent = None
