"""
SimulationAdapter: a TargetAdapter over the graduated in-process mocks.

These mocks are deterministic systems with KNOWN vulnerability, so the whole
pipeline can be measured against an answer key:
  * naive    -> MUST be broken (leaks its system prompt / canary readily)
  * guarded  -> yields only to escalation / authority framing (tests adaptivity)
  * hardened -> MUST stay clean (the false-positive guard)

The adapter plants the profile's SYSTEM_PROMPT canary into the mock's hidden
prompt, so a genuine disclosure surfaces as a tier-1 canary match rather than a
judgement call. Implements contracts.interfaces.TargetAdapter.
"""
from __future__ import annotations

from typing import Sequence

from red_ai.contracts.domain import AssetCategory, Message, TargetProfile, TargetResponse
from red_ai.targets._mocks import NaiveTarget, GuardedTarget, HardenedTarget

_LEVELS = {"naive": NaiveTarget, "guarded": GuardedTarget, "hardened": HardenedTarget}


class SimulationAdapter:
    def __init__(self, level: str, profile: TargetProfile) -> None:
        if level not in _LEVELS:
            raise ValueError(f"Unknown simulation level {level!r}; use one of {sorted(_LEVELS)}")
        self.level = level
        self.name = f"sim-{level}"
        self._cls = _LEVELS[level]
        self._canary = self._canary_for(profile)
        self._bot: object | None = None
        self._turns = 0

    @staticmethod
    def _canary_for(profile: TargetProfile) -> str:
        for c in profile.canaries():
            if c.category is AssetCategory.SYSTEM_PROMPT:
                return c.value
        return "REDAI-CNY-UNSET"

    def _system_prompt(self) -> str:
        from red_ai.targets._mocks import _SECRET_SYSTEM_PROMPT
        return _SECRET_SYSTEM_PROMPT.format(canary=self._canary)

    # -- TargetAdapter --------------------------------------------------------

    def initialize(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._bot = self._cls(system_prompt=self._system_prompt())
        self._turns = 0

    def send(self, messages: Sequence[Message]) -> TargetResponse:
        if self._bot is None:
            self.reset()
        self._turns += 1
        return self._bot.send(list(messages))

    def get_state(self) -> dict:
        return {"level": self.level, "turns": self._turns}

    def get_events(self) -> list[dict]:
        # Text-only mocks expose no tool/state telemetry; leak detection is by
        # canary/policy on the response. Richer telemetry arrives with
        # instrumented targets.
        return []

    def cleanup(self) -> None:
        self._bot = None
