"""
Component interfaces as typing.Protocols. Structural typing means an
implementation only has to match the shape -- no base-class import, no lock-in,
and plugins never depend on RED-AI internals.

The split that matters: the intelligent components (ModelProvider, Planner,
Skill) PROPOSE; the control components execute and judge. A TargetAdapter is
the only thing that talks to the system under test, so the reasoning layer is
identical regardless of whether the target is a mock, an HTTP app, or (later) a
networked host.
"""
from __future__ import annotations

from typing import Optional, Protocol, Sequence, runtime_checkable

from red_ai.contracts.domain import (
    AttackTechnique, Attempt, Finding, Message, Objective, ScanResult,
    Signal, TargetProfile, TargetResponse, Turn,
)
from red_ai.contracts.proposal import Proposal


@runtime_checkable
class TargetAdapter(Protocol):
    """Transport boundary to the system under test. Never raises on target-side
    failure -- errors come back inside TargetResponse.error so an errored path
    is recorded as inconclusive, never as a successful defence."""
    name: str

    def initialize(self) -> None: ...
    def reset(self) -> None: ...
    def send(self, messages: Sequence[Message]) -> TargetResponse: ...
    def get_state(self) -> dict: ...
    def get_events(self) -> list[dict]: ...
    def cleanup(self) -> None: ...


@runtime_checkable
class ModelProvider(Protocol):
    """RED-AI's own model backend (used by model-driven skills). Mockable so the
    test suite never needs a network or a paid API."""
    name: str

    def generate(self, messages: Sequence[Message], **options) -> str: ...
    def supports_tools(self) -> bool: ...
    def get_model_info(self) -> dict: ...


@runtime_checkable
class Detector(Protocol):
    """Inspects one exchange and emits zero or more signals. Pure and
    side-effect free, so a stored transcript can be re-judged later."""
    id: str
    tier: int

    def inspect(self, profile: TargetProfile, attacker_message: str,
                response: TargetResponse) -> list[Signal]: ...


@runtime_checkable
class Planner(Protocol):
    """Chooses the next move against an objective. should_continue must never
    treat a refusal as terminal."""
    name: str

    def begin(self, objective: Objective) -> None: ...
    def next_technique(self, objective: Objective, history: list[Turn]) -> Optional[AttackTechnique]: ...
    def craft_message(self, profile: TargetProfile, objective: Objective,
                      technique: AttackTechnique, history: list[Turn]) -> str: ...
    def should_continue(self, objective: Objective, history: list[Turn]) -> bool: ...


@runtime_checkable
class Skill(Protocol):
    """A registered, human-authored attack capability. The growth seam: new
    rungs of the ladder are new Skills. A skill declares its technique space and
    the detectors that prove it, and builds a planner (optionally model-driven).
    The model USES a skill; only the operator GRANTS one (by registering it)."""
    id: str
    name: str
    techniques: tuple[AttackTechnique, ...]

    def build_ladder(self, profile: TargetProfile): ...  # -> DetectorLadder
    def make_planner(self, provider: Optional[ModelProvider] = None) -> Planner: ...


@runtime_checkable
class Adjudicator(Protocol):
    """Turns raw signals into findings and routes the ambiguous ones to review."""
    def adjudicate(self, profile: TargetProfile, attempts: list[Attempt]) -> list[Finding]: ...


@runtime_checkable
class Reporter(Protocol):
    format: str
    def render(self, result: ScanResult) -> str: ...
