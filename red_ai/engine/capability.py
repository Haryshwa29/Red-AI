"""
Capability: one uniform shape over every way RED-AI can act on a target.

The control plane does not know how to inject a prompt or scan a port; it knows
how to route to a *capability* and let that capability execute behind its own
signed scope and gate. This is the integration seam that makes one engine span
the LLM-interface attacks and the network recon engine without either knowing
about the other.

Hard wall preserved: the recon engine never imports the LLM engine and vice
versa. This adapter module sits ABOVE both and may import both; the wall is
between the two execution engines, not above them.

A capability PROPOSES and EXECUTES within its scope; it never widens scope. The
per-action gate inside each underlying controller remains the sole authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from red_ai.contracts.domain import Objective, TargetProfile
from red_ai.contracts.scope import Scope


@dataclass
class Engagement:
    """One authorized engagement handed to the control plane.

    ``kind`` selects the capability class. For ``llm`` the scope/profile/adapter/
    objectives are set; for ``recon`` the recon_scope is set. Keeping both in one
    object lets the router treat them uniformly while each capability reads only
    the fields it needs."""
    kind: str                                  # "llm" | "recon"
    scope: Optional[Scope] = None
    profile: Optional[TargetProfile] = None
    adapter: object = None
    objectives: tuple[Objective, ...] = ()
    recon_scope: object = None                 # red_ai.recon.scope.ReconScope
    provider: object = None
    cancel_file: Optional[Path] = None

    def __post_init__(self) -> None:
        if self.kind not in ("llm", "recon"):
            raise ValueError("Engagement.kind must be 'llm' or 'recon'")
        if self.kind == "llm" and (self.scope is None or self.profile is None or self.adapter is None):
            raise ValueError("llm engagement needs scope, profile and adapter")
        if self.kind == "recon" and self.recon_scope is None:
            raise ValueError("recon engagement needs a recon_scope")

    @property
    def environment(self) -> str:
        if self.kind == "llm":
            return self.scope.environment
        return getattr(self.recon_scope, "environment", "owned")

    @property
    def target_name(self) -> str:
        if self.kind == "llm":
            return self.profile.name
        return ", ".join(getattr(self.recon_scope, "hosts", ()) or ["?"])


@dataclass
class CapabilityResult:
    capability_id: str
    run_dir: Path
    summary: dict
    findings: list = field(default_factory=list)
    report_path: Optional[Path] = None


@runtime_checkable
class Capability(Protocol):
    """A registered way to act on a target. New rungs are new capabilities."""
    id: str
    name: str
    kind: str                                  # "llm" | "recon"

    def applies_to(self, engagement: Engagement) -> bool: ...
    def covers_techniques(self) -> tuple[str, ...]: ...
    def execute(self, engagement: Engagement, knowledge, out_dir: Path) -> CapabilityResult: ...


class LLMSkillCapability:
    """Wraps a registered LLM Skill and drives it through the existing Controller.

    Execution, gating, evidence, detection and reproduction all stay in the
    battle-tested ``control.controller.Controller``; this adapter only presents
    the skill to the control plane as a routable capability and feeds it the
    knowledge-derived priors."""
    kind = "llm"

    def __init__(self, skill) -> None:
        self.skill = skill
        self.id = f"llm:{skill.id}"
        self.name = skill.name

    def applies_to(self, engagement: Engagement) -> bool:
        return engagement.kind == "llm"

    def covers_techniques(self) -> tuple[str, ...]:
        return tuple(t.value for t in getattr(self.skill, "techniques", ()))

    def execute(self, engagement: Engagement, knowledge, out_dir: Path) -> CapabilityResult:
        # Imported here to keep the module import graph shallow and the recon
        # path free of any LLM-controller import at module load.
        from red_ai.control.controller import Controller
        from red_ai.reporting.report import write_report

        controller = Controller(
            engagement.scope, engagement.adapter, out_dir, self.skill,
            cancel_file=engagement.cancel_file, provider=engagement.provider)
        summary = controller.run(
            engagement.profile, list(engagement.objectives),
            memory=knowledge.priors_for_controller())
        report = None
        try:
            report = write_report(out_dir)
        except Exception:  # report is a derived view; never fail the run on it
            report = None
        return CapabilityResult(capability_id=self.id, run_dir=Path(out_dir),
                                summary=summary, findings=summary.get("findings", []),
                                report_path=report)


class ReconCapability:
    """Wraps the network recon engine as a routable capability.

    The control plane routes here when the engagement is a recon engagement. The
    recon engine keeps its own signed ReconScope, its own gate and its own
    evidence; this adapter adds nothing to its authority."""
    kind = "recon"
    id = "recon:tcp_connect"
    name = "Network recon (read-only TCP connect)"

    def applies_to(self, engagement: Engagement) -> bool:
        return engagement.kind == "recon"

    def covers_techniques(self) -> tuple[str, ...]:
        return ("port_discovery",)

    def execute(self, engagement: Engagement, knowledge, out_dir: Path) -> CapabilityResult:
        from red_ai.recon.controller import ReconController
        controller = ReconController(engagement.recon_scope, out_dir,
                                     provider=engagement.provider,
                                     cancel_file=engagement.cancel_file)
        summary = controller.run()
        return CapabilityResult(capability_id=self.id, run_dir=Path(out_dir),
                                summary=summary, findings=summary.get("open", []),
                                report_path=None)
