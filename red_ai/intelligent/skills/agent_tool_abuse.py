"""Skill #2: agent & tool abuse.

The second rung of the ladder, and the demonstration that a new target family
needs a new Skill -- not a new engine. It reuses the target-agnostic adaptive
planner UNCHANGED; all that is new is the technique framings (added to the
shared AttackTechnique space), the target adapter, and the deterministic
tool-abuse detectors this skill adds to the ladder.
"""
from __future__ import annotations

from typing import Optional

from red_ai.contracts.domain import AttackTechnique, TargetProfile
from red_ai.contracts.interfaces import ModelProvider, Planner
from red_ai.detection.ladder import DetectorLadder
from red_ai.detection.tool_abuse import ToolExfiltrationDetector
from red_ai.intelligent.planner import AdaptivePlanner
from red_ai.intelligent.planner_model import ModelDrivenPlanner


class AgentToolAbuseSkill:
    """Implements contracts.interfaces.Skill."""

    id = "agent_tool_abuse"
    name = "Agent & tool abuse"
    techniques = (
        AttackTechnique.TOOL_INVOCATION_COERCION,
        AttackTechnique.INDIRECT_TOOL_INJECTION,
        AttackTechnique.EXCESSIVE_AGENCY_PROBE,
        AttackTechnique.INSTRUCTION_OVERRIDE,
        AttackTechnique.AUTHORITY_IMPERSONATION,
        AttackTechnique.DIRECT_REQUEST,
    )

    def build_ladder(self, profile: TargetProfile, semantic=None) -> DetectorLadder:
        # Profile prohibitions wire the tier-2 UnauthorizedToolCallDetector via
        # the registry; the tier-1 tool-exfiltration canary detector is a
        # default of this skill, exactly as CanaryDetector is for text.
        ladder = DetectorLadder.from_profile(profile, semantic=semantic)
        ladder.deterministic.append(ToolExfiltrationDetector())
        return ladder

    def make_planner(self, provider: Optional[ModelProvider] = None) -> Planner:
        # Deliberately the SAME planner the prompt-injection skill uses: the
        # explore/exploit search is target-agnostic, and proving that is the
        # entire point of this rung.
        if provider is None:
            return AdaptivePlanner()
        return ModelDrivenPlanner(provider=provider)
