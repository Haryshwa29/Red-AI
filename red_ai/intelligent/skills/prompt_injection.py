"""Skill #1: prompt injection and social engineering.

A Skill is the growth seam. It bundles the technique space, the planner that
drives it, and the detector ladder that proves it. New rungs of the ladder
(indirect/RAG, multi-turn agent, web, network) arrive as NEW skills registered
here -- the model uses a skill, it never grants itself one.
"""
from __future__ import annotations

from typing import Optional

from red_ai.contracts.domain import AttackTechnique, TargetProfile
from red_ai.contracts.interfaces import ModelProvider, Planner
from red_ai.detection.ladder import DetectorLadder
from red_ai.intelligent.planner import AdaptivePlanner
from red_ai.intelligent.planner_model import ModelDrivenPlanner


class PromptInjectionSkill:
    """Implements contracts.interfaces.Skill."""
    id = "prompt_injection"
    name = "Prompt injection & social engineering"
    techniques = tuple(AttackTechnique)  # the full phase-1 technique space

    def build_ladder(self, profile: TargetProfile, semantic=None) -> DetectorLadder:
        # Deterministic-first: canary (tier 1) + the profile's policy detectors
        # (tier 2). Semantic (tier 3) is optional and off by default.
        return DetectorLadder.from_profile(profile, semantic=semantic)

    def make_planner(self, provider: Optional[ModelProvider] = None) -> Planner:
        # No brain configured -> the deterministic, seeded heuristic (also the
        # fallback at every step when a configured brain errs). A configured
        # provider upgrades technique *selection* to the model while wording
        # stays template-based and the gate still authorises every move.
        if provider is None:
            return AdaptivePlanner()
        return ModelDrivenPlanner(provider=provider)
