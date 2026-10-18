"""Control-plane engine: unifies knowledge, capability routing, hypotheses,
execution (delegated) and learning behind one loop. See orchestrator.ControlPlane."""
from __future__ import annotations

from red_ai.engine.capability import (
    Engagement, CapabilityResult, LLMSkillCapability, ReconCapability,
)
from red_ai.engine.knowledge import KnowledgeBase
from red_ai.engine.router import CapabilityRouter, RoutingDecision
from red_ai.engine.hypothesis import Hypothesis, HypothesisPlanner
from red_ai.engine.orchestrator import ControlPlane, default_capabilities

__all__ = [
    "Engagement", "CapabilityResult", "LLMSkillCapability", "ReconCapability",
    "KnowledgeBase", "CapabilityRouter", "RoutingDecision",
    "Hypothesis", "HypothesisPlanner", "ControlPlane", "default_capabilities",
]
