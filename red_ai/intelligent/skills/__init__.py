"""Skill registry. Registration is how an operator GRANTS a capability; the
model can only use what is registered here."""
from __future__ import annotations

from red_ai.intelligent.skills.prompt_injection import PromptInjectionSkill
from red_ai.intelligent.skills.agent_tool_abuse import AgentToolAbuseSkill

_REGISTRY: dict[str, object] = {}


def register(skill) -> None:
    if not getattr(skill, "id", None):
        raise ValueError("A skill must have an id")
    _REGISTRY[skill.id] = skill


def get(skill_id: str):
    if skill_id not in _REGISTRY:
        raise KeyError(f"Unknown skill: {skill_id!r}. Registered: {sorted(_REGISTRY)}")
    return _REGISTRY[skill_id]


def all_skills() -> list:
    return list(_REGISTRY.values())


register(PromptInjectionSkill())
register(AgentToolAbuseSkill())
