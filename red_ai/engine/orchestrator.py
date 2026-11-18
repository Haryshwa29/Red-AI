"""
Control plane: the top loop that realizes the engine diagram.

    OBJECTIVE (signed scope)
        -> KNOWLEDGE SYSTEM        build trusted facts (assets + reviewed priors)
        -> CAPABILITY ROUTER       pick a capability from the closed set
        -> PLAN / HYPOTHESIS       state what we expect to break, and why
        -> EXECUTION               delegate to the capability's controller
        -> EVIDENCE                the controller's own hash-linked journal
        -> KNOWLEDGE (feedback)    fold OUR observations back; quarantine target text
        -> LEARNING                surface reviewed upstream proposals (human-gated)

What this layer adds over calling a controller directly:
  * one Knowledge System feeding routing + hypotheses, with the trusted/quarantine
    split that stops a target from steering us;
  * explicit, explainable capability routing across the LLM and recon engines;
  * recorded hypotheses (expected vs observed) for honest reporting and learning;
  * a pinned knowledge snapshot so an adaptive run stays reproducible.

What it deliberately does NOT do: re-implement execution, gating, detection or
reproduction. Those stay in the controllers, which remain the sole authorities.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from red_ai.contracts.scope import now
from red_ai.control.evidence import jsonable
from red_ai.control.controller import new_run_path
from red_ai.control.memory import CaseStore
from red_ai.engine.capability import (
    Capability, Engagement, LLMSkillCapability, ReconCapability,
)
from red_ai.engine.hypothesis import Hypothesis, HypothesisPlanner
from red_ai.engine.knowledge import KnowledgeBase
from red_ai.engine.router import CapabilityRouter, RoutingDecision
from red_ai.intelligent import skills
from red_ai.learning import propose_upgrades


def default_capabilities() -> list[Capability]:
    """Every registered capability the control plane can route to.

    LLM skills come from the skill registry (operator-granted); recon is the
    network capability. New rungs appear here automatically as they register."""
    caps: list[Capability] = [LLMSkillCapability(s) for s in skills.all_skills()]
    caps.append(ReconCapability())
    return caps


class ControlPlane:
    def __init__(self, root, *, provider=None, cancel_file=None,
                 case_store_path=None, capabilities: Optional[list[Capability]] = None) -> None:
        self.root = Path(root)
        self.provider = provider
        self.cancel_file = Path(cancel_file) if cancel_file else None
        self.case_store_path = Path(case_store_path) if case_store_path else None
        self.router = CapabilityRouter(capabilities or default_capabilities())
        self.hypothesis_planner = HypothesisPlanner()

    # -- knowledge construction ---------------------------------------------

    def _load_priors(self, engagement: Engagement) -> list[dict]:
        if engagement.kind != "llm" or not self.case_store_path or not self.case_store_path.exists():
            return []
        store = CaseStore(self.case_store_path)
        try:
            return store.retrieve(engagement.profile, engagement.environment)
        finally:
            store.close()

    def _build_knowledge(self, engagement: Engagement) -> KnowledgeBase:
        if engagement.kind == "llm":
            return KnowledgeBase.from_profile(
                engagement.profile, engagement.environment,
                priors=self._load_priors(engagement))
        return KnowledgeBase(target=engagement.target_name, environment=engagement.environment)

    # -- main entry ----------------------------------------------------------

    def run(self, engagement: Engagement) -> dict:
        knowledge = self._build_knowledge(engagement)
        capability, decision = self.router.route(engagement, knowledge, self.provider)

        hypotheses: list[Hypothesis] = []
        if engagement.kind == "llm":
            hypotheses = [self.hypothesis_planner.form(o, capability.id, knowledge)
                          for o in engagement.objectives]

        out_dir = new_run_path(self.root)
        result = capability.execute(engagement, knowledge, out_dir)
        # The in-memory summary holds live dataclasses (serialized only at the
        # journal boundary). Normalize to plain JSON-safe dicts before the engine
        # reads it, so knowledge/hypotheses/manifest all consume one shape.
        summary = jsonable(result.summary)
        result.summary = summary

        # Feedback: our derived observations become trusted facts; target text is
        # quarantined inside the knowledge base, never fed back as planning input.
        knowledge.record_run(summary)
        attempts_by_obj = {a.get("objective_id"): a
                           for a in summary.get("attempts", [])}
        for h in hypotheses:
            att = attempts_by_obj.get(h.objective_id)
            if att:
                self.hypothesis_planner.update(h, att)

        learning = self._learning_block()
        manifest = self._write_manifest(result, decision, hypotheses, knowledge, learning)

        return {
            "control_plane": True,
            "run_dir": str(result.run_dir),
            "capability": capability.id,
            "routing": decision.as_dict(),
            "hypotheses": [h.as_dict() for h in hypotheses],
            "knowledge_hash": knowledge.snapshot()["knowledge_hash"],
            "evidence_quarantined": knowledge.evidence_count(),
            "learning": learning,
            "capability_summary": result.summary,
            "manifest": str(manifest),
            "report": str(result.report_path) if result.report_path else None,
        }

    # -- learning node -------------------------------------------------------

    def _learning_block(self) -> dict:
        """Surface how many reviewed upstream candidates exist. Read-only: the
        engine never auto-promotes. Export + promotion stay the human-gated
        ``red_ai learn`` path."""
        if not self.case_store_path or not self.case_store_path.exists():
            return {"upstream_candidates": 0, "note": "no reviewed memory yet"}
        store = CaseStore(self.case_store_path)
        try:
            candidates = propose_upgrades(store)
        finally:
            store.close()
        return {"upstream_candidates": len(candidates),
                "candidate_ids": [c.candidate_id for c in candidates],
                "note": "human-gated; run `red_ai learn --export` to review"}

    # -- reproducibility manifest -------------------------------------------

    def _write_manifest(self, result, decision: RoutingDecision,
                        hypotheses: list[Hypothesis], knowledge: KnowledgeBase,
                        learning: dict) -> Path:
        """Derived record of the control plane's reasoning for this run. Written
        beside the capability's hash-linked evidence (its own trust root). This
        manifest is a derived view, like summary.json/report.md -- not the
        evidence chain itself; that limit is stated, not hidden."""
        from collections import Counter
        tally = Counter(h.status for h in hypotheses)
        manifest = {
            "schema": "red_ai.control_plane.v1",
            "generated": now().isoformat(),
            "run_id": result.summary.get("run_id"),
            "capability": result.capability_id,
            "environment": result.summary.get("environment"),
            "target": result.summary.get("target") or result.summary.get("hosts"),
            "routing": decision.as_dict(),
            "hypotheses": [h.as_dict() for h in hypotheses],
            "hypothesis_scoreboard": {
                "formed": len(hypotheses),
                "supported": tally.get("supported", 0),
                "refuted": tally.get("refuted", 0),
                "open": tally.get("open", 0)},
            "knowledge_snapshot": knowledge.snapshot(),
            "brain": result.summary.get("brain"),
            "learning": learning,
            "evidence": "events.jsonl (hash-linked; the trust root)",
            "note": "Derived manifest. Reproducibility: re-running under the same "
                    "scope + knowledge_hash reasons over identical planning inputs.",
        }
        path = result.run_dir / "control_plane.json"
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return path
