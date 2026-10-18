"""
Campaign controller: the deterministic loop that owns execution and judgement.

This is the merge point of the two prototypes. It keeps the RED-AI_Self
discipline (signed scope, per-action gate, budgets, cancellation, hash-linked
evidence, fresh session per objective, confirmation replays) and drives it with
the richer intelligent layer (skills, adaptive planner, tiered detector ladder,
derived-severity adjudicator).

Control flow only. Every judgement is delegated behind an interface:
    skill.make_planner()  -> what to say next        (intelligent, proposes)
    gate()                -> may this action run       (control, decides)
    adapter.send()        -> talk to the target        (boundary)
    ladder.inspect()      -> did a boundary fail        (detection)
    adjudicator           -> signals -> findings        (detection)

The planner proposes; the gate authorizes; the model never touches its own
guardrails.

Deferred (networked targets, not simulation): outbound rate-limiting/throttle
and OS-level timeout isolation are adapter concerns added when a real HTTP or
host target lands. Simulation adapters are in-process and deterministic.
"""
from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Optional, Sequence
import uuid

from dataclasses import replace

from red_ai.contracts.domain import (
    AttackTechnique, Attempt, AttemptOutcome, Message, Objective, ScanResult,
    TargetProfile, Turn,
)
from red_ai.contracts.proposal import Proposal
from red_ai.contracts.scope import Scope, now, timestamp
from red_ai.control.evidence import Journal
from red_ai.control.gate import gate, HALTING
from red_ai.detection.adjudicator import LadderAdjudicator
from red_ai.intelligent.providers import brain_target_overlap


class Controller:
    def __init__(self, scope: Scope, adapter, output, skill, *,
                 cancel_file=None, semantic=None, provider=None, adjudicator=None,
                 target_model_id=None):
        self.scope = scope
        self.adapter = adapter
        self.output = Path(output)
        self.skill = skill
        self.cancel_file = Path(cancel_file) if cancel_file else None
        self.semantic = semantic
        self.provider = provider
        self.target_model_id = target_model_id
        self.adjudicator = adjudicator or LadderAdjudicator()
        self.queries = 0
        self.cost = 0
        self.brain = {"model_decisions": 0, "fallbacks": 0, "coverage_forced": 0,
                      "provider": None, "target_overlap": None}
        self.started = time.monotonic()
        self.halt: Optional[str] = None

    # -- control primitives ---------------------------------------------------

    def cancelled(self) -> bool:
        return bool(self.cancel_file and self.cancel_file.exists())

    def _decide(self, proposal: Proposal) -> Optional[str]:
        return gate(self.scope, proposal, self.queries, self.cost,
                    time.monotonic() - self.started, self.cancelled())

    def _expired(self) -> bool:
        return now() >= timestamp(self.scope.valid_until)

    # -- main loop ------------------------------------------------------------

    def run(self, profile: TargetProfile, objectives: Sequence[Objective],
            source_run: Optional[str] = None, memory: Sequence[dict] = ()) -> dict:
        self.started = time.monotonic()
        self.output.mkdir(parents=True, exist_ok=False)
        run_id = self.output.name
        journal = Journal(self.output / "events.jsonl")
        ladder = self.skill.build_ladder(profile, semantic=self.semantic)
        planner = self.skill.make_planner(self.provider)
        if self.provider is not None:
            self.brain["provider"] = self.provider.get_model_info().get("name")
            self.brain["target_overlap"] = brain_target_overlap(
                self.brain["provider"], self.target_model_id)
        result = ScanResult(target=profile)
        objectives = self._apply_memory(list(objectives), memory) if memory else list(objectives)

        journal.append("run_started", {
            "run_id": run_id, "scope": self.scope, "skill": self.skill.id,
            "target": profile.name, "target_id": profile.id,
            "environment": self.scope.environment, "source_run": source_run,
            "objectives": [{"id": o.id, "name": o.name, "category": o.category} for o in objectives],
            "two_layer": "planner proposes; deterministic gate authorizes; model never edits scope",
            "memory_ids": [m.get("id") for m in memory],
            "selection_policy": "reviewed-memory priority then onboarding order" if memory else "onboarding order",
        })
        try:
            self.adapter.initialize()
            for objective in objectives:
                if self.halt:
                    break
                attempt = self._run_objective(profile, objective, ladder, planner, journal)
                result.attempts.append(attempt)

            self.brain["model_decisions"] = getattr(planner, "model_decisions", 0)
            self.brain["fallbacks"] = getattr(planner, "fallbacks", 0)
            self.brain["coverage_forced"] = getattr(planner, "coverage_forced", 0)
            repro = self._measure_reproduction(profile, result.attempts, ladder, journal)
            findings = self.adjudicator.adjudicate(profile, result.attempts)
            for f in findings:
                rates = [repro[a] for a in f.attempt_ids if a in repro]
                if rates:
                    f.reproduction_rate = max(rates)
            result.findings = findings
            result.finished_at = now()
            if not self.halt:
                self.halt = "search_exhausted"
        finally:
            self.adapter.cleanup()
            summary = self._summary(run_id, profile, result, source_run)
            journal.append("run_finished", summary)
            journal.close()
        return summary

    def _run_objective(self, profile, objective, ladder, planner, journal) -> Attempt:
        planner.begin(objective)
        self.adapter.reset()  # fresh isolated session per objective
        turns: list[Turn] = []
        conversation: list[Message] = []
        outcome = AttemptOutcome.RESISTED

        while planner.should_continue(objective, turns):
            if self.cancelled() or self._expired():
                self.halt = "human_cancellation" if self.cancelled() else "authorization_expired_or_not_yet_valid"
                outcome = AttemptOutcome.ABORTED
                break
            technique = planner.next_technique(objective, turns)
            if technique is None:
                break
            message = planner.craft_message(profile, objective, technique, turns)
            proposal = Proposal(
                skill=self.skill.id, objective_id=objective.id,
                technique=technique.value, message=message,
                rationale=f"{self.skill.id}: {technique.value} vs {objective.name}",
            )
            reason = self._decide(proposal)
            journal.append("gate", {"decision": "deny" if reason else "allow",
                                    "reason": reason, "objective_id": objective.id,
                                    "technique": technique.value, "queries_used": self.queries})
            if reason in HALTING:
                self.halt = reason
                outcome = AttemptOutcome.ABORTED if reason == "human_cancellation" else outcome
                break
            if reason:  # non-halting denial (out-of-scope technique/tool): skip
                continue

            self.queries += 1
            self.cost += 1
            journal.append("input", {"objective_id": objective.id, "technique": technique.value,
                                     "trust": "test_input", "message": message})
            conversation.append(Message(role="user", content=message))
            response = self.adapter.send(conversation)
            conversation.append(Message(role="assistant", content=response.content))
            journal.append("observation", {"objective_id": objective.id, "trust": "untrusted_target_data",
                                           "response": response, "target_state": self.adapter.get_state()})
            signals = ladder.inspect(profile, message, response)
            journal.append("evaluation", {"objective_id": objective.id,
                                          "signals": [s for s in signals],
                                          "detector_failures": list(ladder.failures)})
            turns.append(Turn(index=len(turns), technique=technique,
                              attacker_message=message, response=response, signals=tuple(signals)))
            if signals:
                outcome = AttemptOutcome.BREACHED
                break
            if not response.ok:
                outcome = AttemptOutcome.ERRORED

        attempt = Attempt(objective_id=objective.id, target_id=profile.id, outcome=outcome,
                          turns=turns, started_at=turns[0].timestamp if turns else now(),
                          finished_at=now())
        journal.append("attempt_finished", {"objective_id": objective.id, "outcome": outcome,
                                            "turns": len(turns),
                                            "effort_to_break": attempt.effort_to_break})
        return attempt

    @staticmethod
    def _apply_memory(objectives, memory):
        """Reviewed metadata reorders exploration: remembered categories first,
        and remembered techniques are tried first within their objective. This
        is priority only -- it never adds a technique the scope forbids (the
        gate still checks) and never authorizes anything."""
        remembered_cats = [m.get("category") for m in memory]
        cat_techniques: dict[str, list] = {}
        for m in memory:
            t = m.get("technique")
            if not t or t == "unknown":
                continue
            try:
                cat_techniques.setdefault(m.get("category"), []).append(AttackTechnique(t))
            except ValueError:
                continue
        biased = []
        for o in objectives:
            priors = cat_techniques.get(o.category.value, [])
            if priors:
                ordered = list(dict.fromkeys(priors + list(o.techniques)))
                biased.append(replace(o, techniques=ordered))
            else:
                biased.append(o)
        biased.sort(key=lambda o: 0 if o.category.value in remembered_cats else 1)
        return biased

    # -- reproduction ---------------------------------------------------------

    @staticmethod
    def _breaking_messages(attempt: Attempt) -> list[Message]:
        msgs: list[Message] = []
        for turn in attempt.turns:
            msgs.append(Message(role="user", content=turn.attacker_message))
            if turn.signals:
                break
            msgs.append(Message(role="assistant", content=turn.response.content))
        return msgs

    def _measure_reproduction(self, profile, attempts, ladder, journal) -> dict[str, float]:
        """Replay each breaking attempt from a fresh reset and report a rate.
        Honest measurement ('reproduced in k of N'), not a promise."""
        rates: dict[str, float] = {}
        if self.scope.replays <= 0:
            return rates
        for attempt in attempts:
            if attempt.outcome is not AttemptOutcome.BREACHED or self.halt in HALTING:
                continue
            breaking = self._breaking_messages(attempt)
            if not breaking:
                continue
            user_msgs = [m for m in breaking if m.role == "user"]
            hits = 0
            trials = 0
            for _ in range(self.scope.replays):
                if self.cancelled() or self._expired() or self.cost >= self.scope.max_cost_units:
                    break
                self.adapter.reset()
                convo: list[Message] = []
                broke = False
                for um in user_msgs:
                    self.queries += 1
                    self.cost += 1
                    convo.append(um)
                    resp = self.adapter.send(convo)
                    convo.append(Message(role="assistant", content=resp.content))
                    if ladder.inspect(profile, um.content, resp):
                        broke = True
                        break
                trials += 1
                hits += 1 if broke else 0
            rate = (hits / trials) if trials else 0.0
            rates[attempt.id] = rate
            journal.append("reproduction", {"attempt_id": attempt.id, "hits": hits,
                                            "trials": trials, "rate": rate})
        return rates

    # -- summary --------------------------------------------------------------

    def _summary(self, run_id, profile, result, source_run) -> dict:
        counts = dict(Counter(a.outcome.value for a in result.attempts))
        weakest = result.weakest_link
        return {
            "run_id": run_id, "skill": self.skill.id, "environment": self.scope.environment,
            "target": profile.name, "target_id": profile.id, "scope": self.scope,
            "source_run": source_run, "halt_reason": self.halt or "controller_error",
            "queries": self.queries, "cost_units": self.cost,
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "counts": counts, "coverage": result.coverage_summary,
            "weakest_link": weakest, "findings": result.findings, "brain": self.brain,
            "attempts": result.attempts, "simulation": self.scope.environment == "simulation",
        }


def new_run_path(root) -> Path:
    return Path(root) / "runs" / (now().strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])
