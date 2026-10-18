"""
Adaptive attack planner: explore techniques, exploit the ones that give.

Purpose
-------
Decides the next move against an objective and when to stop. This is the
component that makes RedAI an *adaptive* attacker rather than a static payload
replayer, and it is where the interesting engineering lives.

Design rationale
----------------
The planner runs a lightweight explore/exploit search over the technique space:

*   **Explore.** Cycle through the objective's candidate techniques, cheapest
    and highest-signal first (ordering set by the objective generator).
*   **Read the reaction.** After each turn, ``attack.signals.analyse`` scores
    how much the target *gave*. This is the gradient the search follows.
*   **Exploit.** When a technique produces give (hedging, partial compliance,
    deflection), stay on that line and escalate - press for the specific asset -
    instead of moving on. A crack that widens is worth more turns than an
    untried technique.
*   **Never conclude safety from a refusal.** A hard refusal retires *one
    framing*, not the objective. The planner keeps going until every candidate
    technique is exhausted or the turn budget runs out. Only then is the
    objective recorded as RESISTED, and even that is phrased as "not broken in N
    turns", never "safe".

This is intentionally not a bandit or RL agent yet. A transparent, seeded
heuristic is reproducible and explainable - every move can be justified in the
report - which matters more in phase 1 than optimality. The interface is built
so a learned policy can replace the heuristic later without changing anything
downstream.

Known limitations
-----------------
*   No cross-objective learning within a scan. A technique that broke objective
    A is not yet prioritised for objective B.
*   Escalation depth per line is capped by ``max_escalations`` to avoid spending
    the whole budget digging a single dry hole.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from red_ai.contracts.domain import AttackTechnique, Objective, Turn
from red_ai.intelligent.payloads import RenderContext, TemplateBank
from red_ai.intelligent.signals import ResistanceReading, SignalAnalysis, analyse


@dataclass
class _LineState:
    """Tracks the current line of attack (one technique being pressed)."""

    technique: AttackTechnique
    escalations: int = 0


@dataclass
class AdaptivePlanner:
    """
    Explore/exploit planner over a fixed technique space.

    Implements ``red_ai.contracts.interfaces.AttackPlanner``.

    Args:
        bank: Template renderer. Deterministic given its seed.
        max_escalations: How many follow-up turns to spend pressing a single
            technique that is giving, before rotating to a new one.
    """

    bank: TemplateBank = field(default_factory=TemplateBank)
    max_escalations: int = 2
    name: str = "adaptive"

    # Per-objective mutable search state, keyed by objective id. Reset via
    # ``begin``.
    _remaining: dict[str, list[AttackTechnique]] = field(default_factory=dict, init=False)
    _line: dict[str, _LineState] = field(default_factory=dict, init=False)

    def begin(self, objective: Objective) -> None:
        """Initialise search state for an objective. Call once per attempt."""
        self._remaining[objective.id] = list(objective.techniques) or [
            AttackTechnique.DIRECT_REQUEST
        ]
        self._line.pop(objective.id, None)

    # -- reading the last turn ------------------------------------------------

    @staticmethod
    def _last_analysis(history: list[Turn]) -> SignalAnalysis | None:
        if not history:
            return None
        last = history[-1]
        breached = bool(last.signals)
        return analyse(last.response.content, errored=not last.response.ok, breached=breached)

    # -- interface methods ----------------------------------------------------

    def next_technique(self, objective: Objective, history: list[Turn]) -> AttackTechnique | None:
        """
        Choose the next technique.

        Exploit path: if the last turn gave and we have escalation budget left
        on the current line, stay on it. Explore path: otherwise pop the next
        candidate technique.
        """
        if objective.id not in self._remaining:
            self.begin(objective)

        analysis = self._last_analysis(history)
        line = self._line.get(objective.id)

        # Exploit: the current line is giving and not yet exhausted.
        if (
            line is not None
            and analysis is not None
            and analysis.worth_escalating
            and line.escalations < self.max_escalations
            and analysis.reading is not ResistanceReading.ERROR
        ):
            line.escalations += 1
            return line.technique

        # Explore: rotate to the next untried technique. Skip any technique
        # already present in the transcript so that a state/history desync (or a
        # future re-planner) can never re-issue a framing that has already been
        # shown to fail.
        tried = {t.technique for t in history}
        remaining = self._remaining.get(objective.id, [])
        while remaining:
            technique = remaining.pop(0)
            if technique in tried:
                continue
            self._line[objective.id] = _LineState(technique=technique)
            return technique
        return None

    def craft_message(
        self,
        profile,
        objective: Objective,
        technique: AttackTechnique,
        history: list[Turn],
    ) -> str:
        analysis = self._last_analysis(history)
        ctx = RenderContext(
            objective=objective,
            bot_purpose=profile.bot_purpose,
            turn_index=len(history),
            last_reading_note=analysis.note if analysis else "",
            give=analysis.give if analysis else 0.0,
        )
        return self.bank.render(technique, ctx)

    def should_continue(self, objective: Objective, history: list[Turn]) -> bool:
        """
        Whether to spend another turn.

        Stops only when the turn budget is spent or every technique has been
        tried and no line is still giving. A refusal never stops the loop -
        that is the whole point.
        """
        if len(history) >= objective.max_turns:
            return False

        if objective.id not in self._remaining:
            self.begin(objective)

        remaining = self._remaining.get(objective.id, [])
        line = self._line.get(objective.id)
        analysis = self._last_analysis(history)

        still_escalating = (
            line is not None
            and analysis is not None
            and analysis.worth_escalating
            and line.escalations < self.max_escalations
        )
        return bool(remaining) or bool(still_escalating)
