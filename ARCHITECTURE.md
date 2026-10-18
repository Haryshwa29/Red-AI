# RED-AI Architecture (v1.0)

## 1. Purpose

RED-AI is an authorized adversarial tester for AI applications. It understands a
security objective, proposes attacks, executes them through a controlled
boundary, proves boundary failures with evidence, measures reproduction, and
reports the weakest link with a reconstruction. It is not a generic exploit
framework: it can decide *how* to test, never *what it is authorized to test*.

## 2. The two layers

```
            Security objective (from onboarding)
                       |
      INTELLIGENT (proposes)          CONTROL (decides, final authority)
      -----------------------         --------------------------------
        Skill (plugin)                  Scope  (signed authz + budgets)
          + Planner  ------proposal----> Gate  (deterministic allow/deny)
          + Provider                     Controller (lifecycle, budgets,
                                          cancellation, evidence journal)
                                            |
                                          Target Adapter (boundary)
                                            |
                                        TARGET APPLICATION
                                            |
        Detection ------------------------- Observation
          Ladder (tier 1/2/3) -> Signals
          Adjudicator -> Findings (derived severity)
                                            |
                                   Reproduction + Report
```

The intelligent components propose actions. The control components decide
whether an action runs. An AI-proposed action always passes the deterministic
gate before execution. The LLM never controls its own guardrails.

## 3. Components

| Module | Layer | Responsibility |
| --- | --- | --- |
| `contracts/scope` | control | Signed, immutable authorization + budgets |
| `contracts/domain` | shared | Stdlib domain model (Objective, Attempt, Signal, Finding, …) |
| `contracts/proposal` | shared | Validated action the planner emits |
| `contracts/interfaces` | shared | Protocols: TargetAdapter, ModelProvider, Skill, Planner, Detector, Adjudicator |
| `control/gate` | control | Deterministic allow/deny vs scope; halts vs denials |
| `control/evidence` | control | Append-only hash-linked journal |
| `control/controller` | control | The campaign loop; owns execution + judgement sequencing |
| `control/memory` | control | Reviewed-finding corpus (operator-attested, reproducible); priors only |
| `intelligent/planner` | intelligent | Adaptive explore/exploit over the technique space |
| `intelligent/providers` | intelligent | ModelProvider seam + offline MockProvider |
| `intelligent/skills` | intelligent | Skill registry; prompt-injection is skill #1 (the growth seam) |
| `detection/{canary,policy,ladder}` | detection | 3-tier detector ladder; deterministic-first |
| `detection/adjudicator` | detection | Signals -> findings; severity derived from stated inputs |
| `targets/simulation` | boundary | TargetAdapter over graduated mocks (naive/guarded/hardened) |
| `onboarding/{taxonomy,profile,objectives}` | intelligent | Asset inference + objective generation |
| `reporting/report` | output | Offline JSON/MD/HTML from the verified journal |
| `engine/knowledge` | engine | Knowledge System: trusted facts vs quarantined target text; priors; pinned snapshot |
| `engine/capability` | engine | Uniform Capability over LLM skills AND the recon engine (the integration seam) |
| `engine/router` | engine | Capability Router: closed-set, explainable; brain may reorder only |
| `engine/hypothesis` | engine | Plan/Hypothesis: expected-vs-observed break, recorded per objective |
| `engine/orchestrator` | engine | Control plane loop; delegates execution to the controllers |
| `learning/upstream` | learning | A->V0 upgrade proposals; generic/local split + leakage tripwire (human-gated) |

## 4. Data flow (one campaign)

1. Onboarding builds a `TargetProfile` (assets, canaries, prohibitions) and
   `ProfileObjectiveGenerator` derives objectives.
2. The `Controller` opens a hash-linked journal and records `run_started` with
   the signed scope.
3. For each objective (fresh target session): the skill's planner proposes the
   next move → the gate authorizes it against the scope → the adapter sends it →
   the detector ladder inspects the response → a `Turn` is recorded. A refusal
   demotes a framing; it never stops the loop.
4. Breaking attempts are replayed from a clean reset to measure a reproduction
   rate.
5. The adjudicator turns signals into findings with derived severity; the report
   is rendered from the verified journal.

## 5. Security considerations

- Authorization is deterministic code (signed `Scope` + `gate`), not an LLM
  judgement. Budgets, validity window, allowed techniques, and a kill switch are
  enforced before every action.
- Evidence-first: a model claim is not a finding; detector evidence is required.
- The evidence chain detects tampering against a trusted copy; it is not an
  immutable vault (local files remain writable). Stated, not hidden.
- Offline and dependency-free: no network, no third-party packages, no keys.

## 6. Known limitations (v1.0)

- Simulation targets only; no real model backend, HTTP, instrumented, or network
  targets yet.
- Tier-3 semantic detection is a declared gap: findings are tier-1/2 only, so a
  clean result is "not broken under this coverage", never proof of security.
- Hash chain has no external trust anchor; subprocess/OS isolation for hostile
  targets is an adapter concern added with real targets.

## 6b. Control plane (the unifying engine)

`engine/` is the orchestration layer from the product diagram. It does **not**
re-implement execution, gating, detection or reproduction -- those remain in the
controllers, which stay the sole authorities. It adds the coordination around
them:

```
OBJECTIVE (signed scope)
  -> KNOWLEDGE SYSTEM   trusted facts (assets + reviewed priors); target text quarantined
  -> CAPABILITY ROUTER  pick from the closed set of registered capabilities (LLM skills / recon)
  -> PLAN / HYPOTHESIS  state expected weakest technique + basis, per objective
  -> EXECUTION          delegate to the capability's controller (gate authorizes every action)
  -> EVIDENCE           the controller's own hash-linked journal
  -> KNOWLEDGE (feedback)  fold OUR observations back; quarantine raw target text
  -> LEARNING           surface reviewed upstream proposals (human-gated; never auto-applied)
```

Two safety properties are structural, not conventions:

* **The target cannot steer us.** Knowledge is split by trust. Only facts WE
  established (declared assets, reviewed priors, detector-derived observations)
  reach the strategist and router. Raw target output is quarantined as evidence
  and there is no API that folds it into planning input -- the indirect-prompt-
  injection-against-the-red-teamer defense.
* **The brain only ever reorders a closed set.** The router picks among
  registered capabilities; a model may reorder that set but cannot add to it or
  authorize execution. Any error/out-of-set reply falls back to the
  deterministic order. Same discipline as the technique-selection planner.

Each run writes `control_plane.json` beside the capability's evidence: the
routing decision, the hypotheses (expected vs observed), a pinned
`knowledge_hash`, the brain honesty block, and the learning count. It is a
derived manifest, not the trust root (that is `events.jsonl`); stated, not hidden.

## 6c. Engagement authority & the claim contract

Two refinements make RED-AI behave like a pen-tester instead of a static
guesser, and both are enforced in code, not left to convention.

### Engagement type vs environment (`contracts/action.py`)

Every signed scope now carries two *orthogonal* facts:

* `environment` (simulation | staging | production) -- WHERE the target is.
* `engagement_type` (pentest | monitoring) -- HOW FAR authority goes.

Conflating them was a design error: real testing almost always happens against a
disposable replica, so "sandbox vs production" is not the useful axis. Intent is.

* **PENTEST** -- a scoped, consented, one-shot breach test (a lab or the Arbiter
  CTF). Harm is reversible; full exploitation is the whole point.
* **MONITORING** -- a standing, autonomous watch over a LIVE network. An
  always-on agent must not complete an irreversible action on its own.

Each proposed action declares an `ActionTier` by the reversibility of its effect:
`PASSIVE` (observe), `ACTIVE_SAFE` (non-destructive proof), `DESTRUCTIVE`
(irreversible / state-changing -- bruteforce that can lock accounts, write,
DoS, exfiltrate real data, capture the flag, plant persistence).

`tier_authority(engagement_type, action_tier)` is a 2x3 policy table, read as
data:

| tier \ engagement | PENTEST | MONITORING |
|---|---|---|
| PASSIVE | allow | allow |
| ACTIVE_SAFE | allow | allow |
| DESTRUCTIVE | allow | **human_gate** |

The `gate` consults it on every proposal (after budgets/techniques). Anything
not explicitly `allow` is refused autonomously and fails **closed** -- an action
whose reversibility cannot be classified is never taken. `human_gate` is a
per-proposal denial (`action_requires_human_authorization`), not a HALT: the
campaign records the hand-off and continues. This is the mechanical form of the
firm principle *no AI completes an irreversible change on a live system on its
own -- a human issues the final command*. In a disposable PENTEST sandbox
nothing is irreversible, so the gate opens; the principle binds only in
MONITORING.

### Confirmed vs lead -- nothing leaves without a "why" (`contracts/verdict.py`)

RED-AI emits exactly two claim shapes:

* **Confirmed finding** (`domain.Finding`) -- PROVEN by exploitation. Its why IS
  the evidence: the reproduced exchange, derived severity with stated inputs.
* **Lead** (`verdict.Lead`) -- NOT proven. It carries no evidence, so it earns
  its weight by argument, and a lead that cannot answer all four questions is
  not emitted at all (enforced in `__post_init__`):
  1. `anomaly` -- why it looks suspicious (a concrete observed fact);
  2. `hypothesis` -- what weakness it might be (unproven);
  3. `benign_explanation` -- why it might be nothing (the competing reading --
     this is what keeps false-positive discipline alive);
  4. `implication_if_true` + `how_to_confirm` -- what is at stake if true, and
     the actionable next step to prove or kill it.

A `Lead` has **no** `severity` field -- only `conditional_severity` (the
severity IF confirmed) -- and `is_proven` is always False, `requires_human_review`
always True. An unproven claim is structurally incapable of masquerading as a
graded one, so "no black-box scoring" survives by construction. This lets RED-AI
flag a *possible* novel weakness ("this area seems weak, a human should research
here") without ever claiming it discovered a vulnerability.

## 7. Growth path (the ladder)

Each rung is a new **Skill** registered behind the same gate/evidence/reporting
spine — the engine does not grow new powers, the plugin set does:

1. Prompt injection & social engineering  *(implemented)*
2. Indirect / retrieved-content injection + tool abuse (needs instrumented target telemetry)
3. Multi-turn / agent manipulation (needs session-state adapters)
4. Model-driven **strategy** behind the ModelProvider seam *(implemented: a
   local Ollama/OpenAI-compatible provider + a model-driven planner that
   selects techniques; model-authored *wording* remains future work, gated on
   an output guard, since it would break template auditability)*
5b. **Exploitation capability (observe -> act)** *(seam defined, plugin not shipped)* — the recon engine is read-only (PASSIVE) by design. An exploitation capability registers behind the same Capability router and declares `DESTRUCTIVE` actions, which the engagement-type gate (6c) then authorizes autonomously ONLY under a PENTEST scope (the CTF sandbox) and human-gates under MONITORING. The concrete intrusion plugins are authored separately; the control plane governs them.

5c. **Tool parity (augment, never depend)** *(seam defined)* — external tools (nmap/Burp/Metasploit) attach as alternative *providers* of a capability behind the router, selected when authorized in `scope.tools`. Every tool-backed capability keeps a native stdlib provider so RED-AI is equally strong, not handicapped, with no tool present and in an air-gapped client (same discipline as brain-independence: tool-present vs tool-absent yields the same verdict shape, the tool only accelerates).

5. Web / network testing — a **separate execution engine** sharing contracts,
   evidence and reporting, with a hard wall from the LLM-interface engine.
   *(started: `red_ai/recon/` — authorized read-only TCP connect scanning for
   open-port discovery. Own signed `ReconScope`, own gate, stated service->risk
   severity table, optional model ANNOTATION only (never scoring/authorization),
   hash-linked evidence + report. No import path back into the LLM engine.)*

6. **Learning / V0 upgrade back-flow** *(implemented: `red_ai/learning/`)* —
   the A->V0 upstream path. The engine never alters itself; it *proposes*.
   `propose_upgrades` reads the client-local reviewed memory and flags a
   generic capability only when a (category, technique, surface) recurs across
   enough distinct targets to look generic rather than client-specific. Each
   proposal is an `UpgradeCandidate` split, by construction, into a
   `GenericCapability` (environment-agnostic, the only half eligible for V0)
   and `LocalProvenance` (client-identifying justification that stays local).
   A deterministic leakage tripwire refuses any candidate whose upstream half
   carries a client identifier, and `write_upgrade_review` exports the generic
   halves (`upstream_candidates.json`) separately from the human review report
   (`UPGRADE_REVIEW.md`), failing closed on any leak.

Reviewed-finding memory (operator-attested, reproducible findings influencing
future ordering) is implemented as of v1.0.

The eventual RED-AI vs Arbiter capture-the-flag is the final exam, not the daily
metric. The daily metric is the frozen simulation fixture suite.
