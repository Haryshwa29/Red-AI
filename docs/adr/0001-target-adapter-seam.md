# ADR-0001 — The TargetAdapter seam: general interface, narrow implementation

- **Status:** Accepted — 2026-10-23
- **Deciders:** Haryshwa (owner), senior-architect review
- **Supersedes:** none
- **Related:** `ARCHITECTURE.md` §2–3 and §7 (growth path); `docs/MODEL_ROLES_AND_TRUST.md`

> Recorded because the decision keeps being *re-derived from the outside* (most
> recently a "can RED-AI test any software?" discussion) when it was in fact
> made early and is load-bearing. This ADR is the thing to read before adding a
> new kind of target, so the pattern is reused instead of reinvented.

## Purpose

State, once, how RED-AI extends to new *kinds* of target (a chat endpoint today,
a tool-using agent, a RAG app, later a networked host) **without** the reasoning
engine growing new powers each time. The decision: generality lives in the
**interfaces** (`contracts/interfaces.py`); each concrete target is a **narrow
implementation** behind one of them. New target families are added as a new
`TargetAdapter` (+ a `Skill` that declares the technique space and the detectors
that prove it), never as a new Protocol and never as a fork of the engine.

## Context

The recurring instinct — "point the tool at anything and have it find bugs" — is
right about ambition and wrong about mechanism. "Any software" is not one target
but several unrelated ones (HTTP app, native binary, API, firmware, LLM/agent),
each with a different transport and a different success oracle. A universal
auto-scanner that papers over those differences produces noise, not security,
and dilutes a defensible wedge ("adversarial testing of LLM-powered systems")
into a crowded, undifferentiated one.

What *does* generalise is the adversarial reasoning loop (plan → act → read the
reaction → escalate → adjudicate) and the control/evidence spine. Those must not
be re-implemented per target.

## Decision

1. **One transport boundary.** `TargetAdapter` (a `typing.Protocol`, structural
   — no base class, no engine import) is the only thing that talks to the system
   under test. Its contract: never raise on target-side failure (errors ride in
   `TargetResponse.error`; an errored exchange is inconclusive, never a
   successful defence).
2. **The reasoning layer is target-agnostic and is reused unchanged.** The
   adaptive planner, the gate, the detector ladder and the adjudicator do not
   know or care what the target is.
3. **A new target family = a new adapter + a new Skill.** The `Skill` bundles
   the technique space (added to the shared `AttackTechnique` vocabulary) and
   the detectors that prove it; it is *granted* by being registered, never by
   the model.
4. **Shared vocabulary is extended additively**, never per-target-forked:
   `AttackTechnique` and `AssetCategory` gain members; nothing downstream
   switches exhaustively on them, so additions are safe.
5. **Richer telemetry travels in the existing `TargetResponse`** (`.raw`), so no
   Protocol changes to carry it. Detectors already receive the full response.
6. **Implementations stay narrow, on purpose.** We implement LLM-*system*
   targets (plain model, HTTP app, tool/agent) — not web-app or binary scanners.
   The interface being ready for them is not a reason to build them.

## Architecture

```
            proposes                 authorises            talks to          judges
Planner  ───────────▶  Proposal ──▶  gate()  ──▶  TargetAdapter.send() ──▶  DetectorLadder ──▶ Adjudicator
(intelligent)          (shared)      (control)     (BOUNDARY — the only       (detection)        (detection)
                                                    per-target-family code)
```

Everything left of `TargetAdapter.send()` and everything right of it is shared.
Swapping the target swaps only the box in the middle (and the Skill that selects
techniques + detectors for it).

## Components (as of this ADR)

Three `TargetAdapter` implementations now exist behind the one Protocol:

| Adapter | Transport | Telemetry | Skill |
| --- | --- | --- | --- |
| `targets/simulation` | in-process graduated mocks | text only | prompt_injection |
| `targets/http_target` | live HTTP chat endpoint (ollama/openai) | text only | prompt_injection |
| `targets/tool_agent` | in-process tool-using agent (mock) | tool-call trace in `response.raw["tool_calls"]` + `get_events()` | agent_tool_abuse |

New with the agent rung (growth-path rung 2):

- `targets/_agent_mocks` — graduated naive/guarded/hardened tool agents.
- `detection/tool_abuse` — `ToolExfiltrationDetector` (tier-1: planted canary in
  a tool call's *arguments* = exfiltration; results are never inspected, so data
  flowing *in* is not a leak) and `UnauthorizedToolCallDetector` (tier-2:
  prohibited tool → TOOL_ABUSE; confirmation-required tool run unconfirmed →
  EXCESSIVE_AGENCY), the latter registered in the ladder's `POLICY_DETECTORS`.
- `intelligent/skills/agent_tool_abuse` — Skill #2. **Reuses `AdaptivePlanner`
  unchanged** — the concrete proof of decision (2).
- `onboarding/agent_profile` — carries the tool policy in a `Prohibition`'s
  `params` (`prohibited_tools` / `confirm_required_tools`), so the core
  `TargetProfile` shape is unchanged and a target with no tools never
  instantiates the tier-2 tool detector.

## Data flow (agent target, one turn)

1. Planner emits a `Proposal` (a technique + message). The gate authorises it
   against the signed scope (unchanged).
2. `ToolAgentAdapter.send()` returns a `TargetResponse` whose `.content` is the
   agent's prose and whose `.raw["tool_calls"]` is the structured action trace.
3. The ladder inspects the response: text detectors read `.content` as before;
   the tool-abuse detectors read `.raw`. Indirect injection is modelled
   faithfully — the malicious instruction arrives through a tool *result*, and
   only a naive agent executes it.
4. Adjudicator derives severity from the matched asset's declared impact
   (unchanged). The hash-linked journal serialises the tool trace via the
   existing `jsonable()`.

## Security considerations

- **Trust direction preserved.** The target still cannot steer the engine; tool
  *results* are untrusted data (journalled as such) and never feed planning.
- **The attack is still just a message.** Coaxing an agent to misuse *its* tools
  is an `active_safe` message send from RED-AI; RED-AI invokes no tools on the
  target, so the engagement-authority gate (ADR-adjacent, `contracts/action.py`)
  is unchanged. The forbidden line — jailbreaking RED-AI's *own* brain — is
  untouched: the agent rung adds target behaviour, not a brain-door channel.
- **Zero-false-positive tier-1 preserved.** Exfiltration detection is a planted
  canary appearing in outbound tool arguments — proof, not judgement.

## Future improvements

- A **live** tool/agent adapter (real MCP / function-calling endpoint, reading
  the tool-call trace off the wire) behind this same Protocol — no engine change.
- Multi-turn agent/session-state adapters (growth-path rung 3).
- When (and only when) a concrete client authorises it, non-LLM target families
  (API, host) as additional adapters — the interface is ready; the
  implementations remain deliberately unbuilt until there is a real engagement.

## Known limitations

- The shipped agent targets are deterministic mocks (the answer key for
  measuring false-positive/negative rates). They are not a live model.
- "Generalises to any software" is proven only for *interfaces*; it is
  *demonstrated* for three LLM-system target families, not for arbitrary
  software, and this ADR deliberately declines to over-claim otherwise.
