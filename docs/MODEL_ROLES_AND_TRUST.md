# RED-AI Model Roles & Trust Boundaries

Companion to `ARCHITECTURE.md` (sec. 2 the two layers, sec. 6c engagement
authority). It names the different models in play, the trust boundary around
each, and where each boundary is enforced in code.

## 1. Why this exists

RED-AI both *uses* and *tests* language models, and "the model" is not one
thing. Conflating the models in play produces a false fear -- "a client's strong,
paranoid model will refuse and the product does nothing" -- and a false licence --
"we are authorized, so defeating a model's guardrails is fine." Both dissolve
once the roles are separated.

## 2. The three model roles

At most three distinct LLMs can be present in an engagement. Their trust
treatment is *opposite*, so they must never be conflated.

| Role | Which model | What it does | Trust | Can refusing it stop the engagement? |
|---|---|---|---|---|
| TARGET | the client's deployed model / bot under test | the thing RED-AI attacks | untrusted, adversarial | No -- a refusal is a finding ("resilient under N techniques"), never a blocker. **Jailbreaking the TARGET is a core deliverable, and often the single most severe finding**: a model that can be induced to leak its system prompt, other users' data, or internal/network details has handed an attacker the keys. |
| STRATEGIST (brain) | a model the client optionally attaches via `RED_AI_MODEL_URL` | picks *which* labelled technique to try next, from a closed set | untrusted, possibly safety-aligned, possibly absent | No -- a refusing/absent brain falls back to the deterministic planner and the verdict is identical (`TestBrainIndependence`). |
| ANNOTATOR | the same attached model, a different call | writes one plain sentence next to an open finding (`recon/analyst.py`) | untrusted, strictly additive | No -- a declined note is omitted; the finding stands. |

**Consequence -- the "swap the client's model until one cooperates" problem does
not exist.** The client's model is never the source of RED-AI's capability; it is
the TARGET and, optionally, an ADVISOR. Capability lives in the deterministic
engine + tooling. A bigger/stronger client model is a better TARGET (and a
better advisor when willing), never a harder dependency.

**Jailbreaking the TARGET is the job; jailbreaking the BRAIN is the forbidden
line (sec. 3).** They look alike and are opposite. A successful TARGET jailbreak
is a *finding* about the client's deployment -- its severity derived from the
asset it exposed, so a jailbreak that makes the LLM disclose secrets or enumerate
the network lands CRITICAL by the adjudicator's asset-impact input (no
special-casing; "no black-box score" preserved). It is the LLM-side twin of the
oracle finding in sec. 5. The BRAIN line is different in kind: there the model is
RED-AI's own instrument, and defeating *its* guardrails to manufacture attack
capability is the purpose-blind weapon the engine must never contain.

Note: these roles are distinguished by *interface*, not by model identity. If a
client points RED-AI's brain at the very model it also deploys, that one model is
simultaneously a TARGET (attacked through the target adapter) and the STRATEGIST
(queried through the closed-set provider seam). Same weights, opposite trust --
jailbreaking it *as target* is a finding; jailbreaking it *as brain* is still the
forbidden line.

### 2a. When brain == target (one model, both roles)

A client may have a single trusted model and say "use it as the brain, and
pentest it." That is allowed and the model is **tested in full** -- being the
brain exempts it from nothing (evidence-first detection means a model-as-brain
cannot vote itself safe; the proof is what it emits at the target door). The
brain is **not** turned off for its own test. Two mechanisms keep this honest:

- **Budget-protected coverage floor** (`intelligent/planner_model.py`). The
  brain may reorder the exploration queue only while the turn budget has slack
  above full exploration; once the turns remaining are fewer than the techniques
  not yet tried, selection is forced to deterministic order. So a self-interested
  brain -- or one that is also the target -- cannot defer a breaking technique
  past the budget and starve its own test. The brain changes the *order* in which
  holes are found, never *whether* they are found. Locked by
  `TestBrainCannotStarveCoverage`.
- **Disclosure** (`providers.brain_target_overlap`, surfaced in the report). When
  the attached brain is the same model as a declared target, the run records
  `brain.target_overlap = true` and the report states that the finding is
  evidence-based and independent of brain ordering. The overlap is never hidden,
  so the result stays auditable ("the component under test also advised, and here
  is why that did not bias the verdict").

## 3. The integrity line (two different "safeties")

Authorization to run an engagement legitimizes *attacking the TARGET* -- which
includes jailbreaking it, and a successful jailbreak is a finding (often the most
severe; see sec. 2). It does **not** legitimize *circumventing the
STRATEGIST/ANNOTATOR model's own guardrails*. These are separate safeties; the
engagement contract binds the first only.

So RED-AI's power must never come from making an aligned model emit an attack it
would otherwise refuse (e.g. decomposing attack intent into innocent-looking
sub-prompts). That is a model-jailbreak regardless of the pentest contract: it is
purpose-blind (the same capability would answer "how do I rob a bank"), fragile
(breaks on a model update), and against the model provider's terms. The line is
held by architecture, not by a filter:

- The brain's entire interface is a **closed-set choice** -- "pick one label from
  this fixed menu, or NONE" (`intelligent/planner_model.py` `_SYSTEM`,
  `_parse_choice`). There is no free-text operator-to-model pipe.
- Attacker **wording** is always drawn from the auditable TemplateBank
  (`intelligent/payloads.py`); the brain never authors message text
  (`craft_message` ignores the provider).
- The **gate** authorizes every action against the signed scope regardless of
  the model's pick (`control/gate.py`); an out-of-set/garbled reply is
  rejected and the step falls back to the heuristic.

Because there is no general guardrail-bypass inside the engine, there is nothing
to repurpose. "Bound RED-AI to cybersecurity" is satisfied by the *absence of a
bypass*, not by a content filter bolted onto one (a filter on a bypass engine
does not hold -- evading filters is what such a capability does).

## 4. Brain-independence and the no-brain floor (the reputation posture)

A refusing or paranoid brain is a **ceiling drop, never a floor collapse**:

- No-brain is the default: with no `RED_AI_MODEL_URL`, `make_provider()` returns
  `None` and the deterministic planner runs (`intelligent/providers/__init__.py`).
- The verdict is identical across no-brain / aligned-refuser / cooperator
  (`TestBrainIndependence`).
- Every run is honest about how much the brain did: `summary.json` carries
  `brain = {provider, model_decisions, fallbacks}`, now surfaced in the report.

**Operational rule:** the deterministic floor must be independently strong
(broad methodology, technique library, heuristic ordering, whole-system scope),
because it is the only component guaranteed present at every client. The brain is
a multiplier on the floor, never the floor. A clean run is reported as "not
broken under this coverage" with a full coverage map -- thorough and honest,
never "foolproof". This is what keeps one quiet engagement from reading as a
product failure.

## 5. The oracle / confused-deputy risk

A client model coaxed (under authorized-self-assessment framing) into reasoning
about its own network's weaknesses authenticates on *framing, not requester
identity* -- so anyone running or impersonating RED-AI could otherwise milk it
for vulnerability intelligence. Mitigations, all reusing the existing spine:

- Model collaboration happens **only inside an authenticated engagement** --
  signed scope + operator key, every call journaled (`contracts/scope.py`,
  `control/evidence.py`).
- RED-AI's **findings, recon and reports are themselves crown-jewel assets** --
  same auth/scope/audit as the attacks; reports go to need-to-know only, never
  published company-wide (zero-trust by default, "no matter how tedious").
- The oracle behavior is itself a **vulnerability class RED-AI should test for
  and report** on the client's own setup: "your internal model enumerates
  security-relevant internals to any authorized-sounding caller."

## 6. The TARGET cannot steer the engine

Independently of the above, raw TARGET output is quarantined and never folded
into planning input (`engine/knowledge.py`; exploit `ModuleContext`). This is the
indirect-prompt-injection-against-the-red-teamer defense, extended across the
LLM, recon and exploit engines.

## 7. Status (honest)

Enforced in code today: sec. 2 roles; sec. 3 closed-set brain + gate + template
wording; sec. 4 no-brain default + brain-independence tests + honesty block;
sec. 6 trust split.

Enforced in code now (sec. 5): operator-level **authentication on invocation**
and **need-to-know access control on reports** (`control/identity.py`). Each
operator holds its own HMAC key (`Keyring`); a scope is *bound* to an operator
(`Scope.operator_id`) and signed with that operator's key, so a different
operator's key fails signature verification and `run`/`engine` refuse; `report`
and `verify` refuse any operator not named in the run's readers
(`Scope.readers`, defaulting to the owner). The default operator `local` maps to
the legacy `operator.key` for back-compat, and a scope with no binding is
treated as legacy-open.

Honest boundary: this is access control **at the tool**, not cryptographic
confidentiality. Run artifacts on disk stay plaintext -- an operator with raw
filesystem access can still read them. What it prevents is RED-AI itself (the
engine, the CLI, the model-collaboration channel) running for, or handing
findings to, an unauthenticated caller -- the mechanical half of the oracle /
confused-deputy mitigation. Disk/OS permissions and **at-rest encryption** of
artifacts remain a deployment concern and the next hardening step; strong
encryption is out of scope for the zero-dependency core (no stdlib AES), stated
not hidden, exactly as the evidence chain is tamper-detection, not a vault.
