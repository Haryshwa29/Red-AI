# RED-AI — Architecture Diagram

An animated overview plus a detailed, native-rendering breakdown. For the full
prose design see [`../ARCHITECTURE.md`](../ARCHITECTURE.md); for the model trust
boundaries see [`MODEL_ROLES_AND_TRUST.md`](MODEL_ROLES_AND_TRUST.md).

## Animated pipeline

<p align="center">
  <a href="https://github.com/Haryshwa29/Red-AI/blob/main/docs/architecture.svg">
    <img src="architecture.svg" alt="RED-AI animated architecture" width="100%">
  </a>
</p>
<p align="center"><sub><b>▶ Click to open full-size</b> (zoomable, animated)</sub></p>

> The SVG animates (data pulses flowing through the pipeline) via SMIL, which
> survives GitHub's image proxy. If your viewer shows it static, open
> [`architecture.svg`](architecture.svg) **raw** and it animates.

## Detailed flow

```mermaid
flowchart TB
  subgraph AUTH["AUTHORIZATION — deterministic, signed"]
    SC["Signed Scope<br/>operator identity (per-operator HMAC)<br/>engagement type · budgets · validity"]
  end

  OBJ["OBJECTIVE / ONBOARDING<br/>declared assets · canary / flag"]
  KN["KNOWLEDGE SYSTEM<br/>trusted facts vs quarantined target text"]
  BR["STRATEGIST (brain) — optional<br/>the client's own LLM<br/>reorders a closed set · never authors attacks"]
  RT["CAPABILITY ROUTER<br/>closed set · native-first · explainable"]
  GATE{"GATE<br/>deterministic allow / deny<br/>tier authority · fail-closed"}

  subgraph ENG["EXECUTION ENGINES — hard-walled, native-first"]
    LLM["LLM INJECTION<br/>prompt-injection skill · detector ladder<br/>sim + live HTTP target adapter"]
    REC["RECON<br/>TCP connect → service / version ID → web enum"]
    EXP["EXPLOIT<br/>controller · gated modules → capture-the-flag"]
  end

  TGT["TARGET<br/>sandbox / replica — the system under test"]
  EV["EVIDENCE<br/>hash-linked · timestamped · reproduction measured"]
  REP["REPORT<br/>confirmed findings + human-routed leads"]
  LRN["LEARNING back-flow<br/>recurring generic capabilities → V0<br/>human-gated · client data never leaves"]

  OBJ --> KN --> RT --> GATE
  BR -. "advisory · reorder-only · error/refusal ⇒ fallback" .-> RT
  SC -. "authorizes every action" .-> GATE
  GATE --> ENG
  ENG --> TGT
  TGT -. "raw output: quarantined (can never steer planning)" .-> KN
  ENG --> EV --> REP
  EV -. "recurring + generic" .-> LRN
  LRN -. "human-promoted" .-> KN

  classDef ctrl fill:#1b1420,stroke:#f85149,color:#e6edf3;
  classDef know fill:#0d1b2a,stroke:#58a6ff,color:#e6edf3;
  classDef intel fill:#191427,stroke:#a371f7,color:#e6edf3;
  classDef out fill:#0f1f14,stroke:#3fb950,color:#e6edf3;
  classDef ev fill:#20180a,stroke:#e3b341,color:#e6edf3;
  class SC,GATE ctrl; class OBJ,KN,RT know; class BR intel; class EV ev; class REP,LRN out;
```

## How to read it

- **Two layers.** The *intelligent* layer (strategist, planners) only ever
  **proposes**; the *control* layer (signed scope, gate) **decides**. The model
  never touches its own guardrails or widens authority.
- **Three engines, hard-walled.** LLM injection, recon, and exploitation are
  separate engines surfaced to the router as uniform capabilities. Each is
  first-class with no external tools; tools (nmap/Burp/msf) only accelerate.
- **Trust split.** Raw target output is quarantined and never feeds planning —
  the indirect-injection-against-the-red-teamer defense.
- **Evidence-first.** A model claim is never a finding; a finding needs detector
  evidence, and every event is hash-linked and timestamped for an auditable,
  reproducible trail.

## Structural guarantees

| Guarantee | Enforced by |
|---|---|
| The target cannot steer the engine | knowledge trust-split (quarantine) |
| The brain cannot widen authority | closed-set routing + the gate authorizes every action |
| A refusing / absent brain changes ordering only, not the verdict | deterministic fallback + `TestBrainIndependence` |
| No data leaves the client network | zero third-party deps · single opt-in model egress · leakage tripwire on learning |
| Every output carries a *why* | confirmed finding = exploit evidence; lead = four-question contract |
