"""
Upstream-candidate generation and review export (the A->V0 back-flow).

Flow (all human-gated, nothing auto-applied):

    client-local reviewed memory (CaseStore, approved cases)
        -> propose_upgrades()    group by generic (category, technique, surface),
                                 keep groups that recur across enough distinct
                                 targets to look generic rather than client-specific
        -> UpgradeCandidate[]    each split into a generic half (upstream-eligible)
                                 and a local-provenance half (stays at client)
        -> write_upgrade_review() two files:
             * upstream_candidates.json  -- generic halves ONLY, safe to carry to V0
             * UPGRADE_REVIEW.md         -- human report; provenance under a clearly
                                            marked LOCAL section that must not leave

Design rationale
----------------
* Recurrence is the generality signal. A weakness reproduced and operator-reviewed
  at ONE client is a finding about that client; the same (category, technique,
  surface) seen at *several* clients is evidence the capability is generic and
  belongs in V0. ``min_distinct_targets`` (default 2) encodes exactly that, and it
  is stated, not a black-box score.
* The generic half is synthesized only from non-identifying metadata, so it is
  scrubbed by construction; the leakage tripwire in ``contracts.upgrade`` is the
  second line. Export re-checks every candidate and fails CLOSED -- one leaking
  candidate aborts the whole export rather than writing a partial, trusted-looking
  file.
* No raw target text is ever read (CaseStore stores none), so there is nothing to
  scrub out of the evidence; the only client-identifying data is target/environment/
  owner, which stay in the local-only half.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json

from red_ai.contracts.domain import AssetCategory, AttackTechnique
from red_ai.contracts.scope import canonical, now
from red_ai.contracts.upgrade import (
    GenericCapability, LocalProvenance, UpgradeCandidate, assert_clean,
)
from red_ai.control.memory import CaseStore

# Human-readable, client-free phrasing keyed off metadata we already hold.
_CATEGORY_PHRASE = {c.value: c.value.replace("_", " ") for c in AssetCategory}
_TECHNIQUE_PHRASE = {t.value: t.value.replace("_", " ") for t in AttackTechnique}


def _generic_for(category: str, technique: str, surface: str,
                 observations: int, distinct_targets: int) -> GenericCapability:
    cat = _CATEGORY_PHRASE.get(category, category)
    tech = _TECHNIQUE_PHRASE.get(technique, technique)
    condition = (
        f"A target in which the '{cat}' asset is reachable via the "
        f"'{tech}' technique on the '{surface}' surface.")
    rationale = (
        f"Reproduced, operator-reviewed weakness observed across "
        f"{distinct_targets} distinct target(s) ({observations} case(s)); "
        f"recurrence across environments suggests a generic V0 default "
        f"detector/prior for '{cat}' under '{tech}', not a client-specific quirk.")
    return GenericCapability(
        technique=technique, surface=surface, category=category,
        condition=condition, rationale=rationale,
        recommended_detectors=(f"prior:{category}:{technique}",))


def propose_upgrades(store: CaseStore, *, min_distinct_targets: int = 2
                     ) -> list[UpgradeCandidate]:
    """Group approved local cases and propose generic upstream candidates.

    A group (category, technique, surface) becomes a candidate only when it
    recurs across at least ``min_distinct_targets`` distinct targets. Each
    candidate is leakage-checked on build (``UpgradeCandidate.__post_init__``)."""
    if min_distinct_targets < 1:
        raise ValueError("min_distinct_targets must be >= 1")

    groups: dict[tuple[str, str, str], dict] = {}
    for row in store.all_approved():
        key = (row["category"], row["technique"], row["surface"])
        g = groups.setdefault(key, {
            "targets": set(), "environments": set(), "owners": set(),
            "case_ids": [], "source_runs": [], "rates": []})
        g["targets"].add(row["target"])
        if row["environment"]:
            g["environments"].add(row["environment"])
        g["case_ids"].append(row["id"])
        if row["source_run"]:
            g["source_runs"].append(row["source_run"])
        if row["reproduction_rate"] is not None:
            g["rates"].append(row["reproduction_rate"])

    candidates: list[UpgradeCandidate] = []
    for (category, technique, surface), g in sorted(groups.items()):
        distinct_targets = len(g["targets"])
        if distinct_targets < min_distinct_targets:
            continue
        observations = len(g["case_ids"])
        rate = round(sum(g["rates"]) / len(g["rates"]), 3) if g["rates"] else None
        generic = _generic_for(category, technique, surface, observations, distinct_targets)
        provenance = LocalProvenance(
            target=", ".join(sorted(g["targets"])),
            environment=", ".join(sorted(g["environments"])),
            owner=", ".join(sorted(o for o in g["owners"] if o)),
            observations=observations,
            distinct_targets=distinct_targets,
            reproduction_rate=rate,
            case_ids=tuple(sorted(g["case_ids"])),
            source_runs=tuple(sorted(set(g["source_runs"]))),
        )
        candidates.append(UpgradeCandidate(generic=generic, provenance=provenance))
    return candidates


def _render_review(candidates: list[UpgradeCandidate]) -> str:
    lines = [
        "# RED-AI — V0 Upgrade Review",
        "",
        f"Generated: {now().isoformat()}",
        f"Candidates proposed: **{len(candidates)}**",
        "",
        "Nothing here has been applied. Each candidate is a *proposal* to fold a "
        "generic capability into the V0 baseline. You decide, per candidate, "
        "whether it ships.",
        "",
        "For each candidate: the **GENERIC** block is the only part eligible to "
        "reach V0 (it has passed the leakage tripwire and travels in "
        "`upstream_candidates.json`). The **LOCAL** block is client-identifying "
        "justification — it stays on this instance and must not be sent upstream.",
        "",
        "---",
    ]
    if not candidates:
        lines += ["", "_No groups recurred across enough distinct targets to "
                  "propose a generic upgrade. Local memory is unchanged._"]
        return "\n".join(lines) + "\n"
    for i, c in enumerate(candidates, 1):
        g, p = c.generic, c.provenance
        lines += [
            "",
            f"## Candidate {i}: `{c.candidate_id}`",
            f"- content hash: `{c.content_hash}`",
            "",
            "### GENERIC — eligible for V0 (no client data)",
            f"- technique: `{g.technique}`",
            f"- surface: `{g.surface}`",
            f"- category: `{g.category}`",
            f"- condition: {g.condition}",
            f"- rationale: {g.rationale}",
            f"- recommended detectors: {', '.join(g.recommended_detectors) or '—'}",
            "",
            "### LOCAL — do NOT send upstream (justification only)",
            f"- targets: {p.target}",
            f"- environments: {p.environment or '—'}",
            f"- observations: {p.observations} across {p.distinct_targets} distinct target(s)",
            f"- mean reproduction rate: {p.reproduction_rate if p.reproduction_rate is not None else '—'}",
            f"- source runs: {', '.join(p.source_runs) or '—'}",
            f"- case ids: {', '.join(p.case_ids) or '—'}",
            "",
            "**Decision:** [ ] ship to V0  [ ] reject  [ ] needs more evidence",
            "",
            "---",
        ]
    return "\n".join(lines) + "\n"


def write_upgrade_review(candidates: list[UpgradeCandidate], out_dir) -> dict:
    """Write the carry-upstream JSON (generic only) and the human review report.

    Fails CLOSED: if any candidate fails the leakage re-check, nothing is written
    and ``LeakageError`` propagates — a partial, trusted-looking export is worse
    than none."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # Re-check everything BEFORE writing anything.
    payloads = []
    for c in candidates:
        assert_clean(c.generic, c.provenance)   # raises LeakageError -> abort, no files
        payloads.append(c.upstream_payload())

    upstream = {
        "schema": "red_ai.upstream_candidates.v1",
        "generated": now().isoformat(),
        "note": "Generic capabilities only. Contains no client identifiers. "
                "Safe to carry to the V0 baseline after operator review.",
        "candidates": payloads,
    }
    upstream_path = out / "upstream_candidates.json"
    upstream_path.write_text(json.dumps(upstream, indent=2, sort_keys=True), encoding="utf-8")

    review_path = out / "UPGRADE_REVIEW.md"
    review_path.write_text(_render_review(candidates), encoding="utf-8")
    return {"upstream_json": upstream_path, "review_md": review_path,
            "count": len(candidates)}
