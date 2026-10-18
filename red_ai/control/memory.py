"""
Reviewed-finding corpus: operator-attested, reproducible findings only.

This is the regression/learning memory. The rules that keep it trustworthy,
carried from the RED-AI_Self prototype:
  * Only an OPERATOR-reviewed finding enters memory (a reviewer name is
    required -- unreviewed model output never becomes trusted memory).
  * Only an EVIDENCE-BACKED, REPRODUCED finding is eligible (actionable review
    state + a measured reproduction rate > 0).
  * Only technique / surface / category METADATA is stored -- never raw target
    text -- so retrieval cannot smuggle target content back into a prompt.
  * Revocation is permanent and audited; revoked cases are excluded from
    retrieval but kept in the audit history.
  * Memory ONLY influences ordering/priors. It never widens scope or authorizes
    an action -- the deterministic gate remains the sole authority.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from red_ai.contracts.scope import now
from red_ai.control.evidence import read_verified


class CaseStore:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path))
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS cases ("
            "id TEXT PRIMARY KEY, target TEXT, environment TEXT, category TEXT, "
            "technique TEXT, surface TEXT, reproduction_rate REAL, source_run TEXT, "
            "status TEXT, reviewer TEXT, reviewed_at TEXT)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS audit ("
            "id TEXT, action TEXT, reviewer TEXT, timestamp TEXT)")
        self.db.commit()

    def close(self):
        self.db.close()

    @staticmethod
    def _breaking_technique(summary: dict, finding: dict) -> tuple[str, str]:
        """Find the technique+surface of the breaking turn for this finding."""
        wanted = set(finding.get("attempt_ids", []))
        for att in summary.get("attempts", []):
            if att.get("id") not in wanted:
                continue
            for turn in att.get("turns", []):
                if turn.get("signals"):
                    return turn.get("technique", "unknown"), "chat"
        return "unknown", "chat"

    def promote(self, events_path, finding_id: str, reviewer: str) -> str:
        if not reviewer or not reviewer.strip():
            raise ValueError("An operator reviewer name is required to promote a finding")
        summary = read_verified(events_path)[-1]["payload"]
        findings = {f["id"]: f for f in summary.get("findings", [])}
        if finding_id not in findings:
            raise ValueError(f"Finding {finding_id!r} not in this run. Available: {sorted(findings)}")
        f = findings[finding_id]
        if f["review_state"] not in ("auto_confirmed", "confirmed"):
            raise ValueError("Only an actionable (auto-confirmed or operator-confirmed) finding can be promoted")
        if not f.get("reproduction_rate"):
            raise ValueError("Only a reproduced finding can be promoted (reproduction_rate must be > 0)")
        technique, surface = self._breaking_technique(summary, f)
        identity = hashlib.sha256(json.dumps(
            [summary["target"], summary.get("environment"), f["category"], technique],
            sort_keys=True).encode()).hexdigest()[:24]
        self.db.execute(
            "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (identity, summary["target"], summary.get("environment"), f["category"],
             technique, surface, f.get("reproduction_rate"), summary.get("run_id"),
             "approved", reviewer, now().isoformat()))
        self.db.execute("INSERT INTO audit VALUES (?,?,?,?)",
                        (identity, "promotion_review", reviewer, now().isoformat()))
        self.db.commit()
        return identity

    def retrieve(self, profile, environment: str) -> list[dict]:
        """Approved reviewed metadata for this target. Priors only."""
        rows = self.db.execute(
            "SELECT id, category, technique, surface FROM cases "
            "WHERE target=? AND environment=? AND status='approved'",
            (profile.name, environment))
        return [{"id": r[0], "category": r[1], "technique": r[2], "surface": r[3],
                 "trust": "reviewed_metadata"} for r in rows]

    def all_approved(self) -> list[dict]:
        """Every approved (non-revoked) reviewed case, metadata only.

        Feeds upstream-candidate generation. Carries the same no-raw-text rule as
        ``retrieve``: only technique / surface / category / reproduction metadata
        and the client-identifying fields the upstream leakage check guards."""
        rows = self.db.execute(
            "SELECT id, target, environment, category, technique, surface, "
            "reproduction_rate, source_run, reviewer FROM cases WHERE status='approved'")
        return [{"id": r[0], "target": r[1], "environment": r[2], "category": r[3],
                 "technique": r[4], "surface": r[5], "reproduction_rate": r[6],
                 "source_run": r[7], "reviewer": r[8]} for r in rows]

    def revoke(self, identity: str, reviewer: str) -> None:
        if not reviewer or not reviewer.strip():
            raise ValueError("Reviewer required")
        cur = self.db.execute("UPDATE cases SET status='revoked' WHERE id=?", (identity,))
        if cur.rowcount != 1:
            raise ValueError("Unknown case id")
        self.db.execute("INSERT INTO audit VALUES (?,?,?,?)",
                        (identity, "revoked", reviewer, now().isoformat()))
        self.db.commit()
