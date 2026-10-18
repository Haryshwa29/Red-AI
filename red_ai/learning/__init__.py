"""Learning layer: turn locally-reviewed findings into human-reviewed proposals.

Nothing here alters a running engine. It reads the client-local reviewed-finding
corpus and *proposes* generic capabilities that an operator may (separately,
manually) fold into the V0 baseline. The sensitive A->V0 back-flow lives here,
and it is deliberately all read + propose + export -- never apply.
"""
from __future__ import annotations

from red_ai.learning.upstream import propose_upgrades, write_upgrade_review

__all__ = ["propose_upgrades", "write_upgrade_review"]
