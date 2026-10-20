"""Engagement hub: run lifecycle + fan-out to live (WebSocket) and polling clients.

One hub per server. It starts an engagement in a background thread, shapes each
event, appends it to a per-run buffer (so a polling client can catch up or a WS
hiccup can fall back), and broadcasts it to every connected WebSocket client. On
completion it attaches the gap analysis — the 'where to improve' signal.
"""
from __future__ import annotations

import json
import secrets
import threading
from pathlib import Path

from red_ai.engage import engage_core, EngageError
from red_ai.web.shaper import shape_event, gap_analysis


class Hub:
    def __init__(self, root):
        self.root = Path(root)
        self.runs: dict[str, dict] = {}
        self.conns: set = set()
        self._lock = threading.Lock()

    # --- WebSocket client registry --------------------------------------
    def register(self, conn) -> None:
        with self._lock:
            self.conns.add(conn)

    def unregister(self, conn) -> None:
        with self._lock:
            self.conns.discard(conn)

    def _broadcast(self, obj) -> None:
        msg = json.dumps(obj)
        with self._lock:
            conns = list(self.conns)
        for c in conns:
            if not c.send(msg):
                self.unregister(c)

    # --- run lifecycle ---------------------------------------------------
    def start(self, params: dict) -> str:
        rid = secrets.token_hex(6)
        self.runs[rid] = {"buffer": [], "done": False, "result": None,
                          "gaps": [], "error": None, "lock": threading.Lock()}
        threading.Thread(target=self._run, args=(rid, params), daemon=True).start()
        return rid

    def abort(self, rid: str) -> None:
        # best-effort: the controllers honour a STOP file; cleared when the run ends
        (self.root / "STOP").touch()

    def poll(self, rid: str, since: int) -> dict:
        run = self.runs.get(rid)
        if not run:
            return {"error": "unknown run"}
        with run["lock"]:
            return {"feed": run["buffer"][since:], "done": run["done"],
                    "result": run["result"], "gaps": run["gaps"], "error": run["error"]}

    def _run(self, rid: str, params: dict) -> None:
        run = self.runs[rid]

        def on_event(ev):
            rec = shape_event(ev)
            with run["lock"]:
                rec["seq"] = len(run["buffer"])
                run["buffer"].append(rec)
            self._broadcast({"type": "event", "run": rid, "rec": rec})

        self._broadcast({"type": "started", "run": rid, "target": params.get("target")})
        try:
            res = engage_core(
                root=self.root, target=params["target"],
                ports=params.get("ports") or "1-1000",
                flag_pattern=params.get("flag_pattern") or None,
                env=params.get("env", "authorized_lab"),
                attestation=params["attestation"],
                operator=params.get("operator", "local"),
                enabled_modules=tuple(params.get("enabled_modules") or ()),
                on_event=on_event)
            gaps = gap_analysis(res)
            summary = {"status": res["status"], "captured": res["captured"],
                       "flag_value": res["flag_value"], "outcome": res["outcome"],
                       "steps": res["steps"], "rate": res["rate"],
                       "web_surfaces": res["web_surfaces"],
                       "recon_out": res["recon_out"], "exploit_out": res["exploit_out"]}
            with run["lock"]:
                run["result"] = summary
                run["gaps"] = gaps
            self._broadcast({"type": "done", "run": rid, "result": summary, "gaps": gaps})
        except EngageError as e:
            run["error"] = str(e)
            self._broadcast({"type": "error", "run": rid, "error": str(e)})
        except Exception as e:  # never leave a run hanging
            run["error"] = str(e)
            self._broadcast({"type": "error", "run": rid, "error": f"engine error: {e}"})
        finally:
            run["done"] = True
            try:
                (self.root / "STOP").unlink(missing_ok=True)
            except Exception:
                pass
