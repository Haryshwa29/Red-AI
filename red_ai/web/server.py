"""RED-AI local web console: watch an engagement run, step by step, and learn.

A dependency-free (stdlib ``http.server``) dashboard bound to 127.0.0.1. It runs
ON the operator's machine -- the same machine that has the route to the target
(e.g. on the TryHackMe / HackTheBox VPN) -- and the browser is only the window.
It drives the exact same gated, evidenced ``engage_core`` pipeline as the CLI and
streams every step to the page with plain-English explanations, so a learner can
follow how a CTF is actually approached: authorize → recon → enumerate → exploit
→ capture.

Security: localhost-only by default (do not expose this control panel on the VPN
network); the engagement still requires an operator identity and an explicit
authorization tick, both recorded in the evidence; every exploit step is gated.
"""
from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from red_ai.contracts.scope import now
from red_ai.control.identity import Keyring, DEFAULT_OPERATOR, AccessDenied
from red_ai.engage import engage_core, EngageError, DEFAULT_FLAG_PATTERN
from red_ai.web.annotate import annotate

_RUNS: dict[str, dict] = {}
_RUNS_LOCK = threading.Lock()


def _new_run() -> str:
    rid = secrets.token_hex(6)
    with _RUNS_LOCK:
        _RUNS[rid] = {"lock": threading.Lock(), "feed": [], "done": False,
                      "result": None, "error": None}
    return rid


def _append(rid: str, lines) -> None:
    run = _RUNS.get(rid)
    if not run:
        return
    if isinstance(lines, dict):
        lines = [lines]
    with run["lock"]:
        for ln in lines:
            if ln:
                ln = {**ln, "seq": len(run["feed"]), "t": now().strftime("%H:%M:%S")}
                run["feed"].append(ln)


def _run_engagement(rid: str, root: Path, params: dict) -> None:
    def on_event(ev):
        _append(rid, annotate(ev))
    try:
        res = engage_core(
            root=root, target=params["target"], ports=params.get("ports", "1-1000"),
            flag_pattern=params.get("flag_pattern") or DEFAULT_FLAG_PATTERN,
            env=params.get("env", "authorized_lab"),
            attestation=params["attestation"],
            operator=params.get("operator", DEFAULT_OPERATOR),
            on_event=on_event)
        with _RUNS[rid]["lock"]:
            _RUNS[rid]["result"] = {
                "status": res["status"], "captured": res["captured"],
                "flag_value": res["flag_value"], "outcome": res["outcome"],
                "steps": res["steps"], "rate": res["rate"],
                "recon_out": res["recon_out"], "exploit_out": res["exploit_out"]}
    except EngageError as e:
        _append(rid, {"stage": "authorize", "level": "warn", "text": f"Cannot start: {e}"})
        _RUNS[rid]["error"] = str(e)
    except Exception as e:  # never leave a run hanging
        _append(rid, {"stage": "capture", "level": "warn", "text": f"Engagement error: {e}"})
        _RUNS[rid]["error"] = str(e)
    finally:
        _RUNS[rid]["done"] = True


class _Handler(BaseHTTPRequestHandler):
    root: Path = Path("data")

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
        if u.path == "/api/events":
            q = parse_qs(u.query)
            rid = (q.get("run") or [""])[0]
            since = int((q.get("since") or ["0"])[0])
            run = _RUNS.get(rid)
            if not run:
                return self._send(404, {"error": "unknown run"})
            with run["lock"]:
                feed = run["feed"][since:]
                return self._send(200, {"feed": feed, "done": run["done"],
                                        "result": run["result"], "error": run["error"]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/api/engage":
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            params = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad request body"})
        target = (params.get("target") or "").strip()
        if not target:
            return self._send(400, {"error": "target is required"})
        if not params.get("authorized"):
            return self._send(400, {"error": "you must confirm you are authorized to test this target"})
        params.setdefault("attestation",
                           f"Authorized via RED-AI web console for {target} (operator-attested).")
        rid = _new_run()
        threading.Thread(target=_run_engagement, args=(rid, self.root, params),
                         daemon=True).start()
        return self._send(200, {"run_id": rid})


def serve(host: str = "127.0.0.1", port: int = 8787, data_dir="data") -> None:
    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    # Make the console usable out of the box: ensure the default operator exists.
    kr = Keyring(root)
    try:
        kr.key(DEFAULT_OPERATOR)
    except (AccessDenied, KeyError, FileNotFoundError):
        kr.create(DEFAULT_OPERATOR)
    _Handler.root = root
    httpd = ThreadingHTTPServer((host, port), _Handler)
    where = "localhost only" if host in ("127.0.0.1", "localhost") else host
    print(f"RED-AI console on http://{host}:{port}  ({where}) · data: {root}")
    if host not in ("127.0.0.1", "localhost"):
        print("  WARNING: bound to a non-localhost address — this control panel can drive "
              "attacks; do not expose it on the VPN/LAN.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nRED-AI console stopped.")
    finally:
        httpd.server_close()


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RED-AI — Live CTF Console</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--txt:#e6edf3;--mut:#9aa4b2;
        --blue:#58a6ff;--grn:#3fb950;--red:#f85149;--amb:#e3b341;--vio:#a371f7}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--txt);
    font:15px/1.5 'Segoe UI',system-ui,Arial,sans-serif}
  header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:12px}
  header h1{margin:0;font-size:20px;letter-spacing:.5px} header .sub{color:var(--mut);font-size:13px}
  .wrap{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:16px;max-width:1200px;margin:0 auto}
  @media(max-width:820px){.wrap{grid-template-columns:1fr}}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
  label{display:block;font-size:12px;color:var(--mut);margin:10px 0 4px;text-transform:uppercase;letter-spacing:.4px}
  input[type=text]{width:100%;background:#0b0f14;border:1px solid var(--line);color:var(--txt);
    border-radius:7px;padding:9px 10px;font-size:14px}
  .chk{display:flex;gap:8px;align-items:flex-start;margin:14px 0;font-size:13px;color:var(--txt)}
  .chk input{margin-top:3px}
  button{margin-top:6px;width:100%;background:var(--red);color:#fff;border:0;border-radius:8px;
    padding:11px;font-size:15px;font-weight:700;cursor:pointer}
  button:disabled{opacity:.5;cursor:not-allowed}
  .stages{margin-top:18px}
  .stage{display:flex;gap:10px;padding:8px 0;border-top:1px solid var(--line);opacity:.4;transition:opacity .2s}
  .stage.on{opacity:1}
  .dot{width:11px;height:11px;border-radius:50%;background:var(--line);margin-top:5px;flex:0 0 auto}
  .stage.on .dot{background:var(--blue)} .stage.done .dot{background:var(--grn)}
  .stage b{font-size:13px} .stage p{margin:2px 0 0;font-size:12px;color:var(--mut)}
  .feedcard{min-height:420px;display:flex;flex-direction:column}
  .banner{border-radius:8px;padding:12px 14px;margin-bottom:12px;font-weight:600;display:none}
  .banner.flag{display:block;background:#0f2417;border:1px solid var(--grn);color:#aff0c6}
  .banner.warn{display:block;background:#241b0f;border:1px solid var(--amb);color:#f0dcaf}
  .banner code{background:#0b0f14;padding:1px 6px;border-radius:4px;font-size:12px}
  .feed{flex:1;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;
    background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:10px}
  .row{display:flex;gap:10px;padding:3px 2px;border-bottom:1px solid #161b22}
  .row .tm{color:#6e7681;flex:0 0 auto} .row .st{flex:0 0 76px;color:var(--mut)}
  .row .tx{flex:1}
  .lv-good .tx{color:var(--grn)} .lv-finding .tx{color:var(--amb)}
  .lv-warn .tx{color:var(--red)} .lv-flag .tx{color:#fff;font-weight:700}
  .empty{color:var(--mut);padding:20px;text-align:center}
</style></head>
<body>
<header><h1>RED-AI</h1><span class="sub">Live CTF Console — watch the engagement, learn the method</span></header>
<div class="wrap">
  <div>
    <div class="card">
      <label>Target (IP or host)</label>
      <input id="target" type="text" placeholder="10.10.x.x">
      <label>Ports</label>
      <input id="ports" type="text" value="1-1000">
      <label>Operator</label>
      <input id="operator" type="text" value="local">
      <div class="chk"><input id="auth" type="checkbox">
        <span>I am authorized to test this target (lab/CTF or written permission). Every action is gated and recorded as evidence.</span></div>
      <button id="go">Engage</button>
    </div>
    <div class="card stages" id="stages">
      <div class="stage" data-s="authorize"><div class="dot"></div><div><b>1 · Authorize</b><p>Confirm you may test it. Nothing runs without this.</p></div></div>
      <div class="stage" data-s="recon"><div class="dot"></div><div><b>2 · Recon</b><p>Find what's running — open ports and services.</p></div></div>
      <div class="stage" data-s="enumerate"><div class="dot"></div><div><b>3 · Enumerate</b><p>Map the web surface — paths, parameters, exposed files.</p></div></div>
      <div class="stage" data-s="exploit"><div class="dot"></div><div><b>4 · Exploit</b><p>Try each authorized technique against what was found.</p></div></div>
      <div class="stage" data-s="capture"><div class="dot"></div><div><b>5 · Capture</b><p>Prove the flag by reading it — and reproduce it.</p></div></div>
    </div>
  </div>
  <div class="card feedcard">
    <div class="banner" id="banner"></div>
    <div class="feed" id="feed"><div class="empty">Enter a target and press Engage to watch RED-AI work.</div></div>
  </div>
</div>
<script>
const ORDER=["authorize","recon","enumerate","exploit","capture"];
let runId=null, since=0, timer=null;
const $=id=>document.getElementById(id);
function markStage(stage){
  const idx=ORDER.indexOf(stage); if(idx<0) return;
  document.querySelectorAll('.stage').forEach(el=>{
    const i=ORDER.indexOf(el.dataset.s);
    if(i<idx){el.classList.add('on','done');}
    else if(i===idx){el.classList.add('on');}
  });
}
function addRow(ln){
  const f=$('feed'); const empty=f.querySelector('.empty'); if(empty) empty.remove();
  const d=document.createElement('div'); d.className='row lv-'+(ln.level||'info');
  d.innerHTML=`<span class="tm">${ln.t||''}</span><span class="st">${ln.stage||''}</span><span class="tx"></span>`;
  d.querySelector('.tx').textContent=ln.text; f.appendChild(d); f.scrollTop=f.scrollHeight;
  markStage(ln.stage);
}
function finish(res,err){
  clearInterval(timer); timer=null; $('go').disabled=false;
  const b=$('banner');
  if(res && res.captured){ b.className='banner flag';
    b.innerHTML=`FLAG CAPTURED → <code>${res.flag_value||'(file read)'}</code> · reproduced ${Math.round((res.rate||0)*100)}% · ${res.steps} steps`;
    document.querySelectorAll('.stage').forEach(el=>el.classList.add('on','done'));
  } else if(res){ b.className='banner warn';
    b.innerHTML=`No flag captured (${res.outcome}). Not broken in ${res.steps} step(s) — this is signal, not "secure".`;
  } else if(err){ b.className='banner warn'; b.textContent=err; }
}
async function poll(){
  try{
    const r=await fetch(`/api/events?run=${runId}&since=${since}`);
    const j=await r.json();
    (j.feed||[]).forEach(ln=>{addRow(ln); since=ln.seq+1;});
    if(j.done){ finish(j.result, j.error); }
  }catch(e){}
}
$('go').onclick=async()=>{
  const target=$('target').value.trim();
  if(!target){alert('Enter a target IP or host.');return;}
  if(!$('auth').checked){alert('Please confirm you are authorized to test this target.');return;}
  $('feed').innerHTML=''; $('banner').className='banner'; since=0;
  document.querySelectorAll('.stage').forEach(el=>el.classList.remove('on','done'));
  $('go').disabled=true;
  try{
    const r=await fetch('/api/engage',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({target,ports:$('ports').value.trim()||'1-1000',
        operator:$('operator').value.trim()||'local',authorized:true})});
    const j=await r.json();
    if(j.error){finish(null,j.error);return;}
    runId=j.run_id; timer=setInterval(poll,600); poll();
  }catch(e){finish(null,'Could not reach the console server.');}
};
</script>
</body></html>
"""
