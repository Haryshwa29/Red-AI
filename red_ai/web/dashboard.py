"""The in-depth RED-AI dashboard (single page, vanilla JS, offline).

Shows the *process*, not just the result: a live attack feed, the surface map
recon built, per-module coverage counters, the authorization gate's decisions,
run metrics, and — when a run ends — a 'where to improve' gap list. Realtime over
WebSocket, with an automatic polling fallback. Served as one string by server.py.
"""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RED-AI — Operations Dashboard</title>
<style>
  :root{--bg:#0d1117;--p:#161b22;--p2:#0b0f14;--ln:#30363d;--tx:#e6edf3;--mu:#9aa4b2;
        --bl:#58a6ff;--gn:#3fb950;--rd:#f85149;--am:#e3b341;--vi:#a371f7}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--tx);
    font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif}
  header{display:flex;align-items:center;gap:14px;padding:12px 18px;border-bottom:1px solid var(--ln);
    position:sticky;top:0;background:var(--bg);z-index:5;flex-wrap:wrap}
  header h1{margin:0;font-size:18px;letter-spacing:.5px} header .sub{color:var(--mu);font-size:12px}
  .ws{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--mu);margin-left:auto}
  .ws .d{width:9px;height:9px;border-radius:50%;background:var(--rd)} .ws.on .d{background:var(--gn)}
  .bar{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;padding:12px 18px;border-bottom:1px solid var(--ln)}
  .fld{display:flex;flex-direction:column;gap:3px}
  .fld label{font-size:10px;text-transform:uppercase;letter-spacing:.4px;color:var(--mu)}
  .bar input[type=text]{background:var(--p2);border:1px solid var(--ln);color:var(--tx);border-radius:6px;
    padding:7px 9px;font-size:13px}
  #target{width:160px} #ports{width:96px} #flagpat{width:230px}
  .chk{display:flex;gap:6px;align-items:center;font-size:12px;color:var(--tx)}
  button{border:0;border-radius:6px;padding:8px 14px;font-weight:700;font-size:13px;cursor:pointer}
  #go{background:var(--rd);color:#fff} #stop{background:#30363d;color:var(--tx)} button:disabled{opacity:.45;cursor:not-allowed}
  .mods{display:flex;gap:10px;flex-wrap:wrap;padding:8px 18px;border-bottom:1px solid var(--ln);font-size:12px}
  .mods .t{color:var(--mu);text-transform:uppercase;letter-spacing:.4px;font-size:10px;width:100%;margin-bottom:2px}
  .mods label{display:flex;gap:5px;align-items:center;color:var(--tx)}
  .stages{display:flex;gap:0;padding:10px 18px;border-bottom:1px solid var(--ln);flex-wrap:wrap}
  .stage{display:flex;align-items:center;gap:7px;padding:4px 14px 4px 0;opacity:.4}
  .stage.on{opacity:1} .stage .d{width:9px;height:9px;border-radius:50%;background:var(--ln)}
  .stage.on .d{background:var(--bl)} .stage.done .d{background:var(--gn)} .stage b{font-size:12px}
  .stage .ar{color:var(--mu);margin:0 10px 0 4px}
  .grid{display:grid;grid-template-columns:1.55fr 1fr;gap:14px;padding:14px 18px;max-width:1500px}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  .col{display:flex;flex-direction:column;gap:14px;min-width:0}
  .card{background:var(--p);border:1px solid var(--ln);border-radius:9px;overflow:hidden}
  .card h3{margin:0;padding:9px 12px;font-size:12px;letter-spacing:.4px;text-transform:uppercase;
    color:var(--mu);border-bottom:1px solid var(--ln);display:flex;justify-content:space-between}
  .banner{display:none;margin:0;padding:12px 14px;font-weight:600}
  .banner.flag{display:block;background:#0f2417;border-bottom:1px solid var(--gn);color:#aff0c6}
  .banner.warn{display:block;background:#241b0f;border-bottom:1px solid var(--am);color:#f0dcaf}
  .banner code{background:var(--p2);padding:1px 6px;border-radius:4px}
  .feed{max-height:460px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
  .r{display:flex;gap:9px;padding:3px 12px;border-bottom:1px solid #12161c;cursor:pointer}
  .r:hover{background:#12161c} .r .tm{color:#6e7681;flex:0 0 auto} .r .st{flex:0 0 64px;color:var(--mu)}
  .r .tx{flex:1;word-break:break-word}
  .lv-good .tx{color:var(--gn)} .lv-finding .tx{color:var(--am)} .lv-warn .tx{color:var(--rd)}
  .lv-flag .tx{color:#fff;font-weight:700}
  .raw{display:none;padding:4px 12px 8px 85px;color:#8b949e;font-size:11px;white-space:pre-wrap;background:var(--p2)}
  .raw.show{display:block}
  .pad{padding:10px 12px;font-size:12.5px} .pad.sc{max-height:200px;overflow:auto}
  .chip{display:inline-block;background:var(--p2);border:1px solid var(--ln);border-radius:5px;
    padding:1px 7px;margin:2px 3px 0 0;font-size:11.5px;font-family:ui-monospace,monospace}
  .chip.sev{border-color:var(--rd);color:#ffb0ab}
  table{width:100%;border-collapse:collapse;font-size:12px} th,td{text-align:left;padding:5px 12px}
  th{color:var(--mu);font-weight:600;font-size:10.5px;text-transform:uppercase;border-bottom:1px solid var(--ln)}
  td{border-bottom:1px solid #12161c;font-family:ui-monospace,monospace}
  td.n{text-align:right} .cap{color:var(--gn);font-weight:700} .adv{color:var(--am)}
  .k{color:var(--mu)} .metrics{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--ln)}
  .metrics div{background:var(--p);padding:9px 12px} .metrics b{display:block;font-size:18px} .metrics span{color:var(--mu);font-size:11px}
  .gaps{display:none} .gaps.show{display:block}
  .gap{padding:9px 12px;border-bottom:1px solid #12161c}
  .gap .l{color:var(--tx);font-weight:600} .gap .m{color:var(--mu);font-size:12px}
  .gap .c{display:inline-block;margin-top:3px;font-size:10.5px;color:var(--vi);border:1px solid var(--vi);
    border-radius:4px;padding:0 6px}
  .empty{color:var(--mu);padding:16px;text-align:center}
  .tabs{display:flex;gap:4px;padding:8px 18px 0;border-bottom:1px solid var(--ln)}
  .tab{padding:8px 16px;font-size:13px;font-weight:700;color:var(--mu);cursor:pointer;
    border:1px solid transparent;border-bottom:none;border-radius:7px 7px 0 0}
  .tab.on{color:var(--tx);background:var(--p);border-color:var(--ln)}
  .cwrap{max-width:1100px;padding:16px 18px;display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:820px){.cwrap{grid-template-columns:1fr}}
  textarea{width:100%;min-height:200px;background:var(--p2);border:1px solid var(--ln);color:var(--tx);
    border-radius:7px;padding:10px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;resize:vertical}
  .rsa{display:flex;gap:8px;margin-top:8px} .rsa input{flex:1;min-width:0}
  .cfind{border:1px solid var(--ln);border-radius:8px;margin:10px 12px;overflow:hidden}
  .cfind .hd{padding:7px 10px;font-size:12px;display:flex;gap:8px;align-items:center;border-bottom:1px solid var(--ln)}
  .sev{font-size:10px;font-weight:700;padding:1px 7px;border-radius:4px}
  .sev.critical{background:#3d1416;color:#ffb0ab} .sev.high{background:#3a2a0c;color:#f0c674}
  .sev.medium{background:#15243d;color:#9cc4ff}
  .cfind .bd{padding:8px 10px;font-size:12.5px}
  .recov{background:#0f2417;border:1px solid var(--gn);color:#aff0c6;border-radius:6px;padding:8px 10px;
    margin:6px 0;font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-word;white-space:pre-wrap}
  .cfind .mu{color:var(--mu);font-size:11.5px;margin-top:3px}
</style></head>
<body>
<header>
  <h1>RED-AI</h1><span class="sub">Operations Dashboard — watch the process, find where to improve</span>
  <span class="ws" id="wsind"><span class="d"></span><span id="wstxt">connecting…</span></span>
</header>
<div class="tabs">
  <div class="tab on" id="tab-engage" onclick="showView('engage')">Live Engagement</div>
  <div class="tab" id="tab-crypto" onclick="showView('crypto')">Crypto Audit</div>
</div>
<div id="view-engage">
<div class="bar">
  <div class="fld" style="flex:1 1 240px;min-width:200px"><label>Objective / goal (recorded in evidence)</label><input id="objective" type="text" placeholder="e.g. capture the web flag on this box"></div>
  <div class="fld"><label>Target</label><input id="target" type="text" placeholder="10.10.x.x"></div>
  <div class="fld"><label>Ports</label><input id="ports" type="text" value="1-1000"></div>
  <div class="fld"><label>Flag pattern (regex)</label><input id="flagpat" type="text" placeholder="default: THM/HTB/flag{…} or 32-hex"></div>
  <div class="fld"><label>Operator</label><input id="operator" type="text" value="local" style="width:90px"></div>
  <label class="chk"><input id="auth" type="checkbox"> I'm authorized</label>
  <label class="chk" title="Find ALL vulnerabilities instead of stopping at the first flag"><input id="auditmode" type="checkbox"> Audit (find all)</label>
  <button id="go">Engage</button>
  <button id="stop" disabled>Abort</button>
</div>
<div class="mods" id="mods"><span class="t">Modules (toggle to study coverage)</span></div>
<div class="stages" id="stages"></div>

<div class="grid">
  <div class="col">
    <div class="card">
      <div class="banner" id="banner"></div>
      <h3>Attack feed <span class="k" id="feedcount">click a line for the raw event</span></h3>
      <div class="feed" id="feed"><div class="empty">Enter a target and press Engage.</div></div>
    </div>
    <div class="card">
      <h3>Operations <span class="k" id="opcount">the literal commands / requests RED-AI runs</span></h3>
      <div class="feed" id="ops" style="max-height:320px"><div class="empty">each network operation RED-AI performs appears here, as it happens</div></div>
    </div>
    <div class="card">
      <h3>Where to improve <span class="k">gaps found this run</span></h3>
      <div class="gaps" id="gaps"></div>
      <div class="empty" id="gapsempty">Runs that fall short list the missing capabilities here.</div>
    </div>
  </div>
  <div class="col">
    <div class="card"><h3>Run metrics</h3>
      <div class="metrics">
        <div><b id="m_steps">0</b><span>exploit steps</span></div>
        <div><b id="m_surf">0</b><span>web surfaces</span></div>
        <div><b id="m_paths">0</b><span>paths discovered</span></div>
        <div><b id="m_deny">0</b><span>gate denials</span></div>
      </div>
    </div>
    <div class="card"><h3>Surface map <span class="k">what recon built</span></h3>
      <div class="pad sc" id="surface"><div class="empty">ports, services, paths, params appear here</div></div>
    </div>
    <div class="card"><h3>Module coverage <span class="k">tried · advanced · captured</span></h3>
      <table><thead><tr><th>Module</th><th class="n">try</th><th class="n">adv</th><th class="n">cap</th></tr></thead>
      <tbody id="modrows"></tbody></table>
    </div>
    <div class="card"><h3>Authorization gate <span class="k">denials = the boundary at work</span></h3>
      <div class="pad sc" id="gate"><div class="empty">no denials yet</div></div>
    </div>
  </div>
</div>
</div><!-- view-engage -->

<div id="view-crypto" hidden>
  <div class="cwrap">
    <div class="card">
      <h3>Ciphertext samples <span class="k">one per line — hex, base64, or raw</span></h3>
      <div style="padding:10px 12px">
        <textarea id="samples" placeholder="Paste ciphertext samples, one per line.&#10;hex / base64 / raw text all accepted."></textarea>
        <div class="rsa">
          <input id="rn" type="text" placeholder="RSA n (optional)">
          <input id="re" type="text" placeholder="e">
          <input id="rc" type="text" placeholder="c">
        </div>
        <button id="analyze" style="margin-top:10px;background:var(--vi)">Analyze &amp; recover plaintext</button>
        <p class="mu" style="color:var(--mu);font-size:12px;margin:8px 0 0">Offline, on your machine. Recovers plaintext only when the crypto is misused; correct AES-GCM / TLS 1.3 will not yield — that discipline is the point.</p>
      </div>
    </div>
    <div class="card">
      <h3>Result <span class="k">recovered plaintext is the proof</span></h3>
      <div class="banner" id="cbanner"></div>
      <div id="cfindings"><div class="empty">results appear here after you analyze</div></div>
    </div>
  </div>
</div>

<script>
const STAGES=[["authorize","Authorize"],["recon","Recon"],["enumerate","Enumerate"],["exploit","Exploit"],["capture","Capture"]];
const $=id=>document.getElementById(id);
let ws=null, runId=null, roster=[], counters={}, ports={}, services={}, paths=new Set(), params=new Set(), denies=[], pollTimer=null, since=0, curTarget="", opN=0;

// ---- stages ----
$("stages").innerHTML=STAGES.map((s,i)=>`<div class="stage" data-s="${s[0]}"><span class="d"></span><b>${i+1} ${s[1]}</b></div>`+(i<4?'<span class="ar">→</span>':'')).join("");
function markStage(stage){const idx=STAGES.findIndex(s=>s[0]===stage);if(idx<0)return;
  document.querySelectorAll('.stage').forEach(el=>{const i=STAGES.findIndex(s=>s[0]===el.dataset.s);
    if(i<idx){el.classList.add('on','done')} else if(i===idx){el.classList.add('on')}});}

// ---- modules ----
function renderMods(){$("mods").innerHTML='<span class="t">Modules (toggle to study coverage)</span>'+
  roster.map(m=>`<label class="chk"><input type="checkbox" class="modtog" value="${m.id}" checked> ${m.name}</label>`).join("");
  $("modrows").innerHTML=roster.map(m=>`<tr><td>${m.name}</td><td class="n" id="t_${m.id}">0</td><td class="n" id="a_${m.id}">0</td><td class="n" id="c_${m.id}">0</td></tr>`).join("");}
function enabledMods(){return [...document.querySelectorAll('.modtog')].filter(c=>c.checked).map(c=>c.value);}

// ---- reset ----
function reset(){counters={};ports={};services={};paths=new Set();params=new Set();denies=[];since=0;
  roster.forEach(m=>counters[m.id]={t:0,a:0,c:0});
  $("feed").innerHTML="";$("banner").className="banner";$("gaps").className="gaps";$("gaps").innerHTML="";
  $("gapsempty").style.display="block";$("gate").innerHTML='<div class="empty">no denials yet</div>';
  $("surface").innerHTML='<div class="empty">scanning…</div>';
  $("ops").innerHTML='<div class="empty">each network operation RED-AI performs appears here, as it happens</div>';
  opN=0;$("opcount").textContent="the literal commands / requests RED-AI runs";
  ["m_steps","m_surf","m_paths","m_deny"].forEach(i=>$(i).textContent="0");
  document.querySelectorAll('.stage').forEach(el=>el.classList.remove('on','done'));
  roster.forEach(m=>{$("t_"+m.id).textContent="0";$("a_"+m.id).textContent="0";$("c_"+m.id).textContent="0";});}

// ---- feed ----
function addFeed(rec){if(!rec.ann)return;const f=$("feed");const e=f.querySelector('.empty');if(e)e.remove();
  const d=document.createElement('div');d.className='r lv-'+(rec.ann.level||'info');
  d.innerHTML=`<span class="tm">${rec.t||''}</span><span class="st">${rec.ann.stage||''}</span><span class="tx"></span>`;
  d.querySelector('.tx').textContent=rec.ann.text;
  const raw=document.createElement('div');raw.className='raw';raw.textContent=rec.kind+' '+JSON.stringify(rec.data);
  d.onclick=()=>raw.classList.toggle('show');
  f.appendChild(d);f.appendChild(raw);f.scrollTop=f.scrollHeight;markStage(rec.ann.stage);}

// ---- surface map ----
function renderSurface(){let h="";
  const pk=Object.keys(ports);if(pk.length){h+='<div><b class="k">Open ports</b><br>'+pk.map(p=>`<span class="chip">${p}${services[p]?' '+services[p]:''}</span>`).join("")+'</div>';}
  if(paths.size){h+='<div style="margin-top:8px"><b class="k">Discovered paths ('+paths.size+')</b><br>'+[...paths].slice(0,60).map(p=>`<span class="chip">${p}</span>`).join("")+'</div>';}
  if(params.size){h+='<div style="margin-top:8px"><b class="k">Parameters</b><br>'+[...params].map(p=>`<span class="chip">${p}</span>`).join("")+'</div>';}
  $("surface").innerHTML=h||'<div class="empty">nothing yet</div>';}

// ---- operations log: the literal commands / requests RED-AI runs ----
function opLine(rec){const d=rec.data||{},t=curTarget||"target";
  if(rec.kind==="probe"&&d.state==="open")return `tcp-connect ${t}:${d.port}   -> open (${d.latency_ms}ms)`;
  if(rec.kind==="web_enum")return `GET  http://${t}:${d.port}/   -> HTTP ${(d.root||{}).status}`;
  if(rec.kind==="tls_posture")return `tls-handshake ${t}:${d.port}   [${(d.accepted||[]).join(', ')}]`;
  if(rec.kind==="step"){const extra=(d.obs&&/via/.test(d.obs))?('  « '+d.obs+' »'):'';
    return `GET  http://${t}${d.path||''}${extra}   -> ${d.outcome}${d.flag_claimed?'  ★ FLAG':''}`;}
  return null;}
function addOp(rec){const line=opLine(rec);if(!line)return;const o=$("ops");const e=o.querySelector('.empty');if(e)e.remove();
  const row=document.createElement('div');row.className='r'+(rec.data&&rec.data.flag_claimed?' lv-flag':'');
  row.innerHTML=`<span class="tm">${rec.t||''}</span><span class="tx"></span>`;row.querySelector('.tx').textContent=line;
  o.appendChild(row);o.scrollTop=o.scrollHeight;opN++;$("opcount").textContent=opN+" operations";}

// ---- views + crypto audit ----
function showView(v){$("view-engage").hidden=v!=='engage';$("view-crypto").hidden=v!=='crypto';
  $("tab-engage").classList.toggle('on',v==='engage');$("tab-crypto").classList.toggle('on',v==='crypto');}
function renderCrypto(rep){const b=$("cbanner");b.className='banner '+(rep.broke?'flag':'warn');b.textContent=rep.verdict;
  const el=$("cfindings");
  if(!rep.findings.length){el.innerHTML='<div class="empty">No weakness demonstrated. (Absence of a break is NOT a proof of safety.)</div>';return;}
  el.innerHTML=rep.findings.map(f=>`<div class="cfind"><div class="hd"><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span><b>${f.class}</b><span class="mu">${f.method}</span></div>
    <div class="bd">${f.recovered?'<div class="mu">RECOVERED PLAINTEXT (proof):</div><div class="recov"></div>':''}
    <div class="mu">${f.evidence}</div><div class="mu">fix: ${f.remediation}</div><div class="mu">ref: ${f.reference}</div></div></div>`).join("");
  const recs=rep.findings.filter(f=>f.recovered),nodes=el.querySelectorAll('.recov');
  recs.forEach((f,i)=>{if(nodes[i])nodes[i].textContent=f.recovered;});}

// ---- route one record ----
function handle(rec){
  addFeed(rec);addOp(rec);const d=rec.data||{};
  if(rec.kind==="probe"&&d.state==="open"){ports[d.port]=1;renderSurface();}
  else if(rec.kind==="finding"){ports[d.port]=1;if(d.service)services[d.port]=d.service;renderSurface();}
  else if(rec.kind==="web_enum"){(d.paths||[]).forEach(p=>paths.add(p));(d.params||[]).forEach(p=>params.add(p));
    if(d.findings)d.findings.forEach(f=>paths.add(f.path));renderSurface();}
  else if(rec.kind==="step"){const m=d.module;if(counters[m]){counters[m].t++;if(d.outcome==="advanced")counters[m].a++;if(d.flag_claimed)counters[m].c++;
    $("t_"+m)&&($("t_"+m).textContent=counters[m].t);$("a_"+m)&&($("a_"+m).textContent=counters[m].a,$("a_"+m).className="n adv");
    d.flag_claimed&&$("c_"+m)&&($("c_"+m).textContent=counters[m].c,$("c_"+m).className="n cap");}
    if(d.path){paths.add(d.path);renderSurface();}
    $("m_steps").textContent=Object.values(counters).reduce((s,c)=>s+c.t,0);}
  else if(rec.kind==="gate"&&d.decision==="deny"){denies.push(d);$("m_deny").textContent=denies.length;
    $("gate").innerHTML=denies.map(x=>`<div><span class="chip sev">${x.technique}</span> ${x.reason} <span class="k">(${x.module||''})</span></div>`).join("");}
  else if(rec.kind==="recon_done"){$("m_surf").textContent=d.web_surfaces||0;}
  if(paths.size)$("m_paths").textContent=paths.size;
}

// ---- done ----
function done(result,gaps){stopPoll();$("go").disabled=false;$("stop").disabled=true;
  const b=$("banner");
  if(result&&result.captured){b.className="banner flag";
    const vl=result.vulns||[];
    if(result.audit_mode&&vl.length){
      b.innerHTML=`<b>${vl.length} VULNERABILIT${vl.length>1?'IES':'Y'} CONFIRMED</b> · ${result.steps} steps`+
        '<div style="margin-top:6px;font-weight:400;font-size:12.5px;font-family:ui-monospace,monospace">'+
        vl.map(v=>`• ${(v.technique||'').replace(/_/g,' ')}${v.path?' @ '+v.path:''} → ${v.flag_value||'(read)'}`).join('<br>')+'</div>';
    } else {
      b.innerHTML=`FLAG CAPTURED → <code>${result.flag_value||'(file read)'}</code> · reproduced ${Math.round((result.rate||0)*100)}% · ${result.steps} steps`;
    }
    document.querySelectorAll('.stage').forEach(el=>el.classList.add('on','done'));}
  else if(result){b.className="banner warn";b.innerHTML=`No flag captured (${result.outcome}). Not broken in ${result.steps} step(s) — signal, not "secure".`;}
  if(gaps&&gaps.length){$("gapsempty").style.display="none";$("gaps").className="gaps show";
    $("gaps").innerHTML=gaps.map(g=>`<div class="gap"><div class="l">${g.lead}</div><div class="m">→ ${g.missing}</div><span class="c">${g.checkpoint}</span></div>`).join("");}
}

// ---- transport: WebSocket first, polling fallback ----
function startWS(){try{ws=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws");}catch(e){return fallback();}
  ws.onopen=()=>{$("wsind").className="ws on";$("wstxt").textContent="live (websocket)";};
  ws.onclose=()=>{$("wsind").className="ws";$("wstxt").textContent="disconnected";};
  ws.onerror=()=>{};
  ws.onmessage=ev=>{const m=JSON.parse(ev.data);
    if(m.type==="hello"){if(!roster.length){roster=m.modules;renderMods();}}
    else if(m.type==="started"){runId=m.run;}
    else if(m.type==="event"){handle(m.rec);}
    else if(m.type==="done"){done(m.result,m.gaps);}
    else if(m.type==="crypto_result"){renderCrypto(m.report);}
    else if(m.type==="error"){done({captured:false,outcome:m.error,steps:0},[]);}};}
function fallback(){ // load modules over HTTP if WS never came up
  if(!roster.length)fetch("/api/modules").then(r=>r.json()).then(j=>{roster=j.modules;renderMods();});
  $("wstxt").textContent="polling (fallback)";}
function startPoll(rid){since=0;pollTimer=setInterval(()=>{fetch(`/api/events?run=${rid}&since=${since}`).then(r=>r.json()).then(j=>{
  (j.feed||[]).forEach(rec=>{handle(rec);since=rec.seq+1;});if(j.done)done(j.result,j.gaps);});},600);}
function stopPoll(){if(pollTimer){clearInterval(pollTimer);pollTimer=null;}}

// ---- controls ----
$("go").onclick=()=>{const target=$("target").value.trim();
  if(!target)return alert("Enter a target IP or host.");
  if(!$("auth").checked)return alert("Confirm you are authorized to test this target.");
  reset();curTarget=target;$("go").disabled=true;$("stop").disabled=false;
  const params={target,objective:$("objective").value.trim(),ports:$("ports").value.trim()||"1-1000",
    operator:$("operator").value.trim()||"local",flag_pattern:$("flagpat").value.trim()||null,
    enabled_modules:enabledMods(),audit:$("auditmode").checked,authorized:true};
  if(ws&&ws.readyState===1){params.action="engage";ws.send(JSON.stringify(params));}
  else{fetch("/api/engage",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(params)})
    .then(r=>r.json()).then(j=>{if(j.error){done({captured:false,outcome:j.error,steps:0},[]);return;}runId=j.run_id;startPoll(j.run_id);});}};
$("stop").onclick=()=>{if(ws&&ws.readyState===1)ws.send(JSON.stringify({action:"abort",run:runId}));};
$("analyze").onclick=()=>{const samples=$("samples").value.split("\n").map(s=>s.trim()).filter(Boolean);
  if(!samples.length)return alert("Paste at least one ciphertext sample.");
  const rsa=($("rn").value.trim()&&$("re").value.trim()&&$("rc").value.trim())?
    {n:$("rn").value.trim(),e:$("re").value.trim(),c:$("rc").value.trim()}:null;
  $("cfindings").innerHTML='<div class="empty">analyzing…</div>';$("cbanner").className="banner";
  if(ws&&ws.readyState===1){ws.send(JSON.stringify({action:"crypto",samples,rsa}));}
  else{fetch("/api/crypto",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({samples,rsa})})
    .then(r=>r.json()).then(j=>renderCrypto(j.report));}};

startWS();
// if WS didn't connect within 2s, make sure modules still load
setTimeout(()=>{if(!roster.length)fallback();},2000);
</script>
</body></html>
"""
