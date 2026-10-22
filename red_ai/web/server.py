"""RED-AI dashboard server: one stdlib HTTP server that also speaks WebSocket.

Serves the in-depth dashboard, upgrades ``/ws`` to a WebSocket for realtime
control + streaming, and keeps ``/api/engage`` + ``/api/events`` as a polling
fallback. Localhost-only by default — this console drives engagements, so do not
expose it on the VPN/LAN. Authorization is unchanged: an operator identity
(auto-created ``local`` on first launch) plus an explicit authorization tick,
both recorded in the hash-linked evidence; every exploit step is still gated.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from red_ai.control.identity import Keyring, DEFAULT_OPERATOR, AccessDenied
from red_ai.engage import module_roster
from red_ai.web.ws import accept_key, is_ws_upgrade, WSConnection
from red_ai.web.hub import Hub
from red_ai.web.dashboard import DASHBOARD_HTML

_HUB: Hub = None  # set in serve()


def _validate(params: dict) -> "str | None":
    if not (params.get("target") or "").strip():
        return "target is required"
    if not params.get("authorized"):
        return "you must confirm you are authorized to test this target"
    return None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

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
        if u.path == "/ws" and is_ws_upgrade(self.headers):
            return self._websocket()
        if u.path in ("/", "/index.html"):
            return self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
        if u.path == "/api/modules":
            return self._send(200, {"modules": module_roster()})
        if u.path == "/api/events":
            q = parse_qs(u.query)
            rid = (q.get("run") or [""])[0]
            since = int((q.get("since") or ["0"])[0])
            return self._send(200, _HUB.poll(rid, since))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path not in ("/api/engage", "/api/crypto"):
            return self._send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            params = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad request body"})
        if u.path == "/api/crypto":
            from red_ai.crypto.analyze import analyze_samples
            rep = analyze_samples(params.get("samples") or [], rsa=params.get("rsa"))
            return self._send(200, {"report": rep})
        err = _validate(params)
        if err:
            return self._send(400, {"error": err})
        params.setdefault("attestation",
                          f"Authorized via RED-AI dashboard for {params['target']} (operator-attested).")
        return self._send(200, {"run_id": _HUB.start(params)})

    def _websocket(self):
        self.close_connection = True
        key = self.headers.get("Sec-WebSocket-Key")
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key(key))
        self.end_headers()
        conn = WSConnection(self.rfile, self.wfile)
        _HUB.register(conn)
        conn.send(json.dumps({"type": "hello", "modules": module_roster()}))
        try:
            while True:
                msg = conn.recv()
                if msg is None:
                    break
                try:
                    m = json.loads(msg)
                except Exception:
                    continue
                action = m.get("action")
                if action == "engage":
                    err = _validate(m)
                    if err:
                        conn.send(json.dumps({"type": "error", "error": err}))
                        continue
                    m.setdefault("attestation",
                                 f"Authorized via RED-AI dashboard for {m['target']} (operator-attested).")
                    _HUB.start(m)
                elif action == "abort":
                    _HUB.abort(m.get("run", ""))
                elif action == "crypto":
                    from red_ai.crypto.analyze import analyze_samples
                    rep = analyze_samples(m.get("samples") or [], rsa=m.get("rsa"))
                    conn.send(json.dumps({"type": "crypto_result", "report": rep}))
                elif action == "ping":
                    conn.send(json.dumps({"type": "pong"}))
        finally:
            _HUB.unregister(conn)


def _bind(host: str, port: int, tries: int = 25):
    """Bind the first free port at or above `port`. Returns (httpd, actual_port).

    A fixed port is fragile on a dev machine already running other servers
    (e.g. a Svelte/Vite or FastAPI dev server), so we fall forward to the next
    free port instead of crashing with 'address already in use'.
    """
    last: "OSError | None" = None
    for p in range(port, port + tries):
        try:
            return ThreadingHTTPServer((host, p), _Handler), p
        except OSError as e:  # port busy / not assignable — try the next one
            last = e
    raise OSError(f"no free port in {port}..{port + tries - 1}: {last}")


def serve(host: str = "127.0.0.1", port: int = 8787, data_dir="data",
          open_browser: bool = False) -> None:
    global _HUB
    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    kr = Keyring(root)
    try:
        kr.key(DEFAULT_OPERATOR)
    except (AccessDenied, KeyError, FileNotFoundError):
        kr.create(DEFAULT_OPERATOR)
    _HUB = Hub(root)
    requested = port
    httpd, port = _bind(host, port)
    where = "localhost only" if host in ("127.0.0.1", "localhost") else host
    url = f"http://{'127.0.0.1' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}"
    print("=" * 60)
    if port != requested:
        print(f"RED-AI dashboard  (port {requested} was in use -> using {port})")
    else:
        print("RED-AI dashboard")
    print(f"  OPEN THIS IN YOUR BROWSER:  {url}")
    print(f"  ({where}) · data: {root}")
    print("  Keep this window open. Close it to stop the server.")
    print("=" * 60)
    if host not in ("127.0.0.1", "localhost"):
        print("  WARNING: bound to a non-localhost address — this console can drive attacks; "
              "do not expose it on the VPN/LAN.")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nRED-AI dashboard stopped.")
    finally:
        httpd.server_close()
