"""A deliberately-vulnerable showcase app — the stand-in for a lab target like a
vulnerable iPad web app. Unlike the single-vuln range boxes, this ONE server
exposes many weakness classes at once, so an audit-mode engagement
(`--audit`) demonstrates the full breadth RED-AI finds in a single run:

  * exposed secret file (/.env)                      — misconfiguration
  * robots.txt breadcrumb → backup                   — information disclosure
  * hidden page reachable only by brute force         — content discovery
  * admin panel behind default HTTP Basic creds       — credential access
  * local file inclusion on ?file=                    — injection (LFI)
  * SQL injection on ?id=                             — injection (SQLi)
  * command injection on ?host=                       — injection (RCE)

Run it on any machine and point RED-AI at it:

    python -m redai_range.showcase 8080
    python -m red_ai engage --target <ip> --ports 8080 --operator me --audit
"""
from __future__ import annotations

import base64
import http.server
import socketserver
import sys
import urllib.parse as _up

_OK = "Basic " + base64.b64encode(b"admin:admin").decode()

F = {
    "env": "THM{exposed_env_secret_key}",
    "backup": "THM{robots_disclosed_backup}",
    "internal": "THM{hidden_internal_dashboard}",
    "admin": "THM{default_creds_admin_panel}",
    "lfi": "THM{lfi_arbitrary_file_read}",
    "sqli": "THM{sqli_union_data_dump}",
    "cmd": "THM{command_injection_to_rce}",
}

_HOME = (
    "<html><body><h1>Acme Lab Portal</h1>"
    '<p>Tools: <a href="/view?file=welcome.txt">document viewer</a> · '
    '<a href="/item?id=1">catalog</a> · '
    '<a href="/ping?host=127.0.0.1">network ping</a></p>'
    "</body></html>"
)


def respond(path, query, headers):
    q = _up.parse_qs(query)
    if path == "/":
        return 200, {}, _HOME.encode()
    if path == "/robots.txt":
        return 200, {}, b"User-agent: *\nDisallow: /z9-nightly-backups/\n"
    if path == "/.env":
        return 200, {}, f"APP_ENV=prod\nDB_PASS=s3cr3t\nSECRET_KEY={F['env']}\n".encode()
    if path == "/z9-nightly-backups/flag.txt":
        return 200, {}, (F["backup"] + "\n").encode()
    if path == "/internal":                       # not linked, not robots, not wordlist leaf
        return 200, {}, f"<html>Internal dashboard. {F['internal']}</html>".encode()
    if path == "/admin":
        if headers.get("Authorization") == _OK:
            return 200, {}, f"<html>Admin panel. {F['admin']}</html>".encode()
        return 401, {"WWW-Authenticate": 'Basic realm="admin"'}, b"Unauthorized"
    if path == "/view":                            # LFI
        f = q.get("file", [""])[0]
        if f in ("../../flag", "....//....//flag", "/etc/flag"):
            return 200, {}, (F["lfi"] + "\n").encode()
        if f == "welcome.txt":
            return 200, {}, b"Welcome to the document viewer.\n"
        return 200, {}, b"no such file\n"
    if path == "/item":                            # SQLi
        raw = q.get("id", [""])[0].lower()
        if ("union" in raw and "select" in raw) or "or 1=1" in raw or "or '1'='1" in raw:
            return 200, {}, (f"secret row: {F['sqli']}\n").encode()
        if raw.isdigit():
            return 200, {}, (f"widget #{raw}\n").encode()
        return 200, {}, b"invalid id\n"
    if path == "/ping":                            # command injection
        host = q.get("host", [""])[0]
        if any(c in host for c in (";", "&&", "|", "$(", "`")):
            return 200, {}, (f"PING {host}\n{F['cmd']}\n").encode()
        if host:
            return 200, {}, (f"PING {host}: 64 bytes\n").encode()
        return 200, {}, b"usage: ?host=\n"
    return 404, {}, b"Not Found"


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path, _, query = self.path.partition("?")
        status, hdrs, body = respond(path, query, dict(self.headers))
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "AcmeLab/1.0")
        self.end_headers()
        self.wfile.write(body)


class _TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
    print(f"Acme vulnerable showcase on http://{host}:{port}  "
          f"({len(F)} weakness classes)  — authorized lab targets only", flush=True)
    _TS((host, port), _H).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
