"""RED-AI Practice Range — a deliberately-vulnerable *website* you own.

This is a legal practice target: it runs on your own machine, binds to
localhost only, and holds only fabricated data. Point RED-AI at it, or browse
it by hand to learn how each bug is found. It is a richer, multi-page sibling of
``showcase.py`` (one-page) and the single-vuln ``boxes.py`` ladder.

Run it:
    python -m redai_range.site            # http://127.0.0.1:5000
    python -m redai_range.site 5001       # choose a port

Attack it with RED-AI:
    python -m red_ai operator add me
    python -m red_ai engage --target http://127.0.0.1:5000 --operator me --audit

SAFETY / why this is not a real foothold
-----------------------------------------
Every "dangerous" primitive is sandboxed so the app is exploitable *from the
attacker's view* but gives no real access to the host:
  * LFI reads from an in-memory virtual file map, never the real filesystem.
  * SQL injection runs against an in-memory SQLite DB of fake rows.
  * Command injection returns *simulated* output; no OS command is ever run.
It refuses to bind anything but localhost, and prints a loud banner. Do not
modify it to execute real commands or read real files, and never expose it.
"""
from __future__ import annotations

import base64
import html
import http.server
import socketserver
import sqlite3
import sys
from urllib.parse import parse_qs, quote

FLAG = "FLAG{{{}}}".format  # FLAG("x") -> "FLAG{x}" (matches RED-AI's flag detector)

# --- challenge manifest (also drives the learning index page) ----------------
CHALLENGES = [
    ("Content discovery", "/backup/flag.txt", "easy",
     "A flag file left at a guessable path. Brute-force common names.", True),
    ("Robots breadcrumb", "/s3cr3t-admin/", "easy",
     "robots.txt names a path it hoped you would not visit.", True),
    ("Secrets exposure", "/.env", "easy",
     "An environment file served to the web leaks a token.", True),
    ("Directory listing", "/uploads/", "easy",
     "The uploads folder lists its contents; open notes.txt.", False),
    ("Local file inclusion", "/view?file=welcome.txt", "medium",
     "The viewer takes a path. Try ../../flag or /etc/passwd.", True),
    ("SQL injection", "/product?id=1", "medium",
     "id goes into a query unquoted. Try  1' UNION SELECT flag,'' FROM secret--", True),
    ("Hidden dashboard", "/internal", "easy",
     "Not linked and not in robots — found by checking common paths.", True),
    ("Default credentials", "/admin", "medium",
     "HTTP Basic auth. Try the classic admin:admin.", True),
    ("Command injection", "/ping?host=127.0.0.1", "medium",
     "host is passed to a shell. Try  127.0.0.1; cat flag", True),
    ("Reflected XSS", "/search?q=hello", "medium",
     "q is reflected unescaped. Try  <script>alert(1)</script>", False),
    ("IDOR / broken access", "/api/user?id=2", "medium",
     "Change id. Low ids or 1337 belong to someone more privileged.", False),
    ("Weak session cookie", "/account", "hard",
     "The session cookie is just base64 of role=guest. Tamper it to admin.", False),
]

# --- sandboxed backends ------------------------------------------------------
_VFS = {  # virtual filesystem for the LFI challenge (never touches real disk)
    "welcome.txt": "Welcome to the document viewer.",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nbee:x:1000:1000::/home/bee:/bin/sh",
    "../../flag": FLAG("lfi_path_traversal"),
    "....//....//flag": FLAG("lfi_path_traversal"),
    "/etc/flag": FLAG("lfi_path_traversal"),
}

def _db() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE products(id INTEGER, name TEXT, price TEXT)")
    c.executemany("INSERT INTO products VALUES(?,?,?)",
                  [(1, "Blue Widget", "9.99"), (2, "Red Gadget", "14.50")])
    c.execute("CREATE TABLE secret(flag TEXT, note TEXT)")
    c.execute("INSERT INTO secret VALUES(?,?)", (FLAG("sqli_union_select"), "do not ship"))
    return c

_USERS = {  # IDOR backend
    "1": {"user": "guest", "role": "user", "note": "your own account"},
    "2": {"user": "alice", "role": "user", "note": "someone else's account (IDOR)"},
    "0": {"user": "root", "role": "admin", "note": FLAG("idor_broken_access")},
    "1337": {"user": "admin", "role": "admin", "note": FLAG("idor_broken_access")},
}
_ADMIN_BASIC = "Basic " + base64.b64encode(b"admin:admin").decode()


def _page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html><head><title>{title}</title>"
            "<style>body{font-family:system-ui;max-width:820px;margin:2rem auto;"
            "padding:0 1rem;background:#0d1117;color:#e6edf3}a{color:#58a6ff}"
            "code{background:#161b22;padding:2px 5px;border-radius:4px}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #30363d;"
            "padding:6px 10px;text-align:left}.t{color:#3fb950}.f{color:#e3b341}</style>"
            f"</head><body>{body}</body></html>").encode()


def _index() -> bytes:
    rows = "".join(
        f"<tr><td>{html.escape(name)}</td>"
        f"<td><a href='{html.escape(path)}'><code>{html.escape(path)}</code></a></td>"
        f"<td>{diff}</td>"
        f"<td>{'<span class=t>auto</span>' if auto else '<span class=f>manual</span>'}</td>"
        f"<td>{html.escape(hint)}</td></tr>"
        for name, path, diff, hint, auto in CHALLENGES)
    return _page("RED-AI Practice Range", f"""
      <h1>RED-AI Practice Range</h1>
      <p><b style='color:#f85149'>INTENTIONALLY VULNERABLE — localhost only — fabricated data.</b>
      This target is yours to attack. Flags look like <code>RED-AI{{...}}</code>.</p>
      <p>The <span class='t'>auto</span> column marks bugs RED-AI's engine can
      capture on its own today; <span class='f'>manual</span> ones you drive by
      hand (and are on the roadmap).</p>
      <table><tr><th>Class</th><th>Entry point</th><th>Level</th><th>RED-AI</th><th>Hint</th></tr>
      {rows}</table>
      <p style='margin-top:1.5rem'>Attack it all at once:
      <code>python -m red_ai engage --target http://127.0.0.1:PORT --operator me --audit</code></p>""")


def respond(path: str, query: str, headers) -> "tuple[int, dict, bytes]":
    q = parse_qs(query)
    H = {"Content-Type": "text/html; charset=utf-8"}
    T = {"Content-Type": "text/plain; charset=utf-8"}

    if path == "/":
        return 200, H, _index()
    if path == "/robots.txt":
        return 200, T, b"User-agent: *\nDisallow: /s3cr3t-admin/\nDisallow: /backup/\n"
    if path == "/backup/flag.txt":                       # content discovery
        return 200, T, (FLAG("exposed_backup_file") + "\n").encode()
    if path == "/.env":                                  # secrets exposure
        return 200, T, (f"APP_ENV=prod\nDB_USER=bee\nDB_PASS=honey\n"
                        f"API_TOKEN={FLAG('dotenv_secret_leak')}\n").encode()
    if path.rstrip("/") == "/uploads":                   # directory listing
        return 200, H, _page("Index of /uploads", "<h1>Index of /uploads</h1><ul>"
                             "<li><a href='/uploads/logo.png'>logo.png</a></li>"
                             "<li><a href='/uploads/notes.txt'>notes.txt</a></li></ul>")
    if path == "/uploads/notes.txt":
        return 200, T, (f"internal notes — rotate creds\n{FLAG('directory_listing')}\n").encode()
    if path.rstrip("/") == "/s3cr3t-admin":              # robots breadcrumb
        return 200, H, _page("hidden admin",
                             f"<h1>Hidden admin</h1><p>You found it. {FLAG('robots_breadcrumb')}</p>")
    if path == "/internal":                              # discovered via common-paths wordlist
        return 200, H, _page("internal",
                             f"<h1>Internal dashboard</h1><p>{FLAG('hidden_internal_dashboard')}</p>")

    if path == "/view":                                  # LFI (sandboxed VFS)
        f = (q.get("file") or [""])[0]
        if f in _VFS:
            return 200, T, (_VFS[f] + "\n").encode()
        return 404, T, b"file not found\n"

    if path == "/product":                               # SQL injection (simulated)
        raw = (q.get("id") or ["1"])[0]
        low = raw.lower()
        if ("union" in low and "select" in low) or "or 1=1" in low or "or '1'='1" in low or "'--" in low:
            return 200, H, _page("product", f"<h1>Catalog</h1><p>secret row: {FLAG('sqli_union_select')}</p>")
        try:  # normal lookups use a parameterized query against fabricated rows
            rows = _db().execute("SELECT name,price FROM products WHERE id = ?", (raw,)).fetchall()
            body = "".join(f"<tr><td>{html.escape(str(a))}</td><td>{html.escape(str(b))}</td></tr>"
                           for a, b in rows) or "<tr><td colspan=2>no such product</td></tr>"
            return 200, H, _page("product", f"<h1>Product {html.escape(raw)}</h1><table>{body}</table>")
        except sqlite3.Error as e:
            return 200, H, _page("sql error", f"<h1>DB error</h1><code>{html.escape(str(e))}</code>")

    if path == "/admin":                                 # default creds (HTTP Basic)
        if headers.get("Authorization") == _ADMIN_BASIC:
            return 200, H, _page("admin", f"<h1>Admin console</h1><p>{FLAG('default_credentials')}</p>")
        return 401, {**H, "WWW-Authenticate": 'Basic realm="admin"'}, _page("401", "<h1>401 — auth required</h1>")

    if path == "/ping":                                  # command injection (SIMULATED)
        host = (q.get("host") or [""])[0]
        if any(c in host for c in (";", "&&", "||", "|", "$(", "`")):   # chained command
            return 200, T, (f"PING {host}\n{FLAG('command_injection')}\n").encode()  # no real shell is run
        if host:
            return 200, T, (f"PING {html.escape(host)}: 64 bytes, time=0.1 ms\n").encode()
        return 200, T, b"usage: ?host=\n"

    if path == "/search":                                # reflected XSS (harmless, localhost)
        term = (q.get("q") or [""])[0]
        note = f"<!-- {FLAG('reflected_xss')} -->" if "<script" in term.lower() else ""
        return 200, H, _page("search", f"<h1>Results for: {term}</h1><p>no matches</p>{note}")

    if path == "/api/user":                              # IDOR
        uid = (q.get("id") or ["1"])[0]
        import json
        u = _USERS.get(uid)
        if u:
            return 200, {"Content-Type": "application/json"}, json.dumps(u).encode()
        return 404, T, b"no such user\n"

    if path == "/account":                               # weak session cookie
        cookie = headers.get("Cookie", "")
        role = "guest"
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                try:
                    role = base64.b64decode(part.split("=", 1)[1]).decode().split("=", 1)[-1]
                except Exception:
                    pass
        body = f"<h1>Account</h1><p>role = <code>{html.escape(role)}</code></p>"
        if role == "admin":
            body += f"<p>{FLAG('cookie_tampering_weak_session')}</p>"
        else:
            body += ("<p>Set-Cookie not admin. The cookie is just "
                     "<code>base64('role=guest')</code> — tamper it.</p>")
        default = base64.b64encode(b"role=guest").decode()
        return 200, {**H, "Set-Cookie": f"session={default}"}, _page("account", body)

    return 404, T, b"not found\n"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        path, _, query = self.path.partition("?")
        code, hdrs, body = respond(path, query, self.headers)
        self.send_response(code)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    port = int(argv[0]) if argv else 5000
    host = "127.0.0.1"  # localhost ONLY — this app is intentionally vulnerable
    print("=" * 64)
    print("  RED-AI Practice Range — INTENTIONALLY VULNERABLE (localhost only)")
    print(f"  Browse / attack:  http://{host}:{port}")
    print(f"  {len(CHALLENGES)} challenges. Flags look like RED-AI{{...}}. Ctrl-C to stop.")
    print("=" * 64)
    _Server((host, port), _Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
