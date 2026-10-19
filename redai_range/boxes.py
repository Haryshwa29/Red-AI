"""RED-AI capability range: a graded ladder of deliberately-vulnerable targets.

These are TEST FIXTURES for measuring our OWN engine -- the offline analogue of
pointing RED-AI at progressively harder TryHackMe boxes, so we can see exactly
which rung it clears and where it breaks. Each box is a minimal, stdlib-only HTTP
server modeled on a real THM web archetype, tagged with:

  * difficulty   -- 1..N, monotonically harder
  * archetype    -- the real-world shape it imitates
  * capability   -- what an engine MUST be able to do to capture its flag
  * expect_capture -- our honest prediction for RED-AI *today* (the hypothesis
                      the harness tests; a surprise either way is a finding)
  * solution     -- the request an operator with that capability would send,
                    used by the self-consistency test to prove the box is
                    actually solvable (so a broken fixture never reads as a
                    RED-AI failure)

The flag everywhere is the THM{...} form, so the shipped pattern-capture applies
whenever the engine can REACH it. Difficulty is about reachability, not the flag.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Callable


# A handler: (path, query, headers) -> (status, headers_dict, body_bytes)
Responder = Callable[[str, dict, dict], "tuple[int, dict, bytes]"]


@dataclass(frozen=True)
class Solution:
    """How the intended capability reaches the flag (for the self-consistency test)."""
    path: str
    query: str = ""
    headers: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Box:
    id: str
    name: str
    difficulty: int
    archetype: str
    capability: str
    expect_capture: bool
    flag: str
    respond: Responder
    solution: Solution


def _html(body: str) -> bytes:
    return f"<html><body>{body}</body></html>".encode()


# --------------------------------------------------------------------------- #
# L1 -- exposed flag file at a guessable path (easiest THM shape)
# --------------------------------------------------------------------------- #
_L1_FLAG = "THM{l1_exposed_flag_file}"
def _l1(path, query, headers):
    if path == "/flag.txt":
        return 200, {"Content-Type": "text/plain"}, (_L1_FLAG + "\n").encode()
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html("Welcome")
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L2 -- flag behind a CUSTOM dir named only in robots.txt
# --------------------------------------------------------------------------- #
_L2_FLAG = "THM{l2_robots_breadcrumb}"
def _l2(path, query, headers):
    if path == "/robots.txt":
        return 200, {"Content-Type": "text/plain"}, b"User-agent: *\nDisallow: /qz7-ops-area/\n"
    if path == "/qz7-ops-area/flag.txt":
        return 200, {"Content-Type": "text/plain"}, (_L2_FLAG + "\n").encode()
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html("Home")
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L3 -- flag leaked INSIDE an exposed secrets file (not a flag-named file)
# --------------------------------------------------------------------------- #
_L3_FLAG = "THM{l3_dotenv_secret_leak}"
def _l3(path, query, headers):
    if path == "/.env":
        body = f"APP_ENV=prod\nDB_PASS=s3cr3t\nBACKUP_TOKEN={_L3_FLAG}\n".encode()
        return 200, {"Content-Type": "text/plain"}, body
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html("Corp site")
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L4 -- flag reachable ONLY by following an HTML link (needs crawling)
# not in robots, not in the wordlist; the path is random and only linked
# --------------------------------------------------------------------------- #
_L4_FLAG = "THM{l4_follow_the_link}"
def _l4(path, query, headers):
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html(
            'See our <a href="/n4k8-internal/notes.txt">internal notes</a>.')
    if path == "/n4k8-internal/notes.txt":
        return 200, {"Content-Type": "text/plain"}, (f"meeting notes...\n{_L4_FLAG}\n").encode()
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L5 -- flag behind HTTP Basic auth with default creds (needs credential access)
# --------------------------------------------------------------------------- #
_L5_FLAG = "THM{l5_default_creds_admin}"
_L5_OK = "Basic " + base64.b64encode(b"admin:admin").decode()
def _l5(path, query, headers):
    if path == "/flag.txt":
        auth = headers.get("Authorization", "")
        if auth == _L5_OK:
            return 200, {"Content-Type": "text/plain"}, (_L5_FLAG + "\n").encode()
        return 401, {"WWW-Authenticate": 'Basic realm="admin"'}, b"Unauthorized"
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html("Admin portal")
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L6 -- local file inclusion / path traversal via a query parameter
# --------------------------------------------------------------------------- #
_L6_FLAG = "THM{l6_lfi_path_traversal}"
_L6_FILES = {"welcome.txt": "Welcome to the viewer.", "../../flag": _L6_FLAG,
             "....//....//flag": _L6_FLAG}
def _l6(path, query, headers):
    if path == "/view":
        import urllib.parse as up
        f = up.parse_qs(query).get("file", [""])[0]
        if f in _L6_FILES:
            return 200, {"Content-Type": "text/plain"}, (_L6_FILES[f] + "\n").encode()
        return 200, {"Content-Type": "text/plain"}, b"no such file\n"
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html(
            'Document viewer: <a href="/view?file=welcome.txt">welcome</a>')
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L7 -- SQL injection: the flag is a hidden DB row, reachable via UNION/bypass
# --------------------------------------------------------------------------- #
_L7_FLAG = "THM{l7_sqli_union_select}"
def _l7(path, query, headers):
    if path == "/item":
        import urllib.parse as up
        raw = up.parse_qs(query).get("id", [""])[0]
        # a trivial "injectable" stand-in: a classic tautology or UNION leaks the secret row
        low = raw.lower()
        if ("union" in low and "select" in low) or ("or 1=1" in low) or ("or '1'='1" in low):
            return 200, {"Content-Type": "text/plain"}, (f"id={raw} -> secret: {_L7_FLAG}\n").encode()
        if raw.isdigit():
            return 200, {"Content-Type": "text/plain"}, (f"id={raw} -> widget #{raw}\n").encode()
        return 200, {"Content-Type": "text/plain"}, b"invalid id\n"
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html(
            'Catalog: <a href="/item?id=1">item 1</a>')
    return 404, {}, b"Not Found"


# --------------------------------------------------------------------------- #
# L8 -- command injection / RCE via a parameter
# --------------------------------------------------------------------------- #
_L8_FLAG = "THM{l8_command_injection_rce}"
def _l8(path, query, headers):
    if path == "/ping":
        import urllib.parse as up
        host = up.parse_qs(query).get("host", [""])[0]
        if ";" in host or "&&" in host or "|" in host or "$(" in host or "`" in host:
            # injected command "reads" the flag file
            return 200, {"Content-Type": "text/plain"}, (f"PING {host}\n{_L8_FLAG}\n").encode()
        if host:
            return 200, {"Content-Type": "text/plain"}, (f"PING {host}: 64 bytes, time=0.1ms\n").encode()
        return 200, {"Content-Type": "text/plain"}, b"usage: ?host=\n"
    if path == "/":
        return 200, {"Content-Type": "text/html"}, _html(
            'Network tools: <a href="/ping?host=127.0.0.1">ping</a>')
    return 404, {}, b"Not Found"


BOXES: tuple[Box, ...] = (
    Box("L1", "exposed-flag-file", 1, "exposed file at a guessable path",
        "path read (wordlist)", True, _L1_FLAG, _l1,
        Solution("/flag.txt")),
    Box("L2", "robots-breadcrumb", 2, "custom dir disclosed in robots.txt",
        "robots follow", True, _L2_FLAG, _l2,
        Solution("/qz7-ops-area/flag.txt")),
    Box("L3", "dotenv-secret-leak", 3, "flag leaked inside an exposed .env",
        "exposed secret-file body scan", True, _L3_FLAG, _l3,
        Solution("/.env")),
    Box("L4", "html-link-crawl", 4, "flag only reachable via an HTML link",
        "HTML link extraction / crawling", True, _L4_FLAG, _l4,
        Solution("/n4k8-internal/notes.txt")),
    Box("L5", "basic-auth-default-creds", 5, "flag behind HTTP Basic auth (admin:admin)",
        "credential access / auth", True, _L5_FLAG, _l5,
        Solution("/flag.txt", headers={"Authorization": _L5_OK})),
    Box("L6", "lfi-path-traversal", 6, "flag via local file inclusion on ?file=",
        "LFI / path-traversal injection", True, _L6_FLAG, _l6,
        Solution("/view", query="file=../../flag")),
    Box("L7", "sqli-union", 7, "flag is a hidden DB row via SQL injection",
        "SQL injection", True, _L7_FLAG, _l7,
        Solution("/item", query="id=1 UNION SELECT flag")),
    Box("L8", "command-injection-rce", 8, "flag via command injection on ?host=",
        "command injection / RCE", True, _L8_FLAG, _l8,
        Solution("/ping", query="host=127.0.0.1;cat flag")),
)
