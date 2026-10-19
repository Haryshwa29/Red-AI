"""
Web enumeration for the recon engine (opt-in, read-only HTTP GETs).

After a web port is open, this maps the surface a pentester checks first: the
root response (status / title / Server header) and a short, stated list of common
paths (version-control or secret exposure, status/info endpoints, backup
archives, admin/login/API surface). Every request is a plain GET -- no
parameters, no payloads, no mutation, no auth attempts, and no crawling beyond
the stated list. An exposed secret/VCS/backup at 200 is a FINDING (derived
severity from the stated table); an admin/login/API surface is a human-routed
LEAD, never a confirmed breach.

Opt-in via ReconScope.enumerate_web (default False). stdlib urllib only; the only
egress is the authorized target. Never raises.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Callable, Optional

from red_ai.contracts.domain import Severity

# Injectable for hermetic tests: (url, timeout_s) -> (status, headers, body)
WebOpener = Callable[[str, float], "tuple[int, dict, bytes]"]

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_LEAD_PATHS = {"/admin", "/login", "/api", "/swagger.json"}

# (path, meaning, severity-if-200 or None -> treated as a lead for _LEAD_PATHS)
COMMON_PATHS = [
    ("/robots.txt",    "robots file may disclose hidden paths", None),
    ("/.git/HEAD",     "exposed Git repository (source/secret disclosure)", Severity.CRITICAL),
    ("/.env",          "exposed environment file (credentials/secrets)", Severity.CRITICAL),
    ("/.svn/entries",  "exposed SVN metadata (source disclosure)", Severity.HIGH),
    ("/server-status", "Apache mod_status exposed (internal info)", Severity.HIGH),
    ("/phpinfo.php",   "phpinfo exposed (environment disclosure)", Severity.HIGH),
    ("/backup.zip",    "backup archive exposed", Severity.HIGH),
    ("/backup.sql",    "database dump exposed", Severity.HIGH),
    ("/admin",         "admin panel", None),
    ("/login",         "login panel", None),
    ("/api",           "API surface", None),
    ("/swagger.json",  "API schema exposed (surface enumeration)", None),
]


def _urllib_opener(url: str, timeout_s: float):
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "RED-AI-recon/1.0", "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:  # noqa: S310
            return getattr(r, "status", 200) or 200, dict(r.headers), r.read(65536)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096)
        except Exception:
            body = b""
        return e.code, dict(getattr(e, "headers", {}) or {}), body
    except Exception:
        return 0, {}, b""


_ROBOTS_LINE = re.compile(rb"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)")
_HREF = re.compile(rb"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
_MAX_LINKS = 40


def _extract_params(body: bytes, host: str) -> "list[dict]":
    """Same-origin parameterized endpoints linked from a page (path + param + sample).

    A link like `/view?file=welcome.txt` tells us there is an injectable input
    `file` on `/view`. Recorded as recon knowledge and fed to the injection
    modules, which decide which payloads to try -- discovery stays recon's job,
    exploitation the module's. Bounded, one level, deterministic."""
    from urllib.parse import urlparse, parse_qsl
    out: list[dict] = []
    seen: set[str] = set()
    for raw in _HREF.findall(body or b""):
        u = raw.decode("utf-8", "replace").strip()
        if "?" not in u or u[0] == "#":
            continue
        if u.lower().startswith(("http://", "https://")):
            pr = urlparse(u)
            if pr.hostname != host:
                continue
            path, qs = pr.path, pr.query
        else:
            path, _, qs = u.partition("?")
            if not path.startswith("/"):
                path = "/" + path
        for k, v in parse_qsl(qs):
            key = f"{path}?{k}"
            if k and key not in seen:
                seen.add(key)
                out.append({"path": path, "param": k, "sample": v})
            if len(out) >= _MAX_LINKS:
                return out
    return out


def _extract_links(body: bytes, host: str) -> "list[dict]":
    """Same-origin paths linked from a page body (one level, bounded).

    Classic spidering: the homepage links to pages a wordlist and robots.txt miss.
    Deterministic extraction of what the server itself published -- recon
    knowledge, fed to the exploit engine as candidate paths, never a finding. One
    level only (no recursive crawl); capped so it cannot sprawl."""
    out: list[dict] = []
    seen: set[str] = set()
    for raw in _HREF.findall(body or b""):
        u = raw.decode("utf-8", "replace").strip()
        if not u or u[0] in "#?" or u.lower().startswith(("mailto:", "javascript:", "tel:", "data:")):
            continue
        if u.lower().startswith(("http://", "https://")):
            from urllib.parse import urlparse
            pr = urlparse(u)
            if pr.hostname != host:        # stay same-origin
                continue
            path = pr.path or "/"
        elif u.startswith("/"):
            path = u
        else:
            path = "/" + u                 # relative to root (one level)
        path = path.split("?")[0].split("#")[0]
        if path and path != "/" and path not in seen:
            seen.add(path)
            out.append({"path": path, "meaning": "linked from homepage"})
        if len(out) >= _MAX_LINKS:
            break
    return out


def _parse_robots(body: bytes) -> "list[dict]":
    """Extract Disallow/Allow paths from a robots.txt body.

    robots.txt routinely names exactly the paths an owner wants hidden -- the
    first place a pentester looks. These are recon-established knowledge (the
    server disclosed them), fed to the exploit engine as candidate paths; they
    are not themselves a finding."""
    out: list[dict] = []
    seen: set[str] = set()
    for m in _ROBOTS_LINE.findall(body or b""):
        p = m.decode("utf-8", "replace").strip()
        if not p.startswith("/") or p in seen or p == "/":
            continue
        seen.add(p)
        out.append({"path": p, "meaning": "path disclosed by robots.txt"})
    return out


def _get(base: str, path: str, opener: WebOpener, timeout_s: float):
    try:
        return opener(base + path, timeout_s)
    except Exception:
        return 0, {}, b""


def enumerate_web(host: str, port: int, scheme: str = "http",
                  opener: Optional[WebOpener] = None, timeout_ms: int = 4000) -> dict:
    """Read-only web surface map for one host:port. Never raises."""
    opener = opener or _urllib_opener
    base = f"{scheme}://{host}:{port}"
    timeout_s = timeout_ms / 1000.0

    status, headers, body = _get(base, "/", opener, timeout_s)
    title = None
    m = _TITLE.search(body or b"")
    if m:
        title = m.group(1).decode("utf-8", "replace").strip()[:120]
    root = {"status": status, "server": headers.get("Server"), "title": title}
    linked = _extract_links(body, host) if status else []   # same-origin homepage links
    params = _extract_params(body, host) if status else []  # parameterized endpoints

    findings, leads, paths = [], [], []
    disclosed: list[dict] = []   # paths named inside robots.txt (recon knowledge, not a finding)
    if status:  # only probe paths if the root answered like a web server
        for path, meaning, sev in COMMON_PATHS:
            st, _h, body_p = _get(base, path, opener, timeout_s)
            if st not in (200, 301, 302, 401, 403):
                continue
            entry = {"path": path, "status": st, "meaning": meaning}
            paths.append(entry)
            if sev is not None and st == 200:
                findings.append({**entry, "severity": sev.value, "severity_rank": sev.rank})
            elif path in _LEAD_PATHS and st in (200, 301, 302, 401):
                leads.append(entry)
            if path == "/robots.txt" and st == 200:
                disclosed.extend(_parse_robots(body_p))
    findings.sort(key=lambda f: -f["severity_rank"])
    return {"root": root, "paths": paths, "findings": findings,
            "leads": leads, "disclosed": disclosed, "linked": linked, "params": params}
