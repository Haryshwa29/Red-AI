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

    findings, leads, paths = [], [], []
    if status:  # only probe paths if the root answered like a web server
        for path, meaning, sev in COMMON_PATHS:
            st, _h, _b = _get(base, path, opener, timeout_s)
            if st not in (200, 301, 302, 401, 403):
                continue
            entry = {"path": path, "status": st, "meaning": meaning}
            paths.append(entry)
            if sev is not None and st == 200:
                findings.append({**entry, "severity": sev.value, "severity_rank": sev.rank})
            elif path in _LEAD_PATHS and st in (200, 301, 302, 401):
                leads.append(entry)
    findings.sort(key=lambda f: -f["severity_rank"])
    return {"root": root, "paths": paths, "findings": findings, "leads": leads}
