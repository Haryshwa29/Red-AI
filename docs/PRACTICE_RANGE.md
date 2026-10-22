# RED-AI Practice Range — your own legal target

A deliberately-vulnerable website you run locally. Because it is on your machine,
binds to `127.0.0.1` only, and holds only fabricated data, attacking it is
unambiguously legal — no third-party authorization needed.

## Run it
```
python -m redai_range.site           # http://127.0.0.1:5000
```
or double-click `launchers/VULN-SITE.bat` (Windows) / `.command` (macOS) / `.sh` (Linux).
Open the URL — the home page lists every challenge, its entry point, difficulty,
and whether RED-AI can capture it automatically today.

## Attack it with RED-AI
```
python -m red_ai operator add me
python -m red_ai engage --target http://127.0.0.1:5000 --operator me --audit
```
RED-AI captures 8 flags automatically (content discovery, exposed secrets,
robots breadcrumb, hidden dashboard, default creds, LFI, SQLi, command injection).

## Challenges
| Class | Entry point | RED-AI today |
|-------|-------------|--------------|
| Content discovery (exposed flag file) | `/backup/flag.txt` (via robots) | auto |
| Secrets exposure | `/.env` | auto |
| Robots breadcrumb | `/s3cr3t-admin/` | auto |
| Hidden dashboard | `/internal` | auto |
| Default credentials | `/admin` (admin:admin) | auto |
| Local file inclusion | `/view?file=../../flag` | auto |
| SQL injection | `/product?id=1' UNION SELECT flag,'' FROM secret--` | auto |
| Command injection | `/ping?host=127.0.0.1; cat flag` | auto |
| Directory listing | `/uploads/` → `notes.txt` | manual |
| Reflected XSS | `/search?q=<script>alert(1)</script>` | manual (roadmap) |
| IDOR / broken access | `/api/user?id=1337` | manual (roadmap) |
| Weak session cookie | `/account` (base64 `role=guest`) | manual (roadmap) |

## Safety
Every dangerous primitive is sandboxed: LFI reads an in-memory virtual file map,
SQLi runs against fabricated rows, command injection returns *simulated* output
(no OS command is ever run). It refuses to bind anything but localhost. Do not
modify it to touch the real filesystem/shell, and never expose it to a network.
