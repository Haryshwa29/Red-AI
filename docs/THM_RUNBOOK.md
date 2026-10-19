# RED-AI — Live Engagement Runbook (TryHackMe / HackTheBox)

How to point RED-AI at a live lab box and capture the flag, with every action
gated and every step recorded as verifiable evidence. This is the operator path
toward **Checkpoint 2** (first confirmed capture on a live range box).

---

## What RED-AI can capture today — honestly

RED-AI ships one live-capture capability right now: **discovery-driven web flag
capture.** Given an authorized web surface it will:

1. **Recon** the target — TCP connect scan, service/version identification, and
   read-only web enumeration (root fingerprint, common exposure paths, and
   `robots.txt` `Disallow` breadcrumbs).
2. **Bridge** what recon proved into exploit inputs — open web surfaces plus the
   paths recon disclosed (never raw page text; the trust split holds).
3. **Hunt the flag** — issue a single non-destructive `GET` per candidate path
   (recon-disclosed paths first, then a bounded flag-file wordlist) and scan each
   response for the flag **form** you declared (`THM{…}`, `flag{…}`, `HTB{…}`, or
   a 32-hex). The controller re-checks and re-runs the capture to report a
   measured reproduction rate.

**This solves the common web-box shapes**: a flag exposed at a guessable or
`robots`-disclosed path, in an exposed `.env`/`.git`, on a page reachable by
following a homepage link, behind HTTP Basic auth that accepts **default
credentials** (`admin:admin`), or reachable through a **single-step injection** on
a discovered parameter — **LFI / path traversal, SQL injection, or command
injection** (bounded, read-only payloads that prove the flaw and read the flag).

**It does NOT yet do** (each a planned, separately-gated module — not a silent
gap): SSH/FTP brute force and password spray with lockout awareness, form-login /
token auth, **blind / time-based** SQLi or injection, second-order injection,
file-upload bypass, interactive RCE / reverse shells, multi-step chains, and
privilege escalation (`user.txt` → `root.txt`); plus non-web services. If a box
needs those to reach the flag, RED-AI will recon and probe it, report what it
found, and stop at `no_breach` — honest signal ("not broken in N steps"), never
"secure".

> **Pick boxes accordingly for Checkpoint 2.** Target TryHackMe rooms whose flag
> is reachable over HTTP without an exploit chain (exposed files, `robots.txt`
> breadcrumbs, misconfig disclosure). Those are exactly what the shipped
> capability is built to prove.

---

## The one hard requirement: a route to the box

RED-AI runs **where it can reach the target**. THM/HTB give you an OpenVPN
profile and a `10.x`/`10.10.x` address. **You must run RED-AI from a machine
connected to that VPN** — RED-AI has no part in the tunnel, and it cannot reach a
lab box from a cloud sandbox. There is no workaround inside RED-AI for this; it
is the operator's network, by design.

```bash
sudo openvpn /path/to/your-thm.ovpn      # in one terminal; leave it running
ip addr show tun0                        # confirm you have a 10.x address
ping -c1 <TARGET_IP>                      # confirm the box is reachable
```

---

## One-time setup

```bash
cd RED-AI
python -m red_ai operator add <your-handle>     # creates your per-operator key
```

(Every engagement is tied to an operator identity and an owner attestation, both
recorded in the evidence.)

---

## Run the engagement

```bash
python -m red_ai engage \
    --target <TARGET_IP> \
    --ports 80,8080,8000,8888,443 \
    --operator <your-handle>
```

> **Prefer a visual, learn-as-you-go view?** Run the local web console instead —
> same pipeline, a stage-by-stage timeline and an annotated live feed:
> `python -m red_ai web` → http://127.0.0.1:8787 (localhost only). See
> [`WEB_UI.md`](WEB_UI.md).

You will see a live, timestamped stream of exactly what it does:

```
[hh:mm:ss] [engage] target=10.10.x.x ports=... env=authorized_lab operator=you
[hh:mm:ss] [recon]   PROBE 10.10.x.x:80 -> open
[hh:mm:ss] [recon]   WEB  10.10.x.x:80 root=200 server=Apache/2.4.x title='...'
[hh:mm:ss] [recon]     EXPOSED /.env (200) sev=critical - ...
[hh:mm:ss] [exploit] surface 10.10.x.x:80 (HTTP)
[hh:mm:ss] [exploit]     GET /robots.txt -> no_effect
[hh:mm:ss] [exploit]     GET /<disclosed-dir>/flag.txt -> ★ FLAG
[hh:mm:ss] [exploit]     ✔ CONFIRMED flag=THM{...} reproduced=100%

RED-AI: FLAG CAPTURED on 10.10.x.x  ->  THM{...}
    reproduced: 100%  ·  steps: N
    recon evidence:   data/runs/<ts>-engage-recon
    exploit evidence: data/runs/<ts>-engage-exploit
    verify:  python -m red_ai verify data/runs/<ts>-engage-exploit
```

### Useful flags

| Flag | Purpose |
|---|---|
| `--ports` | Ports to recon (default common web ports). Add the box's web port if unusual (e.g. `--ports 80,3000`). |
| `--flag-pattern` | Regex for the flag **form**. Default matches `THM{…}`/`flag{…}`/`HTB{…}`/32-hex. Override for a room-specific shape. |
| `--max-steps`, `--max-seconds` | Budgets; the gate halts the engagement when either is exhausted. |
| `--env` | `authorized_lab` (default), `owned`, or `production` (the last also needs `--allow-production`). |
| `--quiet` | Suppress the live stream (evidence is still written). |

---

## The evidence (this is the point)

Every run writes a hash-linked `events.jsonl` under `data/runs/<ts>-engage-*`:

- **Recon** run: every probe, web-enum result, finding, and reproduction.
- **Exploit** run: routing, **every gate decision**, every step with its raw
  observation, the capture verification, and the final confirmed finding
  carrying the exact flag value.

Verify the chain and regenerate a report:

```bash
python -m red_ai verify data/runs/<ts>-engage-exploit     # confirms tamper-evident order
python -m red_ai report data/runs/<ts>-engage-exploit     # report.md + report.html
```

To screen-record the capture for a writeup/bug-bounty submission, just record the
terminal during `engage` — the timestamped stream is designed to be legible on
screen, and the evidence directory is your reproducible proof.

---

## Why it's built this way (the guarantees still hold live)

- **Every step is gated before it touches the box.** The exploit gate authorizes
  each `GET` against the signed engagement scope; a step outside scope is denied
  and recorded, never run.
- **Non-destructive by construction.** The shipped module only issues plain
  `GET`s — no payloads, no mutation, no auth attempts. `action_tier=active_safe`.
- **Discovery drives exploitation, target text does not.** Candidate paths come
  only from recon-established knowledge (disclosed/exposed paths), never from a
  live page body read mid-run — the same trust split the LLM engine enforces.
- **Capture is binary and reproduced.** A flag is asserted only when the
  controller's deterministic checker matches the declared form **and** a re-run
  reproduces it; the report states the measured rate, never a promise.
- **The brain is not involved.** Flag capture is pure deterministic capability;
  a refusing or absent model changes nothing here.

---

## Current limits (stated, not hidden)

- Web flag capture only (see the "does NOT yet do" list above).
- Odd web ports are detected from an actual web response, so list the box's web
  port in `--ports` if it isn't a common one.
- RED-AI does not establish the VPN, solve multi-step exploit chains, or perform
  privilege escalation. Those are the next rungs, each a separately-gated module.
