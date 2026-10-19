# RED-AI Checkpoints

A checkpoint is a stated, evidence-anchored milestone: what is true, how it was
proven, and the honest boundary of what it does NOT yet claim. A capability is
only "confirmed" against a target it has actually run on.

---

## Checkpoint 1 — End-to-end pipeline, lab-proven  ·  REACHED 2026-10-18

**Claim:** RED-AI runs the full autonomous-pentester pipeline end to end on
controlled targets — recon → service/version ID → web-surface enumeration →
exploitation → flag capture — under signed authorization, with per-operator
auth, a deterministic gate, and a hash-linked, timestamped, reproducible
evidence trail.

**Proven by:**
- 157 offline unit tests (stdlib only, hermetic).
- Live loopback proofs on the machine (real sockets, not mocks):
  - recon fingerprinted `OpenSSH_7.6p1` and `vsFTPd 2.3.4` and raised the
    correct version exposure leads;
  - web enumeration found an exposed `/.git/HEAD` (CRITICAL) and an `/admin`
    lead against a real HTTP server;
  - the exploit engine captured a declared flag over real HTTP, reproduction
    rate 1.0, with a recorded breach path and a CRITICAL finding.
- Every run writes `events.jsonl` (ordered, per-event ISO/UTC timestamp,
  hash-linked) and is re-checkable with `verify`.

**Honest boundary (what this checkpoint does NOT claim):**
- Everything above was proven against **controlled / loopback** targets, never
  yet against a live TryHackMe / HackTheBox / EC-Council box.
- Exploit coverage today = one reference module (HTTP flag read) plus recon and
  web-enum leads. It is not yet a broad exploit library, and it does not yet do
  RCE, auth bypass, injection, or privilege escalation.
- "Find vulnerabilities" today means: enumerate exposures + surface
  version/exposure **leads** + capture exposed-file / path-authorized flags.

---

## Checkpoint 2 — First confirmed capture on a live range box  ·  NOT REACHED

**Claim to earn:** RED-AI, run on the operator's machine over the range VPN,
connects to one authorized easy TryHackMe/HTB box, enumerates its real services,
and (target permitting) captures the declared flag — producing the evidence
bundle (`events.jsonl` + `verify` + report).

**Acceptance criterion:** a real run, on the VPN, that no cloud sandbox can
perform — only the operator can close this, because the lab network is reachable
only from their machine. This is the checkpoint that converts "built and
lab-proven" into "works in the wild."

**Capability status — READY, awaiting the live run.** The capture path CP2 needs
is built and proven over **real sockets** (not mocks) against deliberately-
vulnerable local servers, and now measured by a graded capability range:
- a one-command `engage` flow: recon → recon→exploit bridge → gated exploit, with
  a live timestamped progress stream;
- a `pattern` flag kind that captures the flag **form** (`THM{…}`/`flag{…}`/
  `HTB{…}`/32-hex) with no pre-declared path — zero-false-positive, reproduced;
- a graded range (`python -m redai_range`) of 8 THM-archetype boxes, **all
  cleared L1–L8**: exposed file, robots breadcrumb, `.env` leak, HTML-link crawl,
  Basic-auth default creds, and the injection family (LFI, SQLi, command
  injection) — 0 false positives, 0 regressions;
- 180 offline tests (was 157), incl. every module, the matcher, the bridge, and a
  range rot-guard.

**To close it (operator, on VPN):**
```
python -m red_ai operator add <you>
python -m red_ai engage --target <box-ip> --ports 80,8080,8000,8888,443 --operator <you>
python -m red_ai verify data/runs/<ts>-engage-exploit
```
See **[docs/THM_RUNBOOK.md](docs/THM_RUNBOOK.md)** for the full procedure and the
honest scope, and **[docs/CAPABILITY_RANGE.md](docs/CAPABILITY_RANGE.md)** for the
capability map. The range is the floor of competence; the live box is the proof.

---

## Checkpoint 3 — Toward bug-bounty  ·  IN PROGRESS

Raise the ceiling above the L1–L8 single-step web range: password spray (lockout-
aware) and SSH/FTP brute, form/token auth, **blind / time-based** and second-order
injection, file-upload bypass, multi-step chains, and privilege escalation
(`user.txt` → `root.txt`); plus validated tool-parity adapters (nmap/Burp/msf).
Each a gated, separately-reviewed module behind the shipped exploit interface,
each encoded as a new range rung and validated on a real box before it is called
"ready".
