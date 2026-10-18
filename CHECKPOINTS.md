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

**Acceptance criterion:** a real run, on the VPN, that the Claude bridge VM
cannot perform — only the operator can close this, because the lab network is
reachable only from their machine. This is the checkpoint that converts
"built and lab-proven" into "works in the wild."

**Minimum to attempt:**
```
python -m red_ai.recon init --host <box-ip> --ports 1-1000 \
    --attest "THM authorized lab" --env authorized_lab --identify --web
python -m red_ai.recon scan --scope data/recon/<id>.scope.json --verbose
```
(Exploit/flag capture on a real box follows once a surface + a declared flag are
in scope.)

---

## Checkpoint 3 — Toward bug-bounty  ·  FUTURE

A broader native exploit-module set (auth bypass, known-CVE, injection), web-app
depth, and validated tool-parity adapters (nmap/Burp/msf) — each a gated,
separately-reviewed module behind the shipped exploit interface, each validated
on a real box before it is called "ready".
