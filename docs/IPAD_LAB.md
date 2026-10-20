# Test case: assessing a wired lab device (e.g. a vulnerable iPad app)

A worked example of pointing RED-AI at a lab device on a wired link and
showcasing **all** the vulnerabilities it can find — the assessment use case,
not capture-the-flag.

## The one thing that must be true

RED-AI assesses what a device exposes **over the network**. So the vulnerable
software on the iPad must be a **network service** (a web app or HTTP/S API
listening on a port). RED-AI reaches it by IP and port; it does not touch iOS
internals, the app binary, or anything with no listener. If your lab app serves
HTTP(S), it is a perfect fit.

## 1. Put the iPad on a link your PC can reach

Wired is ideal (USB-Ethernet adapter, or both on the same switch). Then find the
iPad's IP and confirm your PC can reach it:

```bash
ping <ipad-ip>
# find its open port if you don't know it: a wide scan does it for you (below)
```

## 2. Launch the dashboard (clickable)

Double-click **`RED-AI-Dashboard.command`** (macOS), **`.sh`** (Linux), or
**`.bat`** (Windows) in the repo — it starts the server and opens your browser.
(Or `python -m red_ai web --open`.)

## 3. Run a full assessment

In the dashboard:

1. **Objective** — "Full vulnerability assessment of the lab iPad app".
2. **Target** — the iPad's IP.
3. **Ports** — `1-10000` (recon finds whatever port the app listens on).
4. Tick **I'm authorized** and **Audit (find all)**.
5. **Engage**, and watch.

Audit mode does not stop at the first flag — it enumerates every reachable
weakness. You will see, live:

- the **Operations log** — every request RED-AI sends (`GET http://ip/path`,
  injection payloads, `tcp-connect`, `tls-handshake`);
- the **Surface map** — open ports, services, discovered paths, parameters;
- **Module coverage** — which techniques fired and how often;
- a result banner listing **every confirmed vulnerability** with its location and
  evidence, and the **Where to improve** panel for anything it couldn't reach.

CLI equivalent:

```bash
python -m red_ai engage --target <ipad-ip> --ports 1-10000 --operator me --audit
```

## What it will find (and what it won't)

RED-AI confirms, with reproduced evidence, the web weakness classes it ships:
content discovery (hidden pages), exposed files / secrets, `robots.txt`
breadcrumbs, HTTP Basic **default credentials**, and the **injection family**
(LFI / path traversal, SQL injection, command injection), plus **TLS/crypto
posture** if the app serves HTTPS. If the app stores or transmits data with weak
crypto, paste samples into the **Crypto Audit** tab to recover the plaintext.

It will **not** (yet) do form-login/token auth, blind/second-order injection,
binary/memory bugs in the app, or anything requiring a device shell — the
dashboard's "Where to improve" panel names exactly which of these a given target
needed.

## Try it now without the iPad

A bundled showcase app reproduces a multi-vulnerability target so you can see the
full assessment before plugging anything in:

```bash
python -m redai_range.showcase 8080           # 7 weakness classes on one server
python -m red_ai engage --target 127.0.0.1 --ports 8080 --operator me --audit
```

Expected: **7 vulnerabilities confirmed** — exposed `.env`, a hidden dashboard, a
`robots`-disclosed backup, a default-credential admin panel, and LFI / SQLi /
command-injection — each with its recovered flag and a reproducible evidence
trail.
