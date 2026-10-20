# RED-AI Crypto Assessment — proof, not citation

A company won't (and shouldn't) accept "this was broken in the past, here's an
article" as a reason to change their crypto. RED-AI's crypto findings are backed
by a demonstration against **their own endpoint or their own sample data** —
recovered plaintext, or their server's own weak behaviour — with the standard /
CVE attached only as the *why it matters*, never as the proof.

There are two complementary capabilities.

---

## 1. Crypto-misuse analyzer — recover plaintext from weak samples

> **The question:** *"Can I ask a company for sample data and have RED-AI decrypt
> it as hard proof?"* — Yes, when the encryption is genuinely misused. The
> recovered plaintext **is** the proof.

```bash
python -m red_ai crypto --samples samples.txt            # one ciphertext per line (hex/base64/raw)
python -m red_ai crypto --samples s.txt --rsa-n <n> --rsa-e <e> --rsa-c <c>
```

It runs a battery of detectors/breakers (all offline, stdlib) and recovers the
plaintext where the scheme is broken:

| Misuse | What RED-AI does | Proof |
|---|---|---|
| **Encoding, not encryption** (base64/hex/plaintext) | decode | the readable data itself |
| **Single-byte XOR** | brute 256 keys, English-score | recovered plaintext |
| **Repeating-key XOR** (Vigenère) | Hamming-distance key period + per-column break | recovered plaintext |
| **Keystream / nonce reuse** (stream/CTR/GCM nonce reused) | two-time-pad XOR + crib-drag | reuse proven; fragments recovered |
| **ECB mode** | detect repeated ciphertext blocks | structure leak shown (no recovery needed) |
| **Weak RSA** (tiny modulus, or e=3 no-padding) | factor / cube-root | recovered plaintext |

**The honesty that makes it credible:** it does **not** break correctly-used
strong crypto (AES-GCM with random keys/nonces, RSA-2048+OAEP). Fed random or
properly-encrypted samples it returns *"No demonstrable break from these samples.
NOT a proof of safety"* — and that discipline is enforced by tests (20 random-
sample trials must all come back clean). A tool that cried "broken" on strong
crypto would be worthless; this one's verdict means something.

So the result is the verdict: **recovery = you're sitting on a time bomb; no
recovery = no demonstrable break here** (still not a certification of safety).

---

## 2. TLS / crypto posture — prove the transport is weak on *their* endpoint

RED-AI does not brute-force AES or TLS 1.3 (nobody can). It demonstrates that
*this server* will negotiate weak transport crypto, by handshaking against it:

- **Deprecated protocols accepted** — SSLv3 / TLS 1.0 / 1.1 (the server completed
  the handshake — captured, re-probed for a reproduction rate).
- **Weak cipher negotiated** — RC4 / 3DES / DES / EXPORT / NULL / MD5.
- **No forward secrecy** — non-ECDHE/DHE key exchange (a later key compromise
  decrypts recorded sessions).
- **Certificate** — a standard verifying client's live verdict: self-signed,
  expired, or hostname mismatch. The rejection error *is* the proof that the cert
  provides no real authentication.

Enabled automatically in `engage` (it assesses TLS on discovered ports and streams
findings to the dashboard). The evidence is the server's own negotiated handshake
at a given time, reproduced — not a reference to history.

> **Honest limitation:** RED-AI can only *attempt* the protocol/cipher versions
> the local TLS library allows. Modern OpenSSL refuses to negotiate the truly
> ancient ones even on request, so for those RED-AI reports "untestable here"
> rather than guessing. The certificate and forward-secrecy demonstrations work
> regardless.

---

## Where this sits

Both are authorized assessment of the **client's own** transport and data — the
same model as password auditing. Neither is a generic "break any encryption"
capability (that doesn't exist); both are honest demonstrations of *misuse*,
which is what organizations actually need to justify a change.
