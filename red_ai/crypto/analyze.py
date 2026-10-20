"""Crypto-misuse analyzer: recover plaintext from poorly-used encryption as hard
proof that it must be replaced.

This is the honest, high-value form of "break the encryption": RED-AI does NOT
break correctly-used strong crypto (AES-GCM with random keys/nonces, TLS 1.3) —
nothing can. It detects and *demonstrates* the ways encryption is commonly
MIS-used, on the client's own authorized sample data, and returns the recovered
plaintext next to their ciphertext. That recovered plaintext is the proof; a
reference to the weakness class is attached only as the why.

Detectors (cheap → expensive), all pure stdlib, none raising past the caller:
  * encoding-not-encryption  — base64 / hex / already-plaintext
  * single-byte XOR          — brute 256 keys, English-score
  * repeating-key XOR        — keysize by Hamming distance, per-column break
  * keystream / nonce reuse  — two-time pad (stream/CTR/GCM nonce reused) crib-drag
  * ECB mode                 — repeated ciphertext blocks leak structure
  * weak RSA                 — tiny modulus (factor) or e=3 cube-root, from a hint

If nothing recovers, the verdict is "no demonstrable break from these samples"
— explicitly NOT a proof of safety.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from itertools import combinations

# Rough English byte-frequency weights for scoring XOR candidates.
_FREQ = {ord(' '): 13.0, ord('e'): 12.7, ord('t'): 9.1, ord('a'): 8.2, ord('o'): 7.5,
         ord('i'): 7.0, ord('n'): 6.7, ord('s'): 6.3, ord('h'): 6.1, ord('r'): 6.0,
         ord('d'): 4.3, ord('l'): 4.0, ord('u'): 2.8, ord('c'): 2.8, ord('m'): 2.4,
         ord('w'): 2.4, ord('f'): 2.2, ord('g'): 2.0, ord('y'): 2.0, ord('p'): 1.9,
         ord('b'): 1.5}


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return ok / len(b)


def _alpha_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if (65 <= x <= 90 or 97 <= x <= 122 or x == 32)) / len(b)


def _alnum_space_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if (48 <= x <= 57 or 65 <= x <= 90 or 97 <= x <= 122 or x == 32)) / len(b)


def _looks_text(b: bytes) -> bool:
    # Readable structured text: NO control bytes (real ciphertext is binary and has
    # them) and mostly alphanumeric/space. Distinguishes base64/plaintext — including
    # digit-heavy data like card numbers — from XOR gibberish (which carries control
    # bytes) without a letter-density bias.
    if not b:
        return False
    if not all(32 <= x < 127 or x in (9, 10, 13) for x in b):
        return False
    return _alnum_space_ratio(b) >= 0.70


def _english_score(b: bytes) -> float:
    if not b:
        return -1e9
    score = 0.0
    for x in b:
        if 32 <= x < 127 or x in (9, 10, 13):
            score += _FREQ.get(x | 0x20, 0.2)  # lowercase fold
        else:
            score -= 12.0  # non-printable: strongly unlikely for text plaintext
    return score / len(b)


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# --------------------------------------------------------------------------- #
# Input decoding
# --------------------------------------------------------------------------- #
def decode_input(s: str) -> "tuple[bytes, str]":
    """Interpret one sample string → (bytes, how). Tries hex, then base64, else raw."""
    t = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", t) and len(t) % 2 == 0 and len(t) >= 4:
        try:
            return binascii.unhexlify(t), "hex"
        except Exception:
            pass
    if re.fullmatch(r"[A-Za-z0-9+/=]+", t) and len(t) % 4 == 0 and len(t) >= 8:
        try:
            return base64.b64decode(t, validate=True), "base64"
        except Exception:
            pass
    return s.encode("utf-8", "replace"), "raw"


# --------------------------------------------------------------------------- #
# Breakers
# --------------------------------------------------------------------------- #
def break_single_byte_xor(ct: bytes) -> "tuple[int, bytes, float]":
    best = (0, b"", -1e9)
    for k in range(256):
        pt = bytes(c ^ k for c in ct)
        sc = _english_score(pt)
        if sc > best[2]:
            best = (k, pt, sc)
    return best


_COMMON_WORDS = set((
    "the be to of and a in that have it for not on with he as you do at this but his "
    "by from they we say her she or an will my one all would there their what so up out "
    "if about who get which go me when make can like time no just him know take into year "
    "good some could them see other then now look only come over think back after use two "
    "how our work first well way even want because any give day most is are was were this "
    "code launch share alpha account admin balance transfer secret password login user data"
).split())


def _word_ratio(text: str) -> float:
    toks = re.findall(r"[a-z]+", text.lower())
    if not toks:
        return 0.0
    return sum(1 for t in toks if t in _COMMON_WORDS) / len(toks)


def _clean(pt: bytes, alpha_min: float) -> bool:
    # readable text: printable, letter-dense, AND containing real English words
    # (the only reliable way to reject letter-dense XOR gibberish)
    if _printable_ratio(pt) < 0.95 or _alpha_ratio(pt) < alpha_min:
        return False
    return _word_ratio(pt.decode("utf-8", "replace")) >= 0.25


def break_xor(ct: bytes, max_keysize: int = 40) -> "tuple[bytes, bytes, float] | None":
    """Recover a fixed/repeating-XOR plaintext. Single-byte first — accepted only
    on a clean, letter-dense result (so a multi-byte ciphertext does not masquerade
    as single-byte). Otherwise detect the key period by normalized Hamming distance
    (the structural signal, not a frequency guess) and recover at that period."""
    if len(ct) < 4:
        return None
    # 1) single byte
    k, pt, sc = break_single_byte_xor(ct)
    if sc > 3.0 and _clean(pt, 0.72):
        return (bytes([k]), pt, sc)
    if len(ct) < 16:
        return None
    # 2) repeating key — rank key sizes by normalized Hamming distance
    sizes = []
    for ks in range(2, min(max_keysize, len(ct) // 4) + 1):
        blocks = [ct[b * ks:(b + 1) * ks] for b in range(min(len(ct) // ks, 6))]
        pairs = list(combinations(blocks, 2))
        if not pairs:
            continue
        d = sum(_hamming(a, b) for a, b in pairs) / (len(pairs) * ks)
        sizes.append((d, ks))
    sizes.sort()
    for _, ks in sizes[:4]:
        key = bytes(break_single_byte_xor(ct[col::ks])[0] for col in range(ks))
        pt = bytes(c ^ key[i % ks] for i, c in enumerate(ct))
        if _clean(pt, 0.70):
            return (key, pt, _english_score(pt))
    return None


def detect_ecb(ct: bytes, block: int = 16) -> int:
    if len(ct) < block * 2:
        return 0
    blocks = [ct[i:i + block] for i in range(0, len(ct) - (len(ct) % block), block)]
    return len(blocks) - len(set(blocks))  # number of repeated blocks


def keystream_reuse(samples: "list[bytes]") -> "list[dict] | None":
    """Two-time pad: if samples share a keystream (stream/CTR/GCM nonce reuse),
    ci XOR cj = pi XOR pj. Crib-drag with ' the ' to recover runs of plaintext."""
    longs = [s for s in samples if len(s) >= 8]
    if len(longs) < 2:
        return None
    hits = []
    for i, j in combinations(range(len(longs)), 2):
        a, b = longs[i], longs[j]
        n = min(len(a), len(b))
        x = bytes(a[k] ^ b[k] for k in range(n))
        # If two plaintexts are ASCII, their XOR is mostly 'letter^letter' (<0x80,
        # often <0x40) — a strong, cheap signal of keystream reuse.
        # p1^p2 for English text: letter^letter < 0x20, letter^space in [A-Za-z],
        # identical chars = 0. That combination is the reused-keystream signature.
        asciiish = sum(1 for v in x if v == 0 or v < 0x20
                       or 0x41 <= v <= 0x5A or 0x61 <= v <= 0x7A) / n
        if asciiish >= 0.7:
            recovered = _crib_drag(x)
            hits.append({"pair": (i, j), "xor_ascii_ratio": round(asciiish, 2),
                         "recovered_fragment": recovered})
    return hits or None


def _crib_drag(xor_stream: bytes,
               cribs=(b" the ", b" and ", b"ing ", b" to ", b" of ", b"the ", b" that ")) -> str:
    """Slide common words through p1^p2; where a crib yields a readable, letter-
    dense run, that run is a fragment of the other plaintext."""
    _WORDS = (" the ", "the ", " and", "ing ", "ion ", "that", " for", " you",
              " are ", " to ", " of ", " is ", "with", "ment")
    best = ""
    for crib in cribs:
        for off in range(0, max(1, len(xor_stream) - len(crib))):
            guess = bytes(xor_stream[off + k] ^ crib[k] for k in range(len(crib)))
            frag = guess.decode("ascii", "replace")
            # a real fragment is all letters/space AND contains a common word
            if all(ch.isalpha() or ch == " " for ch in frag) and \
               any(w in frag.lower() for w in _WORDS) and len(frag.strip()) > len(best.strip()):
                best = frag
    return best


def weak_rsa(n: int, e: int, c: int) -> "dict | None":
    """Recover m for textbook/weak RSA: tiny modulus (factor) or e=3 cube root."""
    # e=3 with small message: c may be a perfect cube (no/short modulus reduction)
    if e == 3:
        r = _iroot(c, 3)
        if r is not None and pow(r, 3) == c:
            return {"method": "RSA e=3 cube root (no padding)", "m": r}
    # small modulus → factor by trial / Fermat
    p = _factor_small(n)
    if p and 1 < p < n and n % p == 0:
        q = n // p
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
        except ValueError:
            return None
        m = pow(c, d, n)
        return {"method": f"RSA modulus factored ({n.bit_length()}-bit)", "p": p, "q": q, "m": m}
    return None


def _iroot(x: int, k: int) -> "int | None":
    if x < 0:
        return None
    lo, hi = 0, 1 << ((x.bit_length() // k) + 2)
    while lo <= hi:
        mid = (lo + hi) // 2
        p = mid ** k
        if p == x:
            return mid
        if p < x:
            lo = mid + 1
        else:
            hi = mid - 1
    return None


def _factor_small(n: int, limit: int = 1_000_000) -> "int | None":
    if n % 2 == 0:
        return 2
    # Fermat (good for close p,q) then bounded trial division
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(100000):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            f = a - b
            if 1 < f < n:
                return f
        a += 1
    f = 3
    while f <= limit and f * f <= n:
        if n % f == 0:
            return f
        f += 2
    return None


def _as_int(m) -> "str":
    """Turn a recovered RSA integer into text if it decodes to bytes nicely."""
    try:
        raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if _looks_text(raw):
            return raw.decode("utf-8", "replace")
        return f"<int {m}>"
    except Exception:
        return f"<int {m}>"


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def analyze_samples(inputs: "list[str]", rsa=None) -> dict:
    """Analyze authorized ciphertext samples. Returns a report with findings; each
    finding that recovers text includes ``recovered`` — the hard proof.

    ``rsa`` optionally = {"n","e","c"} (ints or hex strings) for weak-RSA checks.
    """
    findings: list[dict] = []
    decoded = [decode_input(s) for s in inputs]
    cts = [b for b, _ in decoded]

    # 1) encoding masquerading as encryption / already plaintext
    for i, (b, how) in enumerate(decoded):
        if _looks_text(b):
            findings.append({
                "class": "not-encryption", "severity": "critical",
                "method": f"input was {how}-encoded, not encrypted" if how != "raw" else "plaintext (no encryption)",
                "recovered": b.decode("utf-8", "replace")[:400],
                "evidence": f"sample #{i+1} decodes directly to readable text",
                "remediation": "This data is not encrypted. Encrypt it with AES-GCM and a managed key.",
                "reference": "encoding (base64/hex) is not encryption"})

    plausible = [cts[i] for i, (b, _) in enumerate(decoded) if not _looks_text(b)]

    # 2) keystream / nonce reuse across samples (two-time pad)
    reuse = keystream_reuse(plausible)
    if reuse:
        frag = next((r["recovered_fragment"] for r in reuse if r["recovered_fragment"]), "")
        findings.append({
            "class": "keystream-reuse", "severity": "critical",
            "method": "stream/CTR/GCM keystream (nonce) reused across messages — two-time pad",
            "recovered": frag or None,
            "evidence": f"{len(reuse)} sample pair(s) XOR to near-ASCII (keystream cancels)"
                        + (f"; recovered fragment: {frag!r}" if frag
                           else "; nonce reuse confirmed — full recovery needs more samples/known cribs"),
            "remediation": "Never reuse a nonce/IV with the same key; use a unique random nonce per message.",
            "reference": "nonce reuse breaks CTR/GCM confidentiality"})

    # 3) per-sample XOR family (fixed or repeating key) — one unified breaker
    for i, ct in enumerate(plausible):
        res = break_xor(ct)
        if not res:
            continue
        key, pt, _sc = res
        text = pt.decode("utf-8", "replace")[:400]
        if len(key) == 1 or len(set(key)) == 1:
            findings.append({
                "class": "single-byte-xor", "severity": "critical",
                "method": f"single-byte XOR (key=0x{key[0]:02x})",
                "recovered": text,
                "evidence": f"sample #{i+1}: XOR with one byte yields readable text",
                "remediation": "XOR with a fixed byte is not encryption; use AES-GCM.",
                "reference": "single-byte XOR is trivially brute-forced (256 keys)"})
        else:
            findings.append({
                "class": "repeating-key-xor", "severity": "critical",
                "method": f"repeating-key XOR (key length {len(key)})",
                "recovered": text,
                "evidence": f"sample #{i+1}: Vigenere-style XOR recovered via per-column brute force",
                "remediation": "Repeating-key XOR is not encryption; use AES-GCM with a real key.",
                "reference": "repeating-key XOR is broken by classical cryptanalysis"})

    # 4) ECB structure leak
    for i, ct in enumerate(plausible):
        for block in (16, 8):
            reps = detect_ecb(ct, block)
            if reps > 0:
                findings.append({
                    "class": "ecb-mode", "severity": "high",
                    "method": f"ECB mode ({block}-byte block cipher)",
                    "recovered": None,
                    "evidence": f"sample #{i+1}: {reps} identical ciphertext block(s) of {block} bytes "
                                "— identical plaintext leaks (no recovery needed to prove it)",
                    "remediation": "ECB leaks structure; use an authenticated mode (AES-GCM) with random IV.",
                    "reference": "ECB penguin — identical blocks map identically"})
                break

    # 5) weak RSA
    if rsa:
        try:
            n = int(rsa["n"], 16) if isinstance(rsa["n"], str) else int(rsa["n"])
            e = int(rsa["e"], 16) if isinstance(rsa["e"], str) else int(rsa["e"])
            c = int(rsa["c"], 16) if isinstance(rsa["c"], str) else int(rsa["c"])
            r = weak_rsa(n, e, c)
            if r:
                findings.append({
                    "class": "weak-rsa", "severity": "critical",
                    "method": r["method"], "recovered": _as_int(r["m"]),
                    "evidence": f"recovered the RSA plaintext integer from n({n.bit_length()}-bit),e,c",
                    "remediation": "Use RSA-2048+ with OAEP padding (or modern ECC); never textbook RSA.",
                    "reference": "small modulus is factorable; e=3 without padding is cube-rootable"})
        except Exception:
            pass

    # de-dupe by (class, recovered)
    seen = set()
    uniq = []
    for f in findings:
        key = (f["class"], f.get("recovered"))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    broke = any(f.get("recovered") for f in uniq) or any(
        f["class"] in ("ecb-mode", "keystream-reuse") for f in uniq)

    return {
        "samples": len(inputs),
        "findings": uniq,
        "broke": broke,
        "verdict": ("WEAK ENCRYPTION — plaintext/structure recovered from your samples; replace it"
                    if broke else
                    "No demonstrable break from these samples. NOT a proof of safety — "
                    "absence of a break here does not certify the scheme."),
    }
