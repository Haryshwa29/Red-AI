"""Crypto-misuse analyzer: recovers plaintext from weak samples as proof, and —
critically — does NOT cry 'broken' on strong/random ciphertext. Hermetic."""
import base64
import binascii
import os
import unittest

from red_ai.crypto.analyze import analyze_samples, break_xor


def _xor(b, k):
    return bytes(b[i] ^ k[i % len(k)] for i in range(len(b)))


def _hex(b):
    return binascii.hexlify(b).decode()


class TestCryptoRecovery(unittest.TestCase):
    def test_base64_encoding_is_flagged_not_encryption(self):
        rep = analyze_samples([base64.b64encode(b"user=admin;balance=100000").decode()])
        self.assertTrue(rep["broke"])
        self.assertEqual(rep["findings"][0]["class"], "not-encryption")
        self.assertIn("balance", rep["findings"][0]["recovered"])

    def test_single_byte_xor_recovered_exactly(self):
        pt = b"The quick brown fox says hello to all of you today friend"
        rep = analyze_samples([_hex(_xor(pt, b"\x5a"))])
        rec = [f["recovered"] for f in rep["findings"] if f["class"] == "single-byte-xor"]
        self.assertTrue(rec and rec[0] == pt.decode())

    def test_repeating_key_xor_recovered_and_labeled(self):
        pt = b"Confidential the launch code is alpha seven niner do not share this now ok"
        rep = analyze_samples([_hex(_xor(pt, b"KEY"))])
        got = [f for f in rep["findings"] if f["class"] == "repeating-key-xor"]
        self.assertTrue(got and got[0]["recovered"] == pt.decode())

    def test_keystream_reuse_detected(self):
        ks = os.urandom(80)
        a = _hex(_xor(b"Transfer five thousand dollars to the offshore account please now", ks))
        b = _hex(_xor(b"Meeting at noon about the quarterly revenue and the merger plan ok", ks))
        rep = analyze_samples([a, b])
        self.assertTrue(any(f["class"] == "keystream-reuse" for f in rep["findings"]))

    def test_ecb_structure_detected(self):
        rep = analyze_samples([_hex(os.urandom(16) * 3)])
        self.assertTrue(any(f["class"] == "ecb-mode" for f in rep["findings"]))

    def test_weak_rsa_cube_root(self):
        m = int.from_bytes(b"SECRET", "big")
        rsa = {"n": (1 << 2048) - 1, "e": 3, "c": pow(m, 3, (1 << 2048) - 1)}
        rep = analyze_samples([], rsa=rsa)
        got = [f for f in rep["findings"] if f["class"] == "weak-rsa"]
        self.assertTrue(got and got[0]["recovered"] == "SECRET")

    def test_small_modulus_rsa_factored(self):
        p, q, e = 10007, 10009, 17            # tiny primes -> factorable
        n = p * q
        d = pow(e, -1, (p - 1) * (q - 1))
        m = 42
        c = pow(m, e, n)
        rep = analyze_samples([], rsa={"n": n, "e": e, "c": c})
        self.assertTrue(any(f["class"] == "weak-rsa" for f in rep["findings"]))


class TestNoFalsePositives(unittest.TestCase):
    def test_random_bytes_do_not_break(self):
        for _ in range(20):
            rep = analyze_samples([_hex(os.urandom(64)) for _ in range(4)])
            self.assertFalse(rep["broke"])
            self.assertIn("NOT a proof of safety", rep["verdict"])

    def test_break_xor_returns_none_on_random(self):
        self.assertIsNone(break_xor(os.urandom(64)))


if __name__ == "__main__":
    unittest.main()
