"""TLS posture classifier + assessor: weak protocol/cipher/no-PFS/cert findings,
and a clean bill for a strong config. Hermetic (injected probes/cert)."""
import unittest

from red_ai.recon.tls import classify, assess_tls


def _acc(cipher):
    return {"status": "accepted", "cipher": cipher, "error": None}


def _rej():
    return {"status": "rejected", "cipher": None, "error": "unsupported"}


class TestClassify(unittest.TestCase):
    def test_weak_protocol_flagged(self):
        protos = {"TLSv1.3": _rej(), "TLSv1.2": _rej(),
                  "TLSv1.1": _rej(), "TLSv1": _acc(("AES128-SHA", "TLSv1", 128))}
        f = classify("h", 443, protos, {"valid": True})
        self.assertTrue(any("deprecated TLSv1" in x["title"] for x in f))

    def test_weak_cipher_flagged(self):
        protos = {"TLSv1.2": _acc(("ECDHE-RSA-RC4-SHA", "TLSv1.2", 128))}
        f = classify("h", 443, protos, {"valid": True})
        self.assertTrue(any("Weak cipher" in x["title"] for x in f))

    def test_no_pfs_flagged(self):
        protos = {"TLSv1.2": _acc(("AES256-GCM-SHA384", "TLSv1.2", 256))}  # static RSA kx
        f = classify("h", 443, protos, {"valid": True})
        self.assertTrue(any("forward secrecy" in x["title"] for x in f))

    def test_self_signed_cert_flagged(self):
        protos = {"TLSv1.2": _acc(("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256))}
        f = classify("h", 443, protos, {"valid": False, "error": "self-signed certificate"})
        self.assertTrue(any("self-signed" in x["title"].lower() for x in f))

    def test_strong_config_no_findings(self):
        protos = {"TLSv1.3": _acc(("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)),
                  "TLSv1.2": _acc(("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)),
                  "TLSv1.1": _rej(), "TLSv1": _rej()}
        f = classify("h", 443, protos, {"valid": True})
        self.assertEqual(f, [])


class TestAssess(unittest.TestCase):
    def test_non_tls_endpoint(self):
        prober = lambda h, p, v, t: ("rejected", None, "not tls")
        r = assess_tls("h", 80, prober=prober, cert_fetcher=lambda *a: {})
        self.assertFalse(r["is_tls"])
        self.assertEqual(r["findings"], [])

    def test_weak_endpoint_reports_and_reproduces(self):
        def prober(h, p, version, t):
            # accept TLSv1 with RC4, reject the rest
            name = {getattr(__import__("ssl").TLSVersion, "TLSv1", None): "TLSv1"}.get(version)
            if name == "TLSv1":
                return ("accepted", ("ECDHE-RSA-RC4-SHA", "TLSv1", 128), None)
            return ("rejected", None, "no")
        r = assess_tls("h", 443, prober=prober,
                       cert_fetcher=lambda *a: {"valid": False, "error": "self-signed certificate"},
                       replays=3)
        self.assertTrue(r["is_tls"])
        titles = [f["title"] for f in r["findings"]]
        self.assertTrue(any("TLSv1" in x for x in titles))
        self.assertTrue(any("self-signed" in x.lower() for x in titles))
        self.assertEqual(r["reproduction"]["TLSv1"]["rate"], 1.0)  # reproduced 3/3


if __name__ == "__main__":
    unittest.main()
