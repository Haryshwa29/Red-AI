"""SMB/RDP negotiate fingerprinting."""
import unittest
from red_ai.recon.smb_rdp import probe_smb, probe_rdp, fingerprint_smb_rdp, _smb1_negotiate, _rdp_connection_request


def opener_returning(resp):
    return lambda host, port, t, send: resp


class TestSMB(unittest.TestCase):
    def test_smbv1_enabled(self):
        # \xffSMB negotiate response, status 0, dialect index 0 (chosen)
        resp = b"\x00\x00\x00\x40\xffSMBr\x00\x00\x00\x00" + b"\x98\x01" + b"\x00" * 24 + b"\x00\x00" + b"\x00" * 10
        r = probe_smb("h", 445, opener=opener_returning(resp))
        self.assertEqual(r["service"], "SMB")
        self.assertTrue(r["smbv1"])
        self.assertTrue(any("EternalBlue" in l for l in r["leads"]))

    def test_smb2_only_no_smbv1(self):
        resp = b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 40
        r = probe_smb("h", 445, opener=opener_returning(resp))
        self.assertEqual(r["service"], "SMB")
        self.assertFalse(r["smbv1"])
        self.assertEqual(r["leads"], [])

    def test_no_response(self):
        self.assertIsNone(probe_smb("h", 445, opener=opener_returning(None))["service"])


class TestRDP(unittest.TestCase):
    def _cc(self, selected):
        tpkt = b"\x03\x00\x00\x13"
        x224cc = b"\x0e\xd0\x00\x00\x12\x34\x00"           # LI,CC,dst,src,class
        negrsp = b"\x02\x00\x08\x00" + int(selected).to_bytes(4, "little")
        return tpkt + x224cc + negrsp

    def test_nla_required(self):
        r = probe_rdp("h", 3389, opener=opener_returning(self._cc(0x02)))  # HYBRID
        self.assertEqual(r["service"], "RDP")
        self.assertTrue(r["nla_required"])
        self.assertEqual(r["leads"], [])

    def test_nla_not_required_bluekeep_lead(self):
        r = probe_rdp("h", 3389, opener=opener_returning(self._cc(0x01)))  # SSL only
        self.assertFalse(r["nla_required"])
        self.assertTrue(any("BlueKeep" in l for l in r["leads"]))

    def test_not_rdp(self):
        self.assertIsNone(probe_rdp("h", 3389, opener=opener_returning(b"garbage"))["service"])


class TestDispatchAndPackets(unittest.TestCase):
    def test_dispatch(self):
        self.assertIsNone(fingerprint_smb_rdp("h", 80))
        self.assertIsNotNone(_smb1_negotiate())
        # RDP CR is a well-formed TPKT
        cr = _rdp_connection_request()
        self.assertEqual(cr[0], 0x03)


if __name__ == "__main__":
    unittest.main()
