"""Non-web service fingerprinting from banners / protocol probes."""
import unittest
from red_ai.recon.banner import fingerprint, unauth_exposure, grab_banner


class TestFingerprint(unittest.TestCase):
    def test_ssh(self):
        self.assertEqual(fingerprint(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"), ("SSH", "OpenSSH_8.9p1"))

    def test_mysql_handshake(self):
        # [3-byte len][seq=0][protover=10]8.0.34\x00...
        pkt = b"\x4a\x00\x00\x00\x0a" + b"8.0.34" + b"\x00" + b"\x15\x00\x00\x00rest"
        svc, ver = fingerprint(pkt)
        self.assertEqual(svc, "MySQL"); self.assertTrue(ver.startswith("8.0.34"))

    def test_mariadb(self):
        pkt = b"\x4a\x00\x00\x00\x0a" + b"5.5.5-10.6.12-MariaDB" + b"\x00rest"
        svc, ver = fingerprint(pkt)
        self.assertEqual(svc, "MariaDB")

    def test_vnc(self):
        self.assertEqual(fingerprint(b"RFB 003.008\n")[0], "VNC")

    def test_redis_info(self):
        svc, ver = fingerprint(b"$100\r\n# Server\r\nredis_version:7.0.11\r\nos:Linux\r\n")
        self.assertEqual(svc, "Redis"); self.assertEqual(ver, "7.0.11")

    def test_redis_noauth(self):
        self.assertEqual(fingerprint(b"-NOAUTH Authentication required.\r\n"), ("Redis", None))

    def test_memcached(self):
        self.assertEqual(fingerprint(b"VERSION 1.6.21\r\n"), ("Memcached", "1.6.21"))

    def test_telnet_iac(self):
        self.assertEqual(fingerprint(b"\xff\xfd\x18\xff\xfd\x20")[0], "Telnet")

    def test_unauth_exposure_leads(self):
        self.assertTrue(unauth_exposure("Redis", "7.0.11"))
        self.assertTrue(unauth_exposure("Memcached", "1.6.21"))
        self.assertEqual(unauth_exposure("SSH", "OpenSSH_8.9"), [])

    def test_grab_banner_probes_redis(self):
        seen = {}
        def opener(host, port, t, send):
            seen["send"] = send; return b"redis_version:7.0.0\r\n"
        grab_banner("h", 6379, 2000, opener)
        self.assertEqual(seen["send"], b"INFO server\r\n")


if __name__ == "__main__":
    unittest.main()
