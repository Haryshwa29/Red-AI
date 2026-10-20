"""Dashboard plumbing: the stdlib WebSocket codec, the event shaper, the gap
analysis ('where to improve'), and module-toggle scoping. All hermetic."""
import io
import os
import unittest

from red_ai.web import ws
from red_ai.web.shaper import shape_event, gap_analysis
from red_ai.engage import module_roster
from red_ai.exploit.module import ExploitModuleRegistry
from red_ai.exploit.modules import WebFlagHuntModule, LFIModule


def _client_frame(payload: bytes, opcode=0x1) -> bytes:
    mask = os.urandom(4)
    masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
    n = len(payload)
    if n < 126:
        hdr = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x80 | opcode, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        hdr = bytes([0x80 | opcode, 0x80 | 127]) + n.to_bytes(8, "big")
    return hdr + mask + masked


class _FakeW:
    def __init__(self):
        self.buf = b""
    def write(self, b):
        self.buf += b
    def flush(self):
        pass


class TestWebSocket(unittest.TestCase):
    def test_accept_key_rfc_example(self):
        self.assertEqual(ws.accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_server_frame_is_unmasked_text(self):
        f = ws.encode_text("Hi")
        self.assertEqual(f, bytes([0x81, 2]) + b"Hi")

    def test_decode_masked_client_frame(self):
        op, data = ws.read_frame(io.BytesIO(_client_frame(b'{"action":"engage"}')))
        self.assertEqual((op, data), (0x1, b'{"action":"engage"}'))

    def test_extended_length_roundtrip(self):
        big = b"x" * 300
        op, data = ws.read_frame(io.BytesIO(_client_frame(big)))
        self.assertEqual(data, big)
        self.assertEqual(ws.encode_frame(big)[1], 126)

    def test_recv_answers_ping_and_returns_text(self):
        rf = io.BytesIO(_client_frame(b"x", 0x9) + _client_frame(b'{"a":1}', 0x1))
        w = _FakeW()
        c = ws.WSConnection(rf, w)
        self.assertEqual(c.recv(), '{"a":1}')
        self.assertEqual(w.buf[0] & 0x0F, 0xA)  # a pong was written

    def test_recv_none_on_close(self):
        c = ws.WSConnection(io.BytesIO(_client_frame(b"", 0x8)), _FakeW())
        self.assertIsNone(c.recv())


class TestShaper(unittest.TestCase):
    def test_probe_shape(self):
        rec = shape_event({"kind": "probe", "phase": "recon",
                           "payload": {"port": 80, "state": "open", "latency_ms": 1},
                           "timestamp": "2026-10-20T01:02:03+00:00"})
        self.assertEqual(rec["data"]["port"], 80)
        self.assertEqual(rec["t"], "01:02:03")

    def test_web_enum_merges_disclosed_linked_params(self):
        rec = shape_event({"kind": "web_enum", "phase": "recon", "payload": {
            "port": 80, "root": {"status": 200},
            "paths": [{"path": "/a"}], "disclosed": [{"path": "/b"}],
            "linked": [{"path": "/c"}], "params": [{"path": "/v", "param": "id"}]}})
        self.assertEqual(set(rec["data"]["paths"]), {"/a", "/b", "/c"})
        self.assertEqual(rec["data"]["params"], ["/v?id"])

    def test_step_extracts_discovered_path(self):
        rec = shape_event({"kind": "step", "phase": "exploit", "payload": {
            "module": "native.content_discovery", "outcome": "advanced",
            "proves": "discovered /admin (HTTP 200)", "observations": []}})
        self.assertEqual(rec["data"]["path"], "/admin")


class TestGapAnalysis(unittest.TestCase):
    def test_open_ssh_names_cp3_nonweb(self):
        gaps = gap_analysis({"recon_summary": {"open": [{"port": 22, "service": "ssh"}]},
                             "facts": [], "captured": False, "web_surfaces": 0, "summary": {}})
        self.assertTrue(any("SSH" in g["lead"] for g in gaps))

    def test_login_surface_names_form_auth(self):
        gaps = gap_analysis({"recon_summary": {"open": []},
                             "facts": ["recon: /admin linked from homepage"],
                             "captured": False, "web_surfaces": 1, "summary": {"outcome": "no_breach"}})
        self.assertTrue(any("form-login" in g["missing"] for g in gaps))

    def test_no_open_ports_flags_reachability(self):
        gaps = gap_analysis({"recon_summary": {"open": []}, "facts": [],
                             "captured": False, "status": "no_web_surface", "summary": {}})
        self.assertTrue(any(g["checkpoint"] == "connectivity" for g in gaps))

    def test_open_but_nonweb_surface_gap(self):
        gaps = gap_analysis({"recon_summary": {"open": [{"port": 22, "service": "ssh"}]},
                             "facts": [], "captured": False, "status": "no_web_surface", "summary": {}})
        self.assertTrue(any("no web surface" in g["lead"].lower() for g in gaps))


class TestModuleToggle(unittest.TestCase):
    def test_roster_lists_the_web_modules(self):
        ids = {m["id"] for m in module_roster()}
        self.assertIn("native.content_discovery", ids)
        self.assertIn("native.sqli_read", ids)

    def test_module_allowlist_restricts_candidates(self):
        reg = ExploitModuleRegistry()
        reg.register(WebFlagHuntModule()); reg.register(LFIModule())
        cands = reg.candidates(
            allowed_techniques=frozenset({"data_access", "injection"}),
            allowed_modules=frozenset({"native.web_flag_hunt"}),
            authorized_tools=frozenset())
        self.assertEqual([m.id for m in cands], ["native.web_flag_hunt"])


if __name__ == "__main__":
    unittest.main()
