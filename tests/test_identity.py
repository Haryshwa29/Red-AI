"""
Operator identity + need-to-know access control invariants. Offline, stdlib.

Encodes the mitigation for the oracle / confused-deputy risk: RED-AI runs for,
and hands findings to, only an authenticated, authorized operator.
  * invocation auth: a scope is bound to an operator and signed with that
    operator's key; a different operator's key fails verification;
  * read auth: report/verify are refused to an operator not named as a reader;
  * legacy-open: a scope with no operator binding keeps working (back-compat).
"""
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from red_ai.contracts.scope import Scope, now, sign_scope, verify_scope
from red_ai.control.identity import (
    Keyring, DEFAULT_OPERATOR, AccessDenied, valid_operator_id,
    authorize_invocation, authorize_read, authorized_readers,
)


def a_scope(operator_id="", readers=()):
    vf = now(); vu = vf + timedelta(hours=1)
    return Scope(scope_id="s", owner="o", authorised_by="a", target="t",
                 valid_from=vf.isoformat(), valid_until=vu.isoformat(),
                 operator_id=operator_id, readers=tuple(readers))


class TestKeyring(unittest.TestCase):
    def setUp(self): self.root = Path(tempfile.mkdtemp())

    def test_create_and_load_distinct_keys(self):
        kr = Keyring(self.root)
        a, b = kr.create("alice"), kr.create("bob")
        self.assertNotEqual(a, b)
        self.assertEqual(kr.key("alice"), a)
        self.assertTrue(kr.exists("alice"))

    def test_duplicate_create_refused(self):
        kr = Keyring(self.root); kr.create("alice")
        with self.assertRaises(ValueError): kr.create("alice")

    def test_unknown_operator_key_denied(self):
        with self.assertRaises(AccessDenied): Keyring(self.root).key("ghost")

    def test_legacy_key_maps_to_local(self):
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "operator.key").write_bytes(b"x" * 32)
        kr = Keyring(self.root)
        self.assertTrue(kr.exists(DEFAULT_OPERATOR))
        self.assertIn(DEFAULT_OPERATOR, kr.ids())

    def test_invalid_ids_rejected(self):
        self.assertFalse(valid_operator_id("Alice"))
        self.assertFalse(valid_operator_id("a b"))
        self.assertFalse(valid_operator_id(""))
        self.assertTrue(valid_operator_id("alice-1_x"))


class TestInvocationAuth(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()); self.kr = Keyring(self.root)
        self.kr.create("alice"); self.kr.create("bob")

    def test_legacy_open_scope_allowed(self):
        authorize_invocation(a_scope(operator_id=""), "alice", self.kr)

    def test_bound_operator_allowed(self):
        authorize_invocation(a_scope(operator_id="alice"), "alice", self.kr)

    def test_wrong_operator_refused(self):
        with self.assertRaises(AccessDenied):
            authorize_invocation(a_scope(operator_id="alice"), "bob", self.kr)

    def test_unauthenticated_refused(self):
        with self.assertRaises(AccessDenied):
            authorize_invocation(a_scope(operator_id="ghost"), "ghost", self.kr)

    def test_cross_operator_signature_refused(self):
        env = sign_scope(a_scope(operator_id="alice"), self.kr.key("alice"))
        with self.assertRaises(ValueError):
            verify_scope(env, self.kr.key("bob"))
        self.assertEqual(verify_scope(env, self.kr.key("alice")).operator_id, "alice")


class TestReadAuth(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()); self.kr = Keyring(self.root)
        self.kr.create("alice"); self.kr.create("bob")

    def test_legacy_open_allowed(self):
        authorize_read(a_scope(operator_id="", readers=()), "alice", self.kr)

    def test_owner_is_reader(self):
        authorize_read(a_scope(operator_id="alice"), "alice", self.kr)

    def test_listed_reader_allowed(self):
        authorize_read(a_scope(operator_id="alice", readers=("alice", "bob")), "bob", self.kr)

    def test_non_reader_refused(self):
        with self.assertRaises(AccessDenied):
            authorize_read(a_scope(operator_id="alice", readers=("alice",)), "bob", self.kr)

    def test_authorized_readers_defaults_to_owner(self):
        self.assertEqual(authorized_readers(a_scope(operator_id="alice")), ("alice",))
        self.assertEqual(authorized_readers(a_scope(operator_id="", readers=())), ())


if __name__ == "__main__":
    unittest.main()
