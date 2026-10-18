"""
Operator identity and need-to-know access control.

Authorization in RED-AI is a signed ``Scope`` (``contracts/scope``). *Identity*
binds a scope to a named operator: the scope is signed with that operator's key,
so only a caller holding the same key can verify-and-run it, and only operators
the scope names as readers may render its reports. Offline and dependency-free:
identity is HMAC key possession -- the same primitive the scope already uses to
prove it was not tampered.

Honest boundary (stated, not hidden). This is ACCESS CONTROL AT THE TOOL, not
cryptographic confidentiality. Run artifacts on disk remain plaintext; an
operator with raw filesystem access can still read them. What identity prevents
is RED-AI *itself* -- the engine, the CLI, and the model-collaboration channel
-- running for, or handing findings to, an unauthenticated caller. That is the
mechanical half of the oracle / confused-deputy mitigation: the brain and the
findings only ever flow inside an authenticated, authorized engagement. OS and
disk permissions remain a deployment concern, exactly as the evidence chain is
tamper-DETECTION, not an immutable vault.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

DEFAULT_OPERATOR = "local"
_SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class AccessDenied(Exception):
    """Raised when an operator may not invoke a scope or read a run."""


def valid_operator_id(operator_id) -> bool:
    return bool(isinstance(operator_id, str) and _SLUG.match(operator_id))


class Keyring:
    """Per-operator HMAC keys on local disk. The default operator ``local`` maps
    to the legacy ``operator.key`` so existing single-operator setups keep
    working; every other operator lives under ``operators/<id>.key``."""

    def __init__(self, root):
        self.root = Path(root)
        self.dir = self.root / "operators"

    def _path(self, operator_id: str) -> Path:
        if not valid_operator_id(operator_id):
            raise ValueError(f"Invalid operator id: {operator_id!r} "
                             "(use lowercase letters, digits, '-' or '_')")
        if operator_id == DEFAULT_OPERATOR:
            legacy = self.root / "operator.key"
            if legacy.exists():
                return legacy
        return self.dir / f"{operator_id}.key"

    def exists(self, operator_id) -> bool:
        try:
            return self._path(operator_id).exists()
        except ValueError:
            return False

    def create(self, operator_id: str) -> bytes:
        path = self._path(operator_id)
        if path.exists():
            raise ValueError(f"Operator already exists: {operator_id}")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as h:
            h.write(secrets.token_bytes(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path.read_bytes()

    def key(self, operator_id: str) -> bytes:
        path = self._path(operator_id)
        if not path.exists():
            raise AccessDenied(f"Unknown operator (no key on this host): {operator_id}")
        return path.read_bytes()

    def ensure(self, operator_id: str) -> bytes:
        return self.key(operator_id) if self.exists(operator_id) else self.create(operator_id)

    def ids(self) -> list:
        found = []
        if (self.root / "operator.key").exists():
            found.append(DEFAULT_OPERATOR)
        if self.dir.exists():
            for p in sorted(self.dir.glob("*.key")):
                if p.stem not in found:
                    found.append(p.stem)
        return found


def authorized_readers(scope) -> tuple:
    """Operators allowed to read a run's artifacts: the explicit reader list if
    set, else the owning operator. Empty tuple => no restriction (legacy-open)."""
    readers = tuple(getattr(scope, "readers", ()) or ())
    if readers:
        return readers
    oid = getattr(scope, "operator_id", "") or ""
    return (oid,) if oid else ()


def authorize_invocation(scope, operator_id: str, keyring: Keyring) -> None:
    """Refuse unless ``operator_id`` is authenticated (holds a key) and is the
    operator the scope is bound to. A scope with no ``operator_id`` is treated as
    legacy-open and allowed (``doctor`` warns about those)."""
    bound = getattr(scope, "operator_id", "") or ""
    if not bound:
        return  # legacy-open scope: no identity binding
    if not keyring.exists(operator_id):
        raise AccessDenied(f"Operator not authenticated: {operator_id}")
    if operator_id != bound:
        raise AccessDenied(
            f"Operator {operator_id!r} may not run a scope bound to {bound!r}")


def authorize_read(scope, operator_id: str, keyring: Keyring) -> None:
    """Refuse unless ``operator_id`` is authenticated and is a need-to-know
    reader of this run (the owner counts as a reader). No reader restriction =>
    legacy-open."""
    readers = authorized_readers(scope)
    if not readers:
        return  # legacy-open
    if not keyring.exists(operator_id):
        raise AccessDenied(f"Operator not authenticated: {operator_id}")
    if operator_id not in readers:
        raise AccessDenied(
            f"Operator {operator_id!r} is not a need-to-know reader of this run")
