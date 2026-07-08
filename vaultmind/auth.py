"""Authentication and session management.

Design-doc requirement: session tokens last 15 minutes, after which the
user must re-authenticate via biometrics or PIN.

- The master password is never stored. A random "verifier" blob is
  encrypted with the derived key at setup; a successful decrypt at login
  proves the password without keeping any password hash around.
- PIN unlock re-derives a PIN-wrapped copy of the vault key, so a locked
  session can resume without retyping the master password.
- Biometric unlock is OS-specific (Windows Hello / Touch ID); the PIN
  path stands in for it in this prototype and the hook is noted in the UI.
"""
from __future__ import annotations

import time

from . import corelib
from .storage import VaultStorage

SESSION_SECONDS = 15 * 60
VERIFIER_MAGIC = b"VAULTMIND-OK"


class Session:
    def __init__(self, key: bytes):
        self._key = key
        self.started = time.time()

    @property
    def key(self) -> bytes:
        if self.expired:
            raise PermissionError("session expired — re-authenticate")
        return self._key

    @property
    def expired(self) -> bool:
        return (time.time() - self.started) > SESSION_SECONDS

    @property
    def seconds_left(self) -> int:
        return max(0, int(SESSION_SECONDS - (time.time() - self.started)))

    def refresh(self) -> None:
        self.started = time.time()

    def destroy(self) -> None:
        self._key = b"\x00" * 32


class AuthManager:
    def __init__(self, store: VaultStorage):
        self.store = store

    # ---- first-run setup ---------------------------------------------------
    def initialize(self, master_password: str, pin: str) -> Session:
        salt = corelib.random_bytes(16)
        key = corelib.derive_key(master_password, salt)
        self.store.set_meta("salt", salt)
        self.store.set_meta("verifier", corelib.encrypt(key, VERIFIER_MAGIC))
        self._set_pin(pin, key)
        return Session(key)

    # ---- master password login ----------------------------------------------
    def login(self, master_password: str) -> Session | None:
        salt = self.store.get_meta("salt")
        verifier = self.store.get_meta("verifier")
        if salt is None or verifier is None:
            return None
        key = corelib.derive_key(master_password, salt)
        if corelib.decrypt(key, verifier) != VERIFIER_MAGIC:
            return None
        return Session(key)

    # ---- PIN quick unlock (stand-in for biometric re-auth) -------------------
    def _set_pin(self, pin: str, vault_key: bytes) -> None:
        pin_salt = corelib.random_bytes(16)
        pin_key = corelib.derive_key(pin, pin_salt, iterations=200_000)
        self.store.set_meta("pin_salt", pin_salt)
        self.store.set_meta("pin_wrapped_key", corelib.encrypt(pin_key, vault_key))

    def unlock_with_pin(self, pin: str) -> Session | None:
        pin_salt = self.store.get_meta("pin_salt")
        wrapped = self.store.get_meta("pin_wrapped_key")
        if pin_salt is None or wrapped is None:
            return None
        pin_key = corelib.derive_key(pin, pin_salt, iterations=200_000)
        vault_key = corelib.decrypt(pin_key, wrapped)
        if vault_key is None or len(vault_key) != 32:
            return None
        return Session(vault_key)
