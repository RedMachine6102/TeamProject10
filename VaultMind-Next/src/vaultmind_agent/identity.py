from __future__ import annotations

import base64
import ctypes
import os
import secrets
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaultmind_next.device import signed_message


class _DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD),
                ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _input_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    return _DataBlob(len(data), pointer), buffer


def _windows_protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("agent device keys currently require Windows DPAPI")
    source, source_buffer = _input_blob(data)
    result = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptProtectData(
        ctypes.byref(source), "VaultMind agent device key", None, None, None,
        0x01, ctypes.byref(result),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        ctypes.windll.kernel32.LocalFree(result.data)
        del source_buffer


def _windows_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("agent device keys currently require Windows DPAPI")
    source, source_buffer = _input_blob(data)
    result = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0x01, ctypes.byref(result)
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        ctypes.windll.kernel32.LocalFree(result.data)
        del source_buffer


@dataclass(frozen=True)
class DeviceIdentity:
    agent_id: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, agent_id: str) -> "DeviceIdentity":
        if not 8 <= len(agent_id) <= 128:
            raise ValueError("agent id must contain 8 to 128 characters")
        if not agent_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("agent id contains unsupported characters")
        return cls(agent_id=agent_id, private_key=Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> str:
        return base64.urlsafe_b64encode(
            self.private_key.public_key().public_bytes_raw()
        ).decode("ascii")

    def signed_request(self, action: str,
                       values: dict[str, str | int | None]) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc)
        nonce = secrets.token_urlsafe(24)
        message = signed_message(action, self.agent_id, timestamp, nonce, values)
        signature = base64.urlsafe_b64encode(
            self.private_key.sign(message)
        ).decode("ascii")
        return {
            "agent_id": self.agent_id, "timestamp": timestamp.isoformat(),
            "nonce": nonce, "signature": signature,
        }

    def save(self, path: Path) -> None:
        protected = _windows_protect(self.private_key.private_bytes_raw())
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(protected)
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    @classmethod
    def load(cls, agent_id: str, path: Path) -> "DeviceIdentity":
        raw = _windows_unprotect(path.read_bytes())
        if len(raw) != 32:
            raise ValueError("stored agent device key is invalid")
        return cls(agent_id, Ed25519PrivateKey.from_private_bytes(raw))
