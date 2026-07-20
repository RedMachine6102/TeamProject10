from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class SealedSecret:
    nonce: str
    ciphertext: str
    key_version: int = 1

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))

    @classmethod
    def from_json(cls, value: str) -> "SealedSecret":
        return cls(**json.loads(value))


class SecretBox:
    """Encrypts server-held OAuth tokens and provider credentials.

    Production deployments should load this 32-byte key through a KMS/HSM,
    never from the database or container image.
    """

    def __init__(self, root_key: bytes):
        if len(root_key) != 32:
            raise ValueError("root key must be exactly 32 bytes")
        self._cipher = AESGCM(root_key)

    @classmethod
    def generate(cls) -> tuple["SecretBox", str]:
        key = secrets.token_bytes(32)
        return cls(key), base64.urlsafe_b64encode(key).decode("ascii")

    def seal(self, plaintext: bytes, context: str) -> SealedSecret:
        nonce = secrets.token_bytes(12)
        ciphertext = self._cipher.encrypt(nonce, plaintext, context.encode("utf-8"))
        return SealedSecret(
            nonce=base64.urlsafe_b64encode(nonce).decode("ascii"),
            ciphertext=base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        )

    def open(self, value: SealedSecret, context: str) -> bytes:
        nonce = base64.urlsafe_b64decode(value.nonce)
        ciphertext = base64.urlsafe_b64decode(value.ciphertext)
        return self._cipher.decrypt(nonce, ciphertext, context.encode("utf-8"))
