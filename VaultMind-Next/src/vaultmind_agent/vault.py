from __future__ import annotations

import base64
import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from vaultmind_next.models import VaultEnvelope, VaultKeyEnvelope


VAULT_KEY_CONTEXT = b"vaultmind-vault-key-v1"


def derive_vault_key(passphrase: str, salt_text: str) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("vault passphrase must contain at least 12 characters")
    salt = base64.b64decode(salt_text, altchars=b"-_", validate=True)
    if len(salt) != 16:
        raise ValueError("vault salt must contain 16 bytes")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000
    ).derive(passphrase.encode("utf-8"))


def wrap_vault_key(passphrase: str, vault_key: bytes,
                   salt: bytes | None = None) -> dict:
    if len(vault_key) != 32:
        raise ValueError("vault key must contain 32 bytes")
    salt = salt or secrets.token_bytes(16)
    salt_text = base64.b64encode(salt).decode("ascii")
    wrapping_key = derive_vault_key(passphrase, salt_text)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(wrapping_key).encrypt(nonce, vault_key, VAULT_KEY_CONTEXT)
    return VaultKeyEnvelope(
        salt=salt_text,
        nonce=base64.b64encode(nonce).decode("ascii"),
        wrapped_key=base64.b64encode(wrapped).decode("ascii"),
    ).model_dump(mode="json")


def unwrap_vault_key(passphrase: str, values: dict) -> bytes:
    envelope = VaultKeyEnvelope(**values)
    wrapping_key = derive_vault_key(passphrase, envelope.salt)
    nonce = base64.b64decode(envelope.nonce, altchars=b"-_", validate=True)
    wrapped = base64.b64decode(
        envelope.wrapped_key, altchars=b"-_", validate=True
    )
    key = AESGCM(wrapping_key).decrypt(nonce, wrapped, VAULT_KEY_CONTEXT)
    if len(key) != 32:
        raise ValueError("unwrapped vault key has an invalid size")
    return key


def decrypt_record(envelope_values: dict, key: bytes) -> dict[str, str]:
    envelope = VaultEnvelope(**envelope_values)
    nonce = base64.b64decode(envelope.nonce, altchars=b"-_", validate=True)
    ciphertext = base64.b64decode(
        envelope.ciphertext, altchars=b"-_", validate=True
    )
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    if len(plaintext) > 1_000_000:
        raise ValueError("vault record is too large")
    values = json.loads(plaintext)
    if not isinstance(values, dict):
        raise ValueError("vault record must contain an object")
    username = values.get("username")
    password = values.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("vault record needs a username and password")
    if any(not isinstance(name, str) or not isinstance(value, str)
           for name, value in values.items()):
        raise ValueError("vault record fields must contain text")
    return dict(values)


def encrypt_record(envelope_values: dict, record: dict[str, str],
                   key: bytes) -> dict:
    envelope = VaultEnvelope(**envelope_values)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(record, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    updated = envelope.model_copy(update={
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })
    return updated.model_dump(mode="json")
