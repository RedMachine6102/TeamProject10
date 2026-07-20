from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def signed_message(action: str, agent_id: str, timestamp: datetime,
                   nonce: str, values: dict[str, str | int | None]) -> bytes:
    payload = {
        "action": action,
        "agent_id": agent_id,
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "nonce": nonce,
        "values": values,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_signature(public_key: str, signature: str, message: bytes) -> bool:
    try:
        key_bytes = base64.b64decode(public_key, altchars=b"-_", validate=True)
        signature_bytes = base64.b64decode(signature, altchars=b"-_", validate=True)
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def payload_digest(values: dict) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
