from __future__ import annotations

import base64
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import urlparse

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True)
class PasskeyConfig:
    rp_id: str
    origin: str
    rp_name: str = "VaultMind"

    @classmethod
    def from_origin(cls, origin: str) -> "PasskeyConfig":
        parsed = urlparse(origin)
        if not parsed.hostname:
            raise ValueError("passkey origin needs a hostname")
        local = parsed.hostname == "localhost"
        if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
            raise ValueError("passkeys require HTTPS except on localhost")
        return cls(rp_id=parsed.hostname, origin=origin)


class PasskeyManager:
    def __init__(self, config: PasskeyConfig):
        self.config = config

    def registration_options(self, user_id: bytes, email: str,
                             display_name: str) -> tuple[dict, bytes]:
        options = generate_registration_options(
            rp_id=self.config.rp_id,
            rp_name=self.config.rp_name,
            user_id=user_id,
            user_name=email,
            user_display_name=display_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        return json.loads(options_to_json(options)), options.challenge

    def verify_registration(self, credential: dict, challenge: bytes):
        return verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            require_user_verification=True,
        )

    def authentication_options(self) -> tuple[dict, bytes]:
        options = generate_authentication_options(
            rp_id=self.config.rp_id,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return json.loads(options_to_json(options)), options.challenge

    def verify_authentication(self, credential: dict, challenge: bytes,
                              public_key: bytes, sign_count: int):
        return verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )


class AttemptLimiter:
    """Small single-process throttle for authentication endpoints."""

    def __init__(self, limit: int = 10, window_seconds: int = 300):
        self.limit = limit
        self.window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        attempts = self._attempts[key]
        while attempts and attempts[0] <= now - self.window_seconds:
            attempts.popleft()
        if len(attempts) >= self.limit:
            return False
        attempts.append(now)
        return True
