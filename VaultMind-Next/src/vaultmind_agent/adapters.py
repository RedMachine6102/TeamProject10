from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from vaultmind_next.automation import CredentialMaterial, generate_password

CHALLENGE_ID_PATTERN = re.compile(r"[A-Za-z0-9._~-]{16,256}")


@dataclass(frozen=True)
class PasswordChangeAttempt:
    changed: bool
    challenge_id: str | None = None


class EmailCodeSource(Protocol):
    def get_code(self, rotation_provider: str,
                 requested_after: datetime) -> str | None:
        ...


class TrustedProviderAdapter(ABC):
    provider_id: str

    @abstractmethod
    def change_password(self, credential: CredentialMaterial,
                        new_password: str) -> bool | PasswordChangeAttempt:
        raise NotImplementedError

    def complete_email_challenge(
        self, credential: CredentialMaterial, new_password: str,
        challenge_id: str, code: str,
    ) -> bool:
        return False

    @abstractmethod
    def verify_password(self, username: str, password: str) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class VerifiedRotation:
    changed: bool
    new_password: str | None = None
    error_code: str | None = None


class VerifiedRotationExecutor:
    def __init__(self, adapters: list[TrustedProviderAdapter],
                 code_source: EmailCodeSource | None = None):
        self._adapters = {adapter.provider_id: adapter for adapter in adapters}
        self._code_source = code_source

    def rotate(self, provider_id: str,
               credential: CredentialMaterial) -> VerifiedRotation:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            return VerifiedRotation(False, error_code="provider_not_allowlisted")
        new_password = generate_password()
        try:
            requested_at = datetime.now(timezone.utc)
            attempt = self._normalize_attempt(
                adapter.change_password(credential, new_password)
            )
            if attempt.challenge_id:
                if self._code_source is None:
                    return VerifiedRotation(
                        False, error_code="email_challenge_unavailable"
                    )
                code = self._code_source.get_code(provider_id, requested_at)
                if code is None:
                    return VerifiedRotation(
                        False, error_code="email_challenge_not_resolved"
                    )
                if not adapter.complete_email_challenge(
                    credential, new_password, attempt.challenge_id, code
                ):
                    return VerifiedRotation(
                        False, error_code="provider_rejected_challenge"
                    )
            elif not attempt.changed:
                return VerifiedRotation(False, error_code="provider_rejected_change")
            if not adapter.verify_password(credential.username, new_password):
                self._rollback(adapter, credential, new_password)
                return VerifiedRotation(False, error_code="new_password_not_verified")
        except Exception:
            return VerifiedRotation(False, error_code="provider_request_failed")
        return VerifiedRotation(True, new_password=new_password)

    @staticmethod
    def _normalize_attempt(
        result: bool | PasswordChangeAttempt,
    ) -> PasswordChangeAttempt:
        if isinstance(result, PasswordChangeAttempt):
            return result
        return PasswordChangeAttempt(changed=result)

    @classmethod
    def _rollback(adapter: TrustedProviderAdapter,
                  old: CredentialMaterial, new_password: str) -> bool:
        try:
            attempt = cls._normalize_attempt(adapter.change_password(
                CredentialMaterial(old.username, new_password),
                old.current_password,
            ))
            return (
                attempt.changed
                and not attempt.challenge_id
                and adapter.verify_password(old.username, old.current_password)
            )
        except Exception:
            return False


class HttpProviderAdapter(TrustedProviderAdapter):
    """Strict two-endpoint adapter for an allowlisted provider service."""

    def __init__(self, provider_id: str, base_url: str):
        self.provider_id = provider_id
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        local = parsed.hostname in {"localhost", "127.0.0.1"}
        if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
            raise ValueError("provider adapters require HTTPS except on localhost")
        if (not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError("provider adapter URL is invalid")

    def change_password(self, credential: CredentialMaterial,
                        new_password: str) -> PasswordChangeAttempt:
        result = self._post_json("/password/change", {
            "username": credential.username,
            "current_password": credential.current_password,
            "new_password": new_password,
        })
        if result.get("ok") is True:
            return PasswordChangeAttempt(True)
        challenge_id = result.get("challenge_id")
        if (
            result.get("challenge_required") is True
            and isinstance(challenge_id, str)
            and CHALLENGE_ID_PATTERN.fullmatch(challenge_id)
        ):
            return PasswordChangeAttempt(False, challenge_id)
        return PasswordChangeAttempt(False)

    def complete_email_challenge(
        self, credential: CredentialMaterial, new_password: str,
        challenge_id: str, code: str,
    ) -> bool:
        if (
            not CHALLENGE_ID_PATTERN.fullmatch(challenge_id)
            or not code.isdigit()
            or not 6 <= len(code) <= 8
        ):
            return False
        return self._post_ok("/password/challenge", {
            "username": credential.username,
            "current_password": credential.current_password,
            "new_password": new_password,
            "challenge_id": challenge_id,
            "code": code,
        })

    def verify_password(self, username: str, password: str) -> bool:
        return self._post_ok("/session/verify", {
            "username": username, "password": password,
        })

    def _post_ok(self, path: str, body: dict[str, str]) -> bool:
        return self._post_json(path, body).get("ok") is True

    def _post_json(self, path: str, body: dict[str, str]) -> dict:
        request = Request(
            f"{self.base_url}{path}",
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=20) as response:
                data = response.read(65_537)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError("provider adapter request failed") from exc
        if len(data) > 65_536:
            raise RuntimeError("provider adapter response was too large")
        try:
            result = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("provider adapter returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise RuntimeError("provider adapter returned invalid JSON")
        return result
