from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from vaultmind_next.automation import CredentialMaterial, generate_password


class TrustedProviderAdapter(ABC):
    provider_id: str

    @abstractmethod
    def change_password(self, credential: CredentialMaterial,
                        new_password: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def verify_password(self, username: str, password: str) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class VerifiedRotation:
    changed: bool
    new_password: str | None = None
    error_code: str | None = None


class VerifiedRotationExecutor:
    def __init__(self, adapters: list[TrustedProviderAdapter]):
        self._adapters = {adapter.provider_id: adapter for adapter in adapters}

    def rotate(self, provider_id: str,
               credential: CredentialMaterial) -> VerifiedRotation:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            return VerifiedRotation(False, error_code="provider_not_allowlisted")
        new_password = generate_password()
        try:
            if not adapter.change_password(credential, new_password):
                return VerifiedRotation(False, error_code="provider_rejected_change")
            if not adapter.verify_password(credential.username, new_password):
                self._rollback(adapter, credential, new_password)
                return VerifiedRotation(False, error_code="new_password_not_verified")
        except Exception:
            return VerifiedRotation(False, error_code="provider_request_failed")
        return VerifiedRotation(True, new_password=new_password)

    @staticmethod
    def _rollback(adapter: TrustedProviderAdapter,
                  old: CredentialMaterial, new_password: str) -> bool:
        try:
            changed = adapter.change_password(
                CredentialMaterial(old.username, new_password), old.current_password
            )
            return changed and adapter.verify_password(
                old.username, old.current_password
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
                        new_password: str) -> bool:
        return self._post("/password/change", {
            "username": credential.username,
            "current_password": credential.current_password,
            "new_password": new_password,
        })

    def verify_password(self, username: str, password: str) -> bool:
        return self._post("/session/verify", {
            "username": username, "password": password,
        })

    def _post(self, path: str, body: dict[str, str]) -> bool:
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
        return isinstance(result, dict) and result.get("ok") is True
