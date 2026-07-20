from __future__ import annotations

import secrets
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialMaterial:
    username: str
    current_password: str


@dataclass(frozen=True)
class RotationResult:
    changed: bool
    new_password: str | None = None
    error_code: str | None = None


class ProviderAdapter(ABC):
    """Runs only on a trusted user device or isolated automation worker."""

    provider_id: str

    @abstractmethod
    def rotate(self, credential: CredentialMaterial, new_password: str) -> bool:
        raise NotImplementedError


def generate_password(length: int = 24) -> str:
    if length < 16:
        raise ValueError("rotated passwords must be at least 16 characters")
    groups = [string.ascii_lowercase, string.ascii_uppercase,
              string.digits, "!@#$%^&*_-+="]
    chars = [secrets.choice(group) for group in groups]
    pool = "".join(groups)
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class RotationExecutor:
    """Deterministic executor; AI output never receives provider authority."""

    def __init__(self, adapters: list[ProviderAdapter]):
        self._adapters = {adapter.provider_id: adapter for adapter in adapters}

    def execute(self, provider_id: str,
                credential: CredentialMaterial) -> RotationResult:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            return RotationResult(False, error_code="provider_not_supported")
        new_password = generate_password()
        try:
            changed = adapter.rotate(credential, new_password)
        except Exception:
            return RotationResult(False, error_code="provider_request_failed")
        if not changed:
            return RotationResult(False, error_code="provider_rejected_change")
        return RotationResult(True, new_password=new_password)
