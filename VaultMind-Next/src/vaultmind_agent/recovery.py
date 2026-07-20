from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path

from vaultmind_next.models import VaultEnvelope

from .identity import protect_for_current_user, unprotect_for_current_user


@dataclass(frozen=True)
class PendingRotation:
    stage: str
    job_id: str
    provider_id: str
    username: str
    old_password: str
    new_password: str
    envelope: dict

    def __post_init__(self) -> None:
        if self.stage not in {"prepared", "provider_changed"}:
            raise ValueError("pending rotation stage is invalid")
        if (
            not 8 <= len(self.job_id) <= 128
            or not self.job_id.replace("-", "").replace("_", "").isalnum()
        ):
            raise ValueError("pending rotation job id is invalid")
        if (
            not 2 <= len(self.provider_id) <= 80
            or not self.provider_id.replace("-", "").replace("_", "").isalnum()
        ):
            raise ValueError("pending rotation provider id is invalid")
        if not 1 <= len(self.username) <= 320:
            raise ValueError("pending rotation username is invalid")
        if not 1 <= len(self.old_password) <= 1024:
            raise ValueError("pending rotation old password is invalid")
        if not 16 <= len(self.new_password) <= 1024:
            raise ValueError("pending rotation new password is invalid")
        validated = VaultEnvelope(**self.envelope)
        if validated.provider_id != self.provider_id:
            raise ValueError("pending rotation provider does not match its envelope")


class PendingRotationStore(ABC):
    @abstractmethod
    def load(self) -> PendingRotation | None:
        raise NotImplementedError

    @abstractmethod
    def save(self, pending: PendingRotation) -> None:
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> None:
        raise NotImplementedError


class DpapiPendingRotationStore(PendingRotationStore):
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> PendingRotation | None:
        if not self.path.exists():
            return None
        if self.path.stat().st_size > 2_000_000:
            raise ValueError("stored pending rotation is too large")
        raw = unprotect_for_current_user(self.path.read_bytes())
        try:
            values = json.loads(raw)
        finally:
            del raw
        if not isinstance(values, dict):
            raise ValueError("stored pending rotation is invalid")
        return PendingRotation(**values)

    def save(self, pending: PendingRotation) -> None:
        raw = json.dumps(asdict(pending), separators=(",", ":")).encode("utf-8")
        try:
            protected = protect_for_current_user(raw)
        finally:
            del raw
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_bytes(protected)
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
