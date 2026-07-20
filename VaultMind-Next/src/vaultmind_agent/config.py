from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse


def default_agent_directory() -> Path:
    base = os.getenv("LOCALAPPDATA")
    if not base:
        raise RuntimeError("LOCALAPPDATA is required for the Windows agent")
    return Path(base) / "VaultMind" / "Agent"


@dataclass
class AgentConfig:
    server_url: str
    agent_id: str
    allowed_providers: list[str] = field(default_factory=list)
    adapter_urls: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.server_url = self._safe_url(self.server_url)
        self.allowed_providers = sorted(set(self.allowed_providers))
        if not 8 <= len(self.agent_id) <= 128:
            raise ValueError("agent id must contain 8 to 128 characters")
        if not self.agent_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("agent id contains unsupported characters")
        for provider in self.allowed_providers:
            if not provider.replace("-", "").replace("_", "").isalnum():
                raise ValueError("provider id contains unsupported characters")
        for provider, url in self.adapter_urls.items():
            if provider not in self.allowed_providers:
                raise ValueError("adapter URL provider is not allowlisted")
            self.adapter_urls[provider] = self._safe_url(url)

    @staticmethod
    def _safe_url(value: str) -> str:
        value = value.rstrip("/")
        parsed = urlparse(value)
        local = parsed.hostname in {"localhost", "127.0.0.1"}
        if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
            raise ValueError("agent connections require HTTPS except on localhost")
        if (not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError("agent URL is invalid")
        return value

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(asdict(self), indent=2, sort_keys=True), encoding="utf-8"
        )
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        values = json.loads(path.read_text(encoding="utf-8"))
        return cls(**values)


@dataclass(frozen=True)
class AgentPaths:
    directory: Path

    @classmethod
    def default(cls) -> "AgentPaths":
        return cls(default_agent_directory())

    @property
    def config(self) -> Path:
        return self.directory / "config.json"

    @property
    def device_key(self) -> Path:
        return self.directory / "device.key"

    @property
    def pause_file(self) -> Path:
        return self.directory / "PAUSED"

    @property
    def email_credentials(self) -> Path:
        return self.directory / "email-credentials.dat"
