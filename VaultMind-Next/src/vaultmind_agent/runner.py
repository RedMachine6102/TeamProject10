from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vaultmind_next.automation import CredentialMaterial

from .adapters import VerifiedRotationExecutor
from .client import AgentApiClient
from .config import AgentConfig
from .vault import decrypt_record, derive_vault_key, encrypt_record, unwrap_vault_key


@dataclass(frozen=True)
class RotationOutcome:
    status: str
    job_id: str | None = None
    error_code: str | None = None


class TrustedAgentRunner:
    def __init__(self, config: AgentConfig, client: AgentApiClient,
                 executor: VerifiedRotationExecutor, pause_file: Path):
        self.config = config
        self.client = client
        self.executor = executor
        self.pause_file = pause_file

    def run_once(self, vault_passphrase: str) -> RotationOutcome:
        if self.pause_file.exists():
            return RotationOutcome("paused")
        jobs = self.client.available_jobs()
        job = next(
            (value for value in jobs
             if value.get("provider_id") in self.config.allowed_providers),
            None,
        )
        if job is None:
            return RotationOutcome("idle")
        job_id = str(job["job_id"])
        provider_id = str(job["provider_id"])
        self.client.claim(job_id)
        package = self.client.package(job_id)
        envelope = package["envelope"]
        try:
            key_envelope = package.get("vault_key_envelope")
            key = (
                unwrap_vault_key(vault_passphrase, key_envelope)
                if key_envelope else
                derive_vault_key(vault_passphrase, envelope["kdf_salt"])
            )
            record = decrypt_record(envelope, key)
        except Exception:
            self.client.fail(job_id, "vault_unlock_failed")
            return RotationOutcome("failed", job_id, "vault_unlock_failed")

        credential = CredentialMaterial(
            username=record["username"], current_password=record["password"]
        )
        result = self.executor.rotate(provider_id, credential)
        if not result.changed or not result.new_password:
            error = result.error_code or "provider_rotation_failed"
            self.client.fail(job_id, error)
            return RotationOutcome("failed", job_id, error)

        record["password"] = result.new_password
        rotated_envelope = encrypt_record(envelope, record, key)
        try:
            self.client.commit(job_id, rotated_envelope)
        except Exception:
            self.client.fail(job_id, "vault_commit_failed")
            return RotationOutcome("failed", job_id, "vault_commit_failed")
        finally:
            del credential
            del record
            del key
        return RotationOutcome("succeeded", job_id)
