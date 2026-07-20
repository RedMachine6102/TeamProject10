from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from vaultmind_next.automation import CredentialMaterial, generate_password

from .adapters import VerifiedRotationExecutor
from .client import AgentApiClient
from .config import AgentConfig
from .recovery import PendingRotation, PendingRotationStore
from .vault import decrypt_record, derive_vault_key, encrypt_record, unwrap_vault_key


@dataclass(frozen=True)
class RotationOutcome:
    status: str
    job_id: str | None = None
    error_code: str | None = None


class TrustedAgentRunner:
    def __init__(self, config: AgentConfig, client: AgentApiClient,
                 executor: VerifiedRotationExecutor, pause_file: Path,
                 pending_store: PendingRotationStore):
        self.config = config
        self.client = client
        self.executor = executor
        self.pause_file = pause_file
        self.pending_store = pending_store

    def run_once(self, vault_passphrase: str) -> RotationOutcome:
        if self.pause_file.exists():
            return RotationOutcome("paused")
        pending = self.pending_store.load()
        if pending is not None:
            return self._resume_pending(pending)
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
            self._report_failure(job_id, "vault_unlock_failed")
            return RotationOutcome("failed", job_id, "vault_unlock_failed")

        old_password = record["password"]
        username = record["username"]
        new_password = generate_password()
        record["password"] = new_password
        rotated_envelope = encrypt_record(envelope, record, key)
        pending = PendingRotation(
            stage="prepared",
            job_id=job_id,
            provider_id=provider_id,
            username=username,
            old_password=old_password,
            new_password=new_password,
            envelope=rotated_envelope,
        )
        try:
            self.pending_store.save(pending)
        except Exception:
            error = "local_recovery_store_failed"
            self._report_failure(job_id, error)
            return RotationOutcome("failed", job_id, error)
        finally:
            del record
            del key

        credential = CredentialMaterial(username, old_password)
        result = self.executor.rotate_to(
            provider_id, credential, new_password
        )
        del credential
        if not result.changed:
            return self._resolve_prepared(
                pending, result.error_code or "provider_rotation_failed"
            )
        changed = replace(pending, stage="provider_changed")
        try:
            self.pending_store.save(changed)
        except Exception:
            return RotationOutcome(
                "recovery_required", job_id,
                "provider_changed_recovery_update_failed",
            )
        return self._commit_pending(changed)

    def _resume_pending(self, pending: PendingRotation) -> RotationOutcome:
        if pending.stage == "prepared":
            return self._resolve_prepared(pending, "rotation_interrupted")
        return self._commit_pending(pending)

    def _resolve_prepared(
        self, pending: PendingRotation, failure_code: str,
    ) -> RotationOutcome:
        if self.executor.verify(
            pending.provider_id, pending.username, pending.new_password
        ):
            changed = replace(pending, stage="provider_changed")
            try:
                self.pending_store.save(changed)
            except Exception:
                return RotationOutcome(
                    "recovery_required", pending.job_id,
                    "provider_changed_recovery_update_failed",
                )
            return self._commit_pending(changed)
        if self.executor.verify(
            pending.provider_id, pending.username, pending.old_password
        ):
            if self._report_failure(pending.job_id, failure_code):
                try:
                    self.pending_store.clear()
                except Exception:
                    return RotationOutcome(
                        "recovery_required", pending.job_id,
                        "local_recovery_clear_failed",
                    )
                return RotationOutcome(
                    "failed", pending.job_id, failure_code
                )
        return RotationOutcome(
            "recovery_required", pending.job_id,
            "provider_state_could_not_be_verified",
        )

    def _commit_pending(self, pending: PendingRotation) -> RotationOutcome:
        if pending.stage != "provider_changed":
            return RotationOutcome(
                "recovery_required", pending.job_id,
                "pending_rotation_not_verified",
            )
        if pending.provider_id not in self.config.allowed_providers:
            return RotationOutcome(
                "recovery_required", pending.job_id,
                "pending_provider_not_allowlisted",
            )
        for _ in range(3):
            try:
                self.client.commit(pending.job_id, pending.envelope)
                self.pending_store.clear()
                return RotationOutcome("succeeded", pending.job_id)
            except Exception:
                continue
        return RotationOutcome(
            "pending", pending.job_id, "vault_commit_pending"
        )

    def _report_failure(self, job_id: str, error_code: str) -> bool:
        try:
            self.client.fail(job_id, error_code)
            return True
        except Exception:
            return False
