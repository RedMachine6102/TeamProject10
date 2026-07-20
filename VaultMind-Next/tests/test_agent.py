import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from vaultmind_agent.adapters import TrustedProviderAdapter, VerifiedRotationExecutor
from vaultmind_agent.client import AgentApiClient, AgentApiError
from vaultmind_agent.cli import run_loop
from vaultmind_agent.config import AgentConfig
from vaultmind_agent.identity import DeviceIdentity
from vaultmind_agent.recovery import (
    DpapiPendingRotationStore,
    PendingRotation,
    PendingRotationStore,
)
from vaultmind_agent.runner import RotationOutcome, TrustedAgentRunner
from vaultmind_agent.vault import (
    decrypt_record, derive_vault_key, encrypt_record, unwrap_vault_key,
    wrap_vault_key,
)
from vaultmind_next.api import create_app
from vaultmind_next.automation import CredentialMaterial
from vaultmind_demo_provider.api import create_demo_provider

TOKEN = "test-token-with-more-than-thirty-two-characters"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
PASSPHRASE = "correct horse battery staple"
SALT = "MDEyMzQ1Njc4OWFiY2RlZg=="


class DemoAdapter(TrustedProviderAdapter):
    provider_id = "demo"

    def __init__(self, password: str = "old-password"):
        self.password = password

    def change_password(self, credential: CredentialMaterial,
                        new_password: str) -> bool:
        if credential.username != "owner@example.com":
            return False
        if credential.current_password != self.password:
            return False
        self.password = new_password
        return True

    def verify_password(self, username: str, password: str) -> bool:
        return username == "owner@example.com" and password == self.password


class ProviderPolicyAdapter(DemoAdapter):
    compatible_password = "Provider-Compatible-Password-42"

    def create_password(self) -> str:
        return self.compatible_password


class FakePendingRotationStore(PendingRotationStore):
    def __init__(self):
        self.pending: PendingRotation | None = None

    def load(self) -> PendingRotation | None:
        return self.pending

    def save(self, pending: PendingRotation) -> None:
        self.pending = pending

    def clear(self) -> None:
        self.pending = None


def encrypted_demo_envelope(key: bytes | None = None, key_version: int = 1) -> dict:
    base = {
        "item_id": "demo-item-0001", "provider_id": "demo",
        "site_origin": "https://demo.example", "kdf_salt": SALT,
        "nonce": "MDEyMzQ1Njc4OWFi",
        "ciphertext": "Y2lwaGVydGV4dC1jaXBoZXJ0ZXh0", "key_version": key_version,
    }
    key = key or derive_vault_key(PASSPHRASE, SALT)
    return encrypt_record(base, {
        "title": "Demo Account", "username": "owner@example.com",
        "password": "old-password",
    }, key)


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI test")
def test_device_identity_is_protected_by_windows_account(tmp_path):
    path = tmp_path / "device.key"
    identity = DeviceIdentity.generate("agent-0001")
    identity.save(path)
    assert identity.private_key.private_bytes_raw() not in path.read_bytes()
    loaded = DeviceIdentity.load("agent-0001", path)
    assert loaded.public_key == identity.public_key


def test_vault_encryption_round_trip_uses_fresh_ciphertext():
    envelope = encrypted_demo_envelope()
    key = derive_vault_key(PASSPHRASE, SALT)
    record = decrypt_record(envelope, key)
    assert record["password"] == "old-password"
    updated = encrypt_record(
        envelope, record | {"password": "new-password"}, key
    )
    assert updated["nonce"] != envelope["nonce"]
    assert decrypt_record(updated, key)["password"] == "new-password"


def test_vault_data_key_can_be_rewrapped_without_reencrypting_records():
    data_key = bytes(range(32))
    original = wrap_vault_key(PASSPHRASE, data_key)
    assert unwrap_vault_key(PASSPHRASE, original) == data_key
    with pytest.raises(Exception):
        unwrap_vault_key("wrong passphrase value", original)

    replacement = wrap_vault_key("a completely new vault passphrase", data_key)
    assert replacement["wrapped_key"] != original["wrapped_key"]
    assert unwrap_vault_key(
        "a completely new vault passphrase", replacement
    ) == data_key


def test_trusted_agent_completes_verified_atomic_rotation(tmp_path):
    app = create_app(str(tmp_path / "agent.db"), TOKEN)
    api = TestClient(app)
    identity = DeviceIdentity.generate("agent-0001")
    config = AgentConfig(
        server_url="http://localhost", agent_id="agent-0001",
        allowed_providers=["demo"],
    )
    lose_first_commit_response = True

    def transport(path, body, headers):
        nonlocal lose_first_commit_response
        response = api.post(path, json=body, headers=headers)
        if response.status_code >= 400:
            raise AgentApiError(f"HTTP {response.status_code}")
        if path.endswith("/commit") and lose_first_commit_response:
            lose_first_commit_response = False
            raise AgentApiError("commit response was lost")
        return response.json()

    client = AgentApiClient(config, identity, transport)
    enrollment = api.post(
        "/api/v1/devices/enrollment-code", headers=HEADERS
    ).json()
    client.register("Test Agent", enrollment["code"])
    data_key = bytes(range(32))
    key_envelope = wrap_vault_key(PASSPHRASE, data_key)
    assert api.put(
        "/api/v1/vault/key-envelope", json=key_envelope, headers=HEADERS
    ).status_code == 200
    envelope = encrypted_demo_envelope(data_key, key_version=2)
    assert api.put(
        "/api/v1/vault/items", json=envelope, headers=HEADERS
    ).status_code == 200
    due = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert api.put("/api/v1/rotation/policies", headers=HEADERS, json={
        "item_id": envelope["item_id"], "interval_days": 30,
        "approval_mode": "automatic", "enabled": True, "next_due_at": due,
    }).status_code == 200
    assert api.put("/api/v1/automation/grants", headers=HEADERS, json={
        "item_id": envelope["item_id"], "agent_id": identity.agent_id,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
    }).status_code == 200
    jobs = api.post("/api/v1/rotation/scan", headers=HEADERS).json()
    assert jobs[0]["status"] == "approved"

    adapter = DemoAdapter()
    pending_store = FakePendingRotationStore()
    runner = TrustedAgentRunner(
        config, client, VerifiedRotationExecutor([adapter]), tmp_path / "PAUSED",
        pending_store,
    )
    outcome = runner.run_once(PASSPHRASE)
    assert outcome.status == "succeeded"
    assert pending_store.load() is None
    assert adapter.password != "old-password"

    saved = api.get("/api/v1/vault/items", headers=HEADERS).json()[0]
    record = decrypt_record(saved, data_key)
    assert record["password"] == adapter.password
    job = api.get("/api/v1/rotation/jobs", headers=HEADERS).json()[0]
    assert job["status"] == "succeeded"
    assert api.get("/api/v1/audit/verify", headers=HEADERS).json()["valid"] is True


def test_agent_global_and_provider_kill_switches(tmp_path):
    identity = DeviceIdentity.generate("agent-0001")
    config = AgentConfig(
        server_url="http://localhost", agent_id="agent-0001",
        allowed_providers=["demo"],
    )
    calls = []

    def transport(path, body, headers):
        calls.append(path)
        if path.endswith("/available"):
            return [{"job_id": "other-job", "provider_id": "other"}]
        raise AssertionError("non-allowlisted job must not be claimed")

    pause_file = tmp_path / "PAUSED"
    pause_file.write_text("paused")
    runner = TrustedAgentRunner(
        config, AgentApiClient(config, identity, transport),
        VerifiedRotationExecutor([DemoAdapter()]), pause_file,
        FakePendingRotationStore(),
    )
    assert runner.run_once(PASSPHRASE).status == "paused"
    assert calls == []
    pause_file.unlink()
    assert runner.run_once(PASSPHRASE).status == "idle"
    assert calls == ["/api/v1/agent/jobs/available"]


def test_agent_rejects_job_ids_that_could_change_request_paths():
    identity = DeviceIdentity.generate("agent-0001")
    config = AgentConfig(
        server_url="http://localhost", agent_id="agent-0001",
        allowed_providers=["demo"],
    )
    client = AgentApiClient(
        config, identity,
        lambda path, body, headers: pytest.fail("transport must not be called"),
    )
    with pytest.raises(AgentApiError, match="job id"):
        client.claim("../admin/path")


def test_agent_requires_provider_adapters_to_run_locally():
    with pytest.raises(ValueError, match="local device"):
        AgentConfig(
            server_url="https://vault.example",
            agent_id="agent-0001",
            allowed_providers=["example"],
            adapter_urls={"example": "https://adapter.example"},
        )
    config = AgentConfig(
        server_url="https://vault.example",
        agent_id="agent-0001",
        allowed_providers=["example"],
        adapter_urls={"example": "http://127.0.0.1:8090"},
    )
    assert config.adapter_urls["example"] == "http://127.0.0.1:8090"


def test_provider_adapter_controls_compatible_password_generation():
    adapter = ProviderPolicyAdapter()
    executor = VerifiedRotationExecutor([adapter])
    result = executor.rotate(
        "demo", CredentialMaterial("owner@example.com", "old-password")
    )
    assert result.changed is True
    assert result.new_password == adapter.compatible_password
    assert adapter.password == adapter.compatible_password


def test_provider_adapter_rejects_invalid_generated_password():
    class InvalidPolicyAdapter(DemoAdapter):
        def create_password(self) -> str:
            return "too-short"

    result = VerifiedRotationExecutor([InvalidPolicyAdapter()]).rotate(
        "demo", CredentialMaterial("owner@example.com", "old-password")
    )
    assert result.changed is False
    assert result.error_code == "provider_password_policy_failed"


class RecoveringClient:
    def __init__(self):
        self.allow_commit = False
        self.available_calls = 0
        self.committed_envelope: dict | None = None
        self.failed_with: str | None = None

    def available_jobs(self) -> list[dict]:
        self.available_calls += 1
        return [{"job_id": "pending-job-0001", "provider_id": "demo"}]

    def claim(self, job_id: str) -> dict:
        return {}

    def package(self, job_id: str) -> dict:
        return {"envelope": encrypted_demo_envelope()}

    def commit(self, job_id: str, envelope: dict) -> dict:
        if not self.allow_commit:
            raise AgentApiError("temporary connection failure")
        self.committed_envelope = envelope
        return {}

    def fail(self, job_id: str, error_code: str) -> dict:
        self.failed_with = error_code
        return {}


def test_agent_resumes_encrypted_pending_commit_without_second_change(tmp_path):
    config = AgentConfig(
        server_url="http://localhost", agent_id="agent-0001",
        allowed_providers=["demo"],
    )
    client = RecoveringClient()
    adapter = DemoAdapter()
    store = FakePendingRotationStore()
    runner = TrustedAgentRunner(
        config, client, VerifiedRotationExecutor([adapter]), tmp_path / "PAUSED",
        store,
    )

    first = runner.run_once(PASSPHRASE)
    assert first.status == "pending"
    assert store.load() is not None
    changed_password = adapter.password

    client.allow_commit = True
    second = runner.run_once(PASSPHRASE)
    assert second.status == "succeeded"
    assert store.load() is None
    assert adapter.password == changed_password
    assert client.available_calls == 1
    saved = decrypt_record(
        client.committed_envelope, derive_vault_key(PASSPHRASE, SALT)
    )
    assert saved["password"] == changed_password


def test_agent_does_not_change_provider_without_recovery_record(tmp_path):
    class FailingStore(FakePendingRotationStore):
        def save(self, pending: PendingRotation) -> None:
            raise OSError("storage unavailable")

    config = AgentConfig(
        server_url="http://localhost", agent_id="agent-0001",
        allowed_providers=["demo"],
    )
    client = RecoveringClient()
    adapter = DemoAdapter()
    outcome = TrustedAgentRunner(
        config, client, VerifiedRotationExecutor([adapter]), tmp_path / "PAUSED",
        FailingStore(),
    ).run_once(PASSPHRASE)
    assert outcome.error_code == "local_recovery_store_failed"
    assert adapter.password == "old-password"
    assert client.failed_with == "local_recovery_store_failed"


def test_agent_resolves_crash_during_provider_change(tmp_path):
    new_password = "New-password-value-123!"
    key = derive_vault_key(PASSPHRASE, SALT)
    original = encrypted_demo_envelope()
    record = decrypt_record(original, key)
    rotated = encrypt_record(
        original, record | {"password": new_password}, key
    )
    store = FakePendingRotationStore()
    store.save(PendingRotation(
        stage="prepared",
        job_id="pending-job-0001",
        provider_id="demo",
        username="owner@example.com",
        old_password="old-password",
        new_password=new_password,
        envelope=rotated,
    ))
    client = RecoveringClient()
    client.allow_commit = True
    config = AgentConfig(
        server_url="http://localhost", agent_id="agent-0001",
        allowed_providers=["demo"],
    )
    outcome = TrustedAgentRunner(
        config, client,
        VerifiedRotationExecutor([DemoAdapter(new_password)]),
        tmp_path / "PAUSED", store,
    ).run_once(PASSPHRASE)
    assert outcome.status == "succeeded"
    assert store.load() is None
    assert client.available_calls == 0


def test_foreground_agent_stops_when_manual_recovery_is_required(monkeypatch):
    class SequenceRunner:
        def __init__(self):
            self.outcomes = [
                RotationOutcome("idle"),
                RotationOutcome(
                    "recovery_required", "pending-job-0001",
                    "provider_state_could_not_be_verified",
                ),
            ]

        def run_once(self, passphrase: str) -> RotationOutcome:
            return self.outcomes.pop(0)

    monkeypatch.setattr("vaultmind_agent.cli.time.sleep", lambda seconds: None)
    assert run_loop(SequenceRunner(), PASSPHRASE, 15) == 2
    with pytest.raises(ValueError, match="poll interval"):
        run_loop(SequenceRunner(), PASSPHRASE, 5)


def test_foreground_agent_retries_temporary_api_failure(monkeypatch, capsys):
    class FlakyRunner:
        calls = 0

        def run_once(self, passphrase: str) -> RotationOutcome:
            self.calls += 1
            if self.calls == 1:
                raise AgentApiError("temporary connection failure")
            return RotationOutcome(
                "recovery_required", "pending-job-0001",
                "provider_state_could_not_be_verified",
            )

    delays = []
    monkeypatch.setattr(
        "vaultmind_agent.cli.time.sleep", lambda seconds: delays.append(seconds)
    )
    assert run_loop(FlakyRunner(), PASSPHRASE, 15) == 2
    assert delays == [15]
    assert "retrying in 15 seconds" in capsys.readouterr().err


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI test")
def test_pending_rotation_is_protected_by_windows_account(tmp_path):
    path = tmp_path / "pending-rotation.dat"
    pending = PendingRotation(
        stage="provider_changed",
        job_id="pending-job-0001",
        provider_id="demo",
        username="owner@example.com",
        old_password="old-password",
        new_password="New-password-value-123!",
        envelope=encrypted_demo_envelope(),
    )
    store = DpapiPendingRotationStore(path)
    store.save(pending)
    protected = path.read_bytes()
    assert pending.old_password.encode() not in protected
    assert pending.new_password.encode() not in protected
    assert store.load() == pending
    store.clear()
    assert not path.exists()


def test_demo_provider_changes_and_verifies_without_storing_plaintext():
    provider = TestClient(create_demo_provider(
        "owner@example.com", "old-password-value"
    ))
    changed = provider.post("/password/change", json={
        "username": "owner@example.com",
        "current_password": "old-password-value",
        "new_password": "New-password-value-123!",
    })
    assert changed.json() == {"ok": True}
    assert provider.post("/session/verify", json={
        "username": "owner@example.com", "password": "old-password-value",
    }).json() == {"ok": False}
    assert provider.post("/session/verify", json={
        "username": "owner@example.com", "password": "New-password-value-123!",
    }).json() == {"ok": True}


def test_demo_provider_requires_and_completes_email_challenge():
    provider = TestClient(create_demo_provider(
        "owner@example.com", "old-password-value", "482951"
    ))
    request = {
        "username": "owner@example.com",
        "current_password": "old-password-value",
        "new_password": "New-password-value-123!",
    }
    change = provider.post("/password/change", json=request).json()
    assert change["ok"] is False
    assert change["challenge_required"] is True
    assert provider.post("/session/verify", json={
        "username": "owner@example.com",
        "password": "old-password-value",
    }).json() == {"ok": True}

    challenge = request | {"challenge_id": change["challenge_id"]}
    assert provider.post(
        "/password/challenge", json=challenge | {"code": "111111"}
    ).json() == {"ok": False}
    assert provider.post(
        "/password/challenge", json=challenge | {"code": "482951"}
    ).json() == {"ok": True}
    assert provider.post("/session/verify", json={
        "username": "owner@example.com",
        "password": "New-password-value-123!",
    }).json() == {"ok": True}
