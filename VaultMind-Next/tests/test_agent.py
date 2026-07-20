import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from vaultmind_agent.adapters import TrustedProviderAdapter, VerifiedRotationExecutor
from vaultmind_agent.client import AgentApiClient, AgentApiError
from vaultmind_agent.config import AgentConfig
from vaultmind_agent.identity import DeviceIdentity
from vaultmind_agent.runner import TrustedAgentRunner
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

    def transport(path, body, headers):
        response = api.post(path, json=body, headers=headers)
        if response.status_code >= 400:
            raise AgentApiError(f"HTTP {response.status_code}")
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
    runner = TrustedAgentRunner(
        config, client, VerifiedRotationExecutor([adapter]), tmp_path / "PAUSED"
    )
    outcome = runner.run_once(PASSPHRASE)
    assert outcome.status == "succeeded"
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
    )
    assert runner.run_once(PASSPHRASE).status == "paused"
    assert calls == []
    pause_file.unlink()
    assert runner.run_once(PASSPHRASE).status == "idle"
    assert calls == ["/api/v1/agent/jobs/available"]


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
