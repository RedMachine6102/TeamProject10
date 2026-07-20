from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidTag

from vaultmind_next.automation import (
    CredentialMaterial,
    ProviderAdapter,
    RotationExecutor,
    generate_password,
)
from vaultmind_next.crypto import SecretBox
from vaultmind_next.models import (
    ApprovalMode,
    JobStatus,
    RotationInterval,
    RotationPolicyCreate,
    VaultEnvelope,
)
from vaultmind_next.rotation import next_rotation, require_transition
from vaultmind_next.storage import Database
from vaultmind_next.email import build_authorization_url, security_message
from vaultmind_next.auth import AttemptLimiter, PasskeyConfig, PasskeyManager
from vaultmind_next.scheduler import heartbeat_is_fresh, scan_interval, scan_once


def envelope(item_id: str = "item-0001") -> VaultEnvelope:
    return VaultEnvelope(
        item_id=item_id,
        provider_id="example",
        site_origin="https://example.com",
        kdf_salt="MDEyMzQ1Njc4OWFiY2RlZg==",
        nonce="MDEyMzQ1Njc4OWFi",
        ciphertext="Y2lwaGVydGV4dC1jaXBoZXJ0ZXh0",
    )


def test_secret_box_round_trip_and_context_binding():
    box, _ = SecretBox.generate()
    sealed = box.seal(b"oauth-token", "connection:123")
    assert box.open(sealed, "connection:123") == b"oauth-token"
    with pytest.raises(InvalidTag):
        box.open(sealed, "connection:456")


def test_vault_item_id_rejects_path_and_attribute_characters():
    values = envelope().model_dump()
    values["item_id"] = 'item"><script'
    with pytest.raises(ValueError, match="item_id"):
        VaultEnvelope(**values)


def test_rotation_intervals_and_state_machine():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert next_rotation(now, RotationInterval.DAYS_30) == now + timedelta(days=30)
    require_transition(JobStatus.PROPOSED, JobStatus.APPROVED)
    with pytest.raises(ValueError):
        require_transition(JobStatus.PROPOSED, JobStatus.SUCCEEDED)


def test_storage_creates_one_due_job_and_advances_after_success(tmp_path):
    database = Database(str(tmp_path / "test.db"))
    database.upsert_item(envelope())
    due = datetime.now(timezone.utc) - timedelta(minutes=1)
    database.put_policy(RotationPolicyCreate(
        item_id="item-0001", interval_days=RotationInterval.DAYS_30,
        approval_mode=ApprovalMode.MANUAL, next_due_at=due,
    ))
    jobs = database.create_due_jobs()
    assert len(jobs) == 1
    assert database.create_due_jobs() == []
    approved = database.transition_job(jobs[0].job_id, JobStatus.APPROVED)
    assert approved.status is JobStatus.APPROVED
    claimed = database.claim_job(jobs[0].job_id, "agent-0001")
    assert claimed.lease_owner == "agent-0001" and claimed.attempt_count == 1
    with pytest.raises(PermissionError):
        database.commit_agent_rotation(
            jobs[0].job_id, "agent-0002", envelope().model_copy(update={
                "nonce": "YWJjZGVmZ2hpamts",
                "ciphertext": "bmV3LWNpcGhlcnRleHQtYXV0aC10YWc=",
            })
        )
    invalid = envelope().model_copy(update={
        "provider_id": "other", "nonce": "YWJjZGVmZ2hpamts",
        "ciphertext": "bmV3LWNpcGhlcnRleHQtYXV0aC10YWc=",
    })
    with pytest.raises(ValueError):
        database.commit_agent_rotation(jobs[0].job_id, "agent-0001", invalid)
    assert database.list_jobs()[0].status is JobStatus.RUNNING
    assert database.list_items()[0].provider_id == "example"
    rotated = envelope().model_copy(update={
        "nonce": "YWJjZGVmZ2hpamts",
        "ciphertext": "bmV3LWNpcGhlcnRleHQtYXV0aC10YWc=",
    })
    with database._connection:
        database._connection.execute(
            "UPDATE rotation_jobs SET lease_expires_at=? WHERE job_id=?",
            (
                (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                jobs[0].job_id,
            ),
        )
    committed = database.commit_agent_rotation(
        jobs[0].job_id, "agent-0001", rotated
    )
    assert committed.job.status is JobStatus.SUCCEEDED
    repeated = database.commit_agent_rotation(
        jobs[0].job_id, "agent-0001", rotated
    )
    assert repeated.envelope.ciphertext == rotated.ciphertext
    with pytest.raises(ValueError, match="different result"):
        database.commit_agent_rotation(
            jobs[0].job_id, "agent-0001",
            rotated.model_copy(update={"nonce": "cXdlcnR5dWlvcGFz"}),
        )
    assert database.list_policies()[0].next_due_at > datetime.now(timezone.utc)
    verification = database.verify_audit_chain()
    assert verification.valid and verification.events_checked == 7


def test_expired_job_lease_can_only_be_reclaimed_by_its_agent(tmp_path):
    database = Database(str(tmp_path / "reclaim.db"))
    database.upsert_item(envelope())
    due = datetime.now(timezone.utc) - timedelta(minutes=1)
    database.put_policy(RotationPolicyCreate(
        item_id="item-0001", interval_days=RotationInterval.DAYS_30,
        approval_mode=ApprovalMode.MANUAL, next_due_at=due,
    ))
    job = database.create_due_jobs()[0]
    database.transition_job(job.job_id, JobStatus.APPROVED)
    claimed = database.claim_job(job.job_id, "agent-0001")
    assert claimed.attempt_count == 1
    assert database.list_available_jobs("agent-0001") == []

    with database._connection:
        database._connection.execute(
            "UPDATE rotation_jobs SET lease_expires_at=? WHERE job_id=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
             job.job_id),
        )

    assert database.list_available_jobs("agent-0002") == []
    assert database.list_available_jobs("agent-0001")[0].job_id == job.job_id
    with pytest.raises(PermissionError, match="different agent"):
        database.claim_job(job.job_id, "agent-0002")
    reclaimed = database.claim_job(job.job_id, "agent-0001")
    assert reclaimed.status is JobStatus.RUNNING
    assert reclaimed.attempt_count == 2
    assert reclaimed.lease_expires_at > datetime.now(timezone.utc)
    actions = [event.action for event in database.list_audit_events()]
    assert "rotation.job_reclaimed" in actions


class ExampleAdapter(ProviderAdapter):
    provider_id = "example"

    def rotate(self, credential: CredentialMaterial, new_password: str) -> bool:
        return credential.current_password == "old-password" and len(new_password) == 24


def test_executor_is_allowlisted_and_generates_strong_passwords():
    result = RotationExecutor([ExampleAdapter()]).execute(
        "example", CredentialMaterial("user", "old-password")
    )
    assert result.changed and result.new_password
    assert len(result.new_password) == 24
    unsupported = RotationExecutor([]).execute(
        "unknown", CredentialMaterial("user", "old-password")
    )
    assert unsupported.error_code == "provider_not_supported"
    assert len(generate_password(32)) == 32


def test_automatic_rotation_is_bound_to_a_current_agent_grant(tmp_path):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from vaultmind_next.models import AutomationGrantCreate, DeviceRegistration

    database = Database(str(tmp_path / "automatic.db"))
    database.upsert_item(envelope())
    now = datetime.now(timezone.utc)
    database.put_policy(RotationPolicyCreate(
        item_id="item-0001", interval_days=RotationInterval.DAYS_60,
        approval_mode=ApprovalMode.AUTOMATIC,
        next_due_at=now - timedelta(minutes=1),
    ))
    grant = AutomationGrantCreate(
        item_id="item-0001", agent_id="agent-0001",
        expires_at=now + timedelta(days=7),
    )
    with pytest.raises(ValueError, match="active trusted agent"):
        database.put_automation_grant(grant)
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    database.register_device(DeviceRegistration(
        device_id="agent-0001", display_name="Agent", platform="windows",
        public_key=base64.urlsafe_b64encode(key).decode("ascii"),
    ))
    database.put_automation_grant(grant)
    job = database.create_due_jobs(now)[0]
    assert job.status is JobStatus.APPROVED
    assert job.authorized_agent_id == "agent-0001"
    with pytest.raises(PermissionError):
        database.claim_job(job.job_id, "agent-0002")
    assert database.claim_job(job.job_id, "agent-0001").status is JobStatus.RUNNING


def test_device_revocation_removes_automation_authority(tmp_path):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from vaultmind_next.models import AutomationGrantCreate, DeviceRegistration

    database = Database(str(tmp_path / "revoke.db"))
    database.upsert_item(envelope())
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    database.register_device(DeviceRegistration(
        device_id="agent-0001", display_name="Agent", platform="test",
        public_key=base64.urlsafe_b64encode(key).decode("ascii"),
    ))
    database.put_automation_grant(AutomationGrantCreate(
        item_id="item-0001", agent_id="agent-0001",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    ))
    revoked = database.revoke_device("agent-0001")
    assert revoked.status == "revoked"
    assert database.list_automation_grants() == []
    with pytest.raises(ValueError, match="active trusted agent"):
        database.put_automation_grant(AutomationGrantCreate(
            item_id="item-0001", agent_id="agent-0001",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        ))
    with pytest.raises(KeyError):
        database.get_active_device_key("agent-0001")


def test_policy_and_grant_stops_cancel_waiting_automatic_jobs(tmp_path):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from vaultmind_next.models import AutomationGrantCreate, DeviceRegistration

    database = Database(str(tmp_path / "stops.db"))
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    database.register_device(DeviceRegistration(
        device_id="agent-0001", display_name="Agent", platform="windows",
        public_key=base64.urlsafe_b64encode(key).decode("ascii"),
    ))
    now = datetime.now(timezone.utc)
    for item_id in ("item-0001", "item-0002"):
        database.upsert_item(envelope(item_id))
        database.put_policy(RotationPolicyCreate(
            item_id=item_id, interval_days=RotationInterval.DAYS_30,
            approval_mode=ApprovalMode.AUTOMATIC,
            next_due_at=now - timedelta(minutes=1),
        ))
        database.put_automation_grant(AutomationGrantCreate(
            item_id=item_id, agent_id="agent-0001",
            expires_at=now + timedelta(days=30),
        ))
    jobs = database.create_due_jobs(now)
    assert all(job.status is JobStatus.APPROVED for job in jobs)

    database.put_policy(RotationPolicyCreate(
        item_id="item-0001", interval_days=RotationInterval.DAYS_30,
        approval_mode=ApprovalMode.AUTOMATIC, enabled=False,
        next_due_at=now - timedelta(minutes=1),
    ))
    database.revoke_automation_grant("item-0002")
    stopped = {job.item_id: job for job in database.list_jobs()}
    assert stopped["item-0001"].status is JobStatus.CANCELED
    assert stopped["item-0001"].error_code == "policy_disabled"
    assert stopped["item-0002"].status is JobStatus.CANCELED
    assert stopped["item-0002"].error_code == "automation_grant_revoked"


def test_expired_automation_grant_cannot_be_claimed(tmp_path):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from vaultmind_next.models import AutomationGrantCreate, DeviceRegistration

    database = Database(str(tmp_path / "expired-grant.db"))
    database.upsert_item(envelope())
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    database.register_device(DeviceRegistration(
        device_id="agent-0001", display_name="Agent", platform="windows",
        public_key=base64.urlsafe_b64encode(key).decode("ascii"),
    ))
    now = datetime.now(timezone.utc)
    database.put_policy(RotationPolicyCreate(
        item_id="item-0001", interval_days=RotationInterval.DAYS_30,
        approval_mode=ApprovalMode.AUTOMATIC,
        next_due_at=now - timedelta(minutes=1),
    ))
    database.put_automation_grant(AutomationGrantCreate(
        item_id="item-0001", agent_id="agent-0001",
        expires_at=now + timedelta(minutes=1),
    ))
    job = database.create_due_jobs(now)[0]
    with database._connection:
        database._connection.execute(
            "UPDATE automation_grants SET expires_at=? WHERE item_id=?",
            ((now - timedelta(seconds=1)).isoformat(), "item-0001"),
        )
    assert database.list_available_jobs("agent-0001") == []
    with pytest.raises(PermissionError, match="expired or revoked"):
        database.claim_job(job.job_id, "agent-0001")


def test_email_oauth_uses_pkce_and_metadata_only_scopes():
    url = build_authorization_url(
        "google", "client-id-12345", "https://vault.example/oauth/callback",
        "state-value-that-is-longer-than-thirty-two-characters",
        "challenge-value-that-is-long-enough-for-pkce-validation-123",
    )
    assert "code_challenge_method=S256" in url
    assert "gmail.metadata" in url
    assert "gmail.readonly" not in url
    assert security_message("Security alert: new sign-in", "account@example.com")
    assert not security_message("Your weekly newsletter", "news@example.com")


def test_passkey_options_require_user_verification_and_safe_origin():
    manager = PasskeyManager(PasskeyConfig.from_origin("http://localhost:8080"))
    options, challenge = manager.registration_options(
        b"0123456789abcdef", "owner@example.com", "Vault Owner"
    )
    assert len(challenge) >= 16
    assert options["rp"]["id"] == "localhost"
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    with pytest.raises(ValueError):
        PasskeyConfig.from_origin("http://127.0.0.1:8080")
    with pytest.raises(ValueError):
        PasskeyConfig.from_origin("http://vault.example")


def test_authentication_attempt_limiter_rejects_excess_attempts():
    limiter = AttemptLimiter(limit=2, window_seconds=300)
    assert limiter.allow("client")
    assert limiter.allow("client")
    assert not limiter.allow("client")


def test_scheduler_creates_due_job_once(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "scheduler.db"))
    database.upsert_item(envelope())
    database.put_policy(RotationPolicyCreate(
        item_id="item-0001", interval_days=RotationInterval.DAYS_90,
        approval_mode=ApprovalMode.MANUAL,
        next_due_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    ))
    assert scan_once(database) == 1
    assert scan_once(database) == 0
    monkeypatch.setenv("VAULTMIND_SCAN_SECONDS", "15")
    assert scan_interval() == 15
    monkeypatch.setenv("VAULTMIND_SCAN_SECONDS", "5")
    with pytest.raises(RuntimeError):
        scan_interval()


def test_scheduler_heartbeat_detects_stale_or_missing_worker(tmp_path):
    heartbeat = tmp_path / "scheduler.heartbeat"
    assert not heartbeat_is_fresh(heartbeat, interval_seconds=60, now=100)
    heartbeat.write_text("ready")
    os.utime(heartbeat, (100, 100))
    assert heartbeat_is_fresh(heartbeat, interval_seconds=60, now=249)
    assert not heartbeat_is_fresh(heartbeat, interval_seconds=60, now=251)


def test_expired_device_enrollment_cannot_register_agent(tmp_path):
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from vaultmind_next.models import DeviceEnrollmentRequest

    database = Database(str(tmp_path / "enrollment.db"))
    database.create_device_enrollment(
        "f" * 64, "owner-user",
        datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    public_key = base64.urlsafe_b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode("ascii")
    request = DeviceEnrollmentRequest(
        device_id="agent-expired", display_name="Expired Agent",
        public_key=public_key, platform="windows",
        enrollment_code="x" * 32,
    )
    with pytest.raises(ValueError, match="expired"):
        database.redeem_device_enrollment("f" * 64, request)
    assert database.list_devices() == []
