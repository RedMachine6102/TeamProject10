import base64
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaultmind_next.api import create_app
from vaultmind_next.device import payload_digest, signed_message
from vaultmind_next.email import OAuthTokens
from vaultmind_next.crypto import SecretBox
from vaultmind_next.auth import base64url
from vaultmind_agent.vault import wrap_vault_key

TOKEN = "test-token-with-more-than-thirty-two-characters"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def sample_item():
    return {
        "item_id": "item-0001",
        "provider_id": "example",
        "site_origin": "https://example.com",
        "kdf_salt": "MDEyMzQ1Njc4OWFiY2RlZg==",
        "nonce": "MDEyMzQ1Njc4OWFi",
        "ciphertext": "Y2lwaGVydGV4dC1jaXBoZXJ0ZXh0",
        "key_version": 1,
    }


def signed_request(private_key, action, values):
    timestamp = datetime.now(timezone.utc)
    nonce = secrets.token_urlsafe(18)
    message = signed_message(action, "agent-0001", timestamp, nonce, values)
    signature = base64.urlsafe_b64encode(private_key.sign(message)).decode("ascii")
    return {
        "agent_id": "agent-0001", "timestamp": timestamp.isoformat(),
        "nonce": nonce, "signature": signature,
    }


def test_api_requires_authentication_and_runs_rotation_flow(tmp_path):
    client = TestClient(create_app(str(tmp_path / "api.db"), TOKEN))
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health/ready").json() == {
        "status": "ready", "database": "ok",
    }
    assert client.get("/api/v1/dashboard").status_code == 401

    saved = client.put("/api/v1/vault/items", json=sample_item(), headers=HEADERS)
    assert saved.status_code == 200
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.urlsafe_b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")
    enrollment = client.post(
        "/api/v1/devices/enrollment-code", headers=HEADERS
    ).json()
    device_request = {
        "device_id": "agent-0001", "display_name": "Test Agent",
        "public_key": public_key, "platform": "test",
        "enrollment_code": enrollment["code"],
    }
    device = client.post("/api/v1/devices/enroll", json=device_request)
    assert device.status_code == 201
    assert client.post(
        "/api/v1/devices/enroll", json=device_request
    ).status_code == 400
    due = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    policy = client.put("/api/v1/rotation/policies", headers=HEADERS, json={
        "item_id": "item-0001", "interval_days": 30,
        "approval_mode": "manual", "enabled": True, "next_due_at": due,
    })
    assert policy.status_code == 200

    jobs = client.post("/api/v1/rotation/scan", headers=HEADERS).json()
    assert len(jobs) == 1 and jobs[0]["status"] == "proposed"
    job_id = jobs[0]["job_id"]
    assert client.post(
        f"/api/v1/rotation/jobs/{job_id}/approve", headers=HEADERS
    ).json()["status"] == "approved"
    available_request = signed_request(
        private_key, "rotation.available", {}
    )
    available = client.post(
        "/api/v1/agent/jobs/available", json=available_request
    )
    assert available.status_code == 200
    assert available.json()[0]["job_id"] == job_id
    claim_values = {"job_id": job_id, "lease_seconds": 300}
    claim_request = signed_request(private_key, "rotation.claim", claim_values)
    claim_request["lease_seconds"] = 300
    assert client.post(
        f"/api/v1/agent/jobs/{job_id}/claim",
        json=claim_request,
    ).json()["status"] == "running"
    assert client.post(
        f"/api/v1/agent/jobs/{job_id}/claim",
        json=claim_request,
    ).status_code == 409
    package_request = signed_request(
        private_key, "rotation.package", {"job_id": job_id}
    )
    package = client.post(
        f"/api/v1/agent/jobs/{job_id}/package", json=package_request
    )
    assert package.status_code == 200
    assert package.json()["envelope"]["ciphertext"] == sample_item()["ciphertext"]
    rotated = sample_item() | {
        "nonce": "YWJjZGVmZ2hpamts",
        "ciphertext": "bmV3LWNpcGhlcnRleHQtYXV0aC10YWc=",
    }
    commit_values = {
        "job_id": job_id, "envelope_sha256": payload_digest(rotated),
    }
    commit_request = signed_request(private_key, "rotation.commit", commit_values)
    commit_request["envelope"] = rotated
    committed = client.post(
        f"/api/v1/agent/jobs/{job_id}/commit", json=commit_request
    )
    assert committed.status_code == 200
    assert committed.json()["job"]["status"] == "succeeded"
    assert committed.json()["envelope"]["ciphertext"] == rotated["ciphertext"]

    summary = client.get("/api/v1/dashboard", headers=HEADERS).json()
    assert summary == {
        "vault_items": 1, "active_policies": 1,
        "rotations_due": 0, "jobs_needing_approval": 0,
    }
    verification = client.get("/api/v1/audit/verify", headers=HEADERS).json()
    assert verification["valid"] is True
    assert verification["events_checked"] == 9


def test_readiness_fails_closed_when_database_is_unavailable(tmp_path):
    application = create_app(str(tmp_path / "unavailable.db"), TOKEN)
    client = TestClient(application)
    application.state.database.close()
    response = client.get("/api/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "database": "failed"}


def test_owner_can_cancel_waiting_rotation(tmp_path):
    client = TestClient(create_app(str(tmp_path / "cancel.db"), TOKEN))
    assert client.put(
        "/api/v1/vault/items", json=sample_item(), headers=HEADERS
    ).status_code == 200
    due = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert client.put(
        "/api/v1/rotation/policies", headers=HEADERS,
        json={
            "item_id": "item-0001", "interval_days": 30,
            "approval_mode": "manual", "enabled": True,
            "next_due_at": due,
        },
    ).status_code == 200
    job = client.post(
        "/api/v1/rotation/scan", headers=HEADERS
    ).json()[0]
    canceled = client.post(
        f"/api/v1/rotation/jobs/{job['job_id']}/cancel", headers=HEADERS
    )
    assert canceled.status_code == 200
    assert canceled.json()["status"] == "canceled"
    assert client.post(
        f"/api/v1/rotation/jobs/{job['job_id']}/approve", headers=HEADERS
    ).status_code == 409


def test_vault_item_cannot_change_during_unfinished_rotation(tmp_path):
    client = TestClient(create_app(str(tmp_path / "item-guard.db"), TOKEN))
    item = sample_item()
    assert client.put(
        "/api/v1/vault/items", json=item, headers=HEADERS
    ).status_code == 200
    due = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert client.put(
        "/api/v1/rotation/policies", headers=HEADERS,
        json={
            "item_id": item["item_id"], "interval_days": 30,
            "approval_mode": "manual", "enabled": True,
            "next_due_at": due,
        },
    ).status_code == 200
    job = client.post(
        "/api/v1/rotation/scan", headers=HEADERS
    ).json()[0]

    assert client.put(
        "/api/v1/vault/items", json=item, headers=HEADERS
    ).status_code == 409
    assert client.delete(
        f"/api/v1/vault/items/{item['item_id']}", headers=HEADERS
    ).status_code == 409

    assert client.post(
        f"/api/v1/rotation/jobs/{job['job_id']}/cancel", headers=HEADERS
    ).status_code == 200
    assert client.delete(
        f"/api/v1/vault/items/{item['item_id']}", headers=HEADERS
    ).status_code == 204


def test_vault_key_envelope_is_opaque_and_can_be_rewrapped(tmp_path):
    database_path = tmp_path / "key-envelope.db"
    client = TestClient(create_app(str(database_path), TOKEN))
    data_key = bytes(range(32))
    first = wrap_vault_key("first secure vault passphrase", data_key)
    created = client.put(
        "/api/v1/vault/key-envelope", json=first, headers=HEADERS
    )
    assert created.status_code == 200
    assert client.get(
        "/api/v1/vault/key-envelope", headers=HEADERS
    ).json()["wrapped_key"] == first["wrapped_key"]

    second = wrap_vault_key("second secure vault passphrase", data_key)
    updated = client.put(
        "/api/v1/vault/key-envelope", json=second, headers=HEADERS
    )
    assert updated.status_code == 200
    assert updated.json()["wrapped_key"] != first["wrapped_key"]
    with sqlite3.connect(database_path) as connection:
        stored = connection.execute(
            "SELECT envelope FROM vault_key_envelopes WHERE singleton=1"
        ).fetchone()[0]
    assert "first secure vault passphrase" not in stored
    assert "second secure vault passphrase" not in stored
    assert base64.b64encode(data_key).decode("ascii") not in stored
    assert client.get("/api/v1/audit/verify", headers=HEADERS).json() == {
        "valid": True, "events_checked": 2, "first_invalid_sequence": None,
    }


class FakeOAuthClient:
    def exchange(self, provider, client_id, client_secret, code,
                 redirect_uri, code_verifier):
        assert provider.value == "google"
        assert client_id == "google-client-id"
        assert client_secret == "google-client-secret-value"
        assert code == "authorization-code"
        assert redirect_uri.startswith("https://vault.example/")
        assert len(code_verifier) >= 43
        return OAuthTokens(
            email_address="owner@example.com",
            access_token="access-token-that-must-stay-encrypted",
            refresh_token="refresh-token-that-must-stay-encrypted",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes=("openid", "email", "gmail.metadata"),
        )


def test_email_oauth_flow_encrypts_tokens_and_rejects_replay(tmp_path, monkeypatch):
    database_path = tmp_path / "oauth.db"
    _, encoded_key = SecretBox.generate()
    monkeypatch.setenv("VAULTMIND_ENV", "development")
    monkeypatch.setenv("VAULTMIND_ROOT_KEY", encoded_key)
    monkeypatch.setenv("VAULTMIND_PUBLIC_URL", "https://vault.example")
    monkeypatch.setenv("VAULTMIND_GOOGLE_CLIENT_ID", "google-client-id")
    monkeypatch.setenv(
        "VAULTMIND_GOOGLE_CLIENT_SECRET", "google-client-secret-value"
    )
    client = TestClient(
        create_app(str(database_path), TOKEN, FakeOAuthClient()),
        follow_redirects=False,
    )

    providers = client.get("/api/v1/email/providers", headers=HEADERS).json()
    assert providers[0]["provider"] == "google"
    assert providers[0]["configured"] is True
    started = client.post(
        "/api/v1/email/connections/google/start", headers=HEADERS
    )
    assert started.status_code == 200
    authorization_url = started.json()["authorization_url"]
    query = parse_qs(urlparse(authorization_url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert "code_verifier" not in query
    state = query["state"][0]

    callback = client.get(
        "/api/v1/email/oauth/callback",
        params={"provider": "google", "state": state,
                "code": "authorization-code"},
    )
    assert callback.status_code == 303
    assert callback.headers["location"].endswith("#connections")
    connections = client.get(
        "/api/v1/email/connections", headers=HEADERS
    ).json()
    assert connections[0]["email_address"] == "owner@example.com"
    assert connections[0]["status"] == "active"
    assert "access_token" not in connections[0]

    replay = client.get(
        "/api/v1/email/oauth/callback",
        params={"provider": "google", "state": state,
                "code": "authorization-code"},
    )
    assert replay.status_code == 400

    with sqlite3.connect(database_path) as connection:
        token_sealed = connection.execute(
            "SELECT token_sealed FROM email_connections WHERE provider='google'"
        ).fetchone()[0]
        assert "access-token-that-must-stay-encrypted" not in token_sealed
        assert connection.execute("SELECT COUNT(*) FROM oauth_states").fetchone()[0] == 0

    revoked = client.delete(
        "/api/v1/email/connections/google", headers=HEADERS
    ).json()
    assert revoked["status"] == "revoked"
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT token_sealed FROM email_connections WHERE provider='google'"
        ).fetchone()[0] is None


class FakePasskeyManager:
    challenge = b"passkey-challenge-value-32-bytes"
    credential_id = b"credential-id-value"
    public_key = b"credential-public-key-value"

    def registration_options(self, user_id, email, display_name):
        assert len(user_id) == 16
        assert email == "owner@example.com"
        assert display_name == "Vault Owner"
        return {
            "challenge": base64url(self.challenge),
            "rp": {"id": "vault.example", "name": "VaultMind"},
            "user": {"id": base64url(user_id), "name": email,
                     "displayName": display_name},
            "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
        }, self.challenge

    def verify_registration(self, credential, challenge):
        assert credential["id"] == base64url(self.credential_id)
        assert challenge == self.challenge
        return SimpleNamespace(
            credential_id=self.credential_id,
            credential_public_key=self.public_key,
            sign_count=0,
            credential_device_type=SimpleNamespace(value="single_device"),
            credential_backed_up=False,
        )

    def authentication_options(self):
        return {
            "challenge": base64url(self.challenge),
            "rpId": "vault.example",
            "userVerification": "required",
        }, self.challenge

    def verify_authentication(self, credential, challenge, public_key, sign_count):
        assert credential["id"] == base64url(self.credential_id)
        assert challenge == self.challenge
        assert public_key == self.public_key
        assert sign_count >= 0
        return SimpleNamespace(
            new_sign_count=sign_count + 1,
            credential_device_type=SimpleNamespace(value="single_device"),
            credential_backed_up=False,
        )


def test_passkey_bootstrap_session_origin_and_login_flow(tmp_path, monkeypatch):
    database_path = tmp_path / "passkey.db"
    monkeypatch.setenv("VAULTMIND_ENV", "development")
    monkeypatch.setenv("VAULTMIND_PUBLIC_URL", "https://vault.example")
    application = create_app(
        str(database_path), TOKEN, passkey_manager=FakePasskeyManager()
    )
    client = TestClient(
        application,
        base_url="https://vault.example",
    )
    assert client.get("/api/v1/auth/status").json() == {
        "owner_exists": False, "authenticated": False, "user": None,
    }
    owner = {"email_address": "owner@example.com", "display_name": "Vault Owner"}
    assert client.post(
        "/api/v1/auth/register/options", json=owner
    ).status_code == 401
    started = client.post(
        "/api/v1/auth/register/options", json=owner, headers=HEADERS
    ).json()
    credential = {
        "id": base64url(FakePasskeyManager.credential_id),
        "rawId": base64url(FakePasskeyManager.credential_id),
        "type": "public-key",
        "response": {"transports": ["internal"]},
    }
    finished = client.post(
        "/api/v1/auth/register/finish", headers=HEADERS,
        json={"ceremony_id": started["ceremony_id"], "credential": credential},
    )
    assert finished.status_code == 200
    assert finished.json()["authenticated"] is True
    session_token = client.cookies.get("vaultmind_session")
    assert session_token and "HttpOnly" in finished.headers["set-cookie"]
    assert "SameSite=strict" in finished.headers["set-cookie"]
    assert "Secure" in finished.headers["set-cookie"]
    assert client.get("/api/v1/dashboard").status_code == 200
    assert client.post("/api/v1/rotation/scan").status_code == 403
    origin = {"Origin": "https://vault.example"}
    assert client.post("/api/v1/rotation/scan", headers=origin).status_code == 200
    token_only = TestClient(application, base_url="https://vault.example")
    assert token_only.get(
        "/api/v1/dashboard", headers=HEADERS
    ).status_code == 401

    enrollment = client.post(
        "/api/v1/devices/enrollment-code", headers=origin
    )
    assert enrollment.status_code == 200
    enrollment_code = enrollment.json()["code"]
    with sqlite3.connect(database_path) as connection:
        stored_code = connection.execute(
            "SELECT code_hash FROM device_enrollment_codes"
        ).fetchone()[0]
        assert stored_code != enrollment_code
    agent_public_key = base64.urlsafe_b64encode(
        Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    ).decode("ascii")
    enrollment_request = {
        "device_id": "owner-agent-0001", "display_name": "Owner Agent",
        "public_key": agent_public_key, "platform": "windows",
        "enrollment_code": enrollment_code,
    }
    assert token_only.post(
        "/api/v1/devices/enroll", json=enrollment_request
    ).status_code == 201
    assert token_only.post(
        "/api/v1/devices/enroll", json=enrollment_request
    ).status_code == 400

    with sqlite3.connect(database_path) as connection:
        stored_hash = connection.execute(
            "SELECT token_hash FROM sessions"
        ).fetchone()[0]
        assert stored_hash != session_token
        assert connection.execute(
            "SELECT COUNT(*) FROM passkey_challenges"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM device_enrollment_codes"
        ).fetchone()[0] == 0
        assert enrollment_code not in str(connection.execute(
            "SELECT event_hash FROM audit_events"
        ).fetchall())

    assert client.post("/api/v1/auth/logout", headers=origin).status_code == 204
    assert client.get("/api/v1/dashboard").status_code == 401
    login = client.post("/api/v1/auth/login/options").json()
    signed_in = client.post(
        "/api/v1/auth/login/finish",
        json={"ceremony_id": login["ceremony_id"], "credential": credential},
    )
    assert signed_in.status_code == 200
    assert signed_in.json()["user"]["email_address"] == "owner@example.com"
    assert client.get("/api/v1/dashboard").status_code == 200
    revoked = client.post(
        "/api/v1/devices/owner-agent-0001/revoke", headers=origin
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT actor_id FROM audit_events WHERE action='device.revoked'"
        ).fetchone()[0] == signed_in.json()["user"]["user_id"]
    assert client.post(
        "/api/v1/auth/login/finish",
        headers=origin,
        json={"ceremony_id": login["ceremony_id"], "credential": credential},
    ).status_code == 401

    other_browser = TestClient(application, base_url="https://vault.example")
    other_login = other_browser.post("/api/v1/auth/login/options").json()
    assert other_browser.post(
        "/api/v1/auth/login/finish",
        json={"ceremony_id": other_login["ceremony_id"], "credential": credential},
    ).status_code == 200
    assert other_browser.get("/api/v1/dashboard").status_code == 200
    assert client.post("/api/v1/auth/logout-all", headers=origin).status_code == 204
    assert client.get("/api/v1/dashboard").status_code == 401
    assert other_browser.get("/api/v1/dashboard").status_code == 401
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute(
            "SELECT actor_id FROM audit_events WHERE action='auth.sessions_revoked'"
        ).fetchone()[0] == finished.json()["user"]["user_id"]
