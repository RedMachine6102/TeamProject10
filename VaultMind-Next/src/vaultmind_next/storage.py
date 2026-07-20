from __future__ import annotations

import json
import hashlib
import hmac
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import (
    ApprovalMode,
    AIRecommendation,
    AgentJobPackage,
    AutomationGrant,
    AutomationGrantCreate,
    AuditEvent,
    AuditVerification,
    DeviceRegistration,
    DeviceEnrollmentRequest,
    EmailConnection,
    EmailConnectionStatus,
    EmailSecurityEvent,
    JobStatus,
    RegisteredDevice,
    RotationJob,
    RotationPolicy,
    RotationPolicyCreate,
    RotationCommitResult,
    SessionUser,
    StoredVaultEnvelope,
    StoredVaultKeyEnvelope,
    VaultEnvelope,
    VaultKeyEnvelope,
)
from .rotation import next_rotation, require_transition


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class PendingOAuth:
    provider: str
    redirect_uri: str
    verifier_sealed: str
    expires_at: datetime


@dataclass(frozen=True)
class PendingPasskeyChallenge:
    purpose: str
    user_id: str | None
    email_address: str | None
    display_name: str | None
    challenge: str
    expires_at: datetime


@dataclass(frozen=True)
class StoredPasskey:
    credential_id: str
    user: SessionUser
    public_key: str
    sign_count: int


class Database:
    def __init__(self, path: str):
        db_path = Path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._create_schema()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS vault_items (
                    item_id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    site_origin TEXT NOT NULL,
                    envelope TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vault_key_envelopes (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    envelope TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rotation_policies (
                    item_id TEXT PRIMARY KEY REFERENCES vault_items(item_id) ON DELETE CASCADE,
                    interval_days INTEGER NOT NULL CHECK(interval_days IN (30, 60, 90)),
                    approval_mode TEXT NOT NULL CHECK(approval_mode IN ('manual', 'automatic')),
                    enabled INTEGER NOT NULL,
                    next_due_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rotation_jobs (
                    job_id TEXT PRIMARY KEY,
                    item_id TEXT NOT NULL REFERENCES vault_items(item_id) ON DELETE CASCADE,
                    provider_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    due_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error_code TEXT,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    authorized_agent_id TEXT
                );
                CREATE INDEX IF NOT EXISTS jobs_status_index
                    ON rotation_jobs(status, due_at);
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    details TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS automation_grants (
                    item_id TEXT PRIMARY KEY REFERENCES vault_items(item_id) ON DELETE CASCADE,
                    agent_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS device_nonces (
                    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
                    nonce TEXT NOT NULL,
                    used_at TEXT NOT NULL,
                    PRIMARY KEY(device_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS device_enrollment_codes (
                    code_hash TEXT PRIMARY KEY,
                    created_by TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state_hash TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    verifier_sealed TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS email_connections (
                    provider TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL UNIQUE,
                    email_address TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    token_sealed TEXT,
                    token_expires_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS email_security_events (
                    event_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source_domain TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ai_recommendations (
                    recommendation_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE REFERENCES email_security_events(event_id),
                    action TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    model TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email_address TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS passkeys (
                    credential_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    public_key TEXT NOT NULL,
                    sign_count INTEGER NOT NULL,
                    device_type TEXT NOT NULL,
                    backed_up INTEGER NOT NULL,
                    transports TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS passkey_challenges (
                    ceremony_hash TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL CHECK(purpose IN ('register', 'authenticate')),
                    user_id TEXT,
                    email_address TEXT,
                    display_name TEXT,
                    challenge TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_expiry_index
                    ON sessions(expires_at);
                """
            )

    def owner_exists(self) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM users WHERE status='active' LIMIT 1"
        ).fetchone()
        return row is not None

    def is_ready(self) -> bool:
        try:
            with self._lock:
                result = self._connection.execute(
                    "PRAGMA quick_check(1)"
                ).fetchone()
                self._connection.execute("SELECT 1").fetchone()
            return result is not None and result[0] == "ok"
        except sqlite3.DatabaseError:
            return False

    def create_passkey_challenge(
        self, ceremony_hash: str, purpose: str, challenge: str,
        expires_at: datetime, user_id: str | None = None,
        email_address: str | None = None, display_name: str | None = None,
    ) -> None:
        if purpose not in {"register", "authenticate"}:
            raise ValueError("passkey challenge purpose is invalid")
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM passkey_challenges WHERE expires_at<=?", (_iso(now),)
            )
            self._connection.execute(
                """INSERT INTO passkey_challenges
                   (ceremony_hash, purpose, user_id, email_address, display_name,
                    challenge, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ceremony_hash, purpose, user_id, email_address, display_name,
                 challenge, _iso(expires_at), _iso(now)),
            )

    def consume_passkey_challenge(self, ceremony_hash: str,
                                  purpose: str) -> PendingPasskeyChallenge:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM passkey_challenges WHERE ceremony_hash=?",
                (ceremony_hash,),
            ).fetchone()
            if row is not None:
                self._connection.execute(
                    "DELETE FROM passkey_challenges WHERE ceremony_hash=?",
                    (ceremony_hash,),
                )
            if row is None or row["purpose"] != purpose:
                raise ValueError("passkey ceremony is invalid or was already used")
            if _time(row["expires_at"]) <= now:
                raise ValueError("passkey ceremony expired")
            return PendingPasskeyChallenge(
                purpose=row["purpose"], user_id=row["user_id"],
                email_address=row["email_address"],
                display_name=row["display_name"], challenge=row["challenge"],
                expires_at=_time(row["expires_at"]),
            )

    def register_owner_passkey(
        self, user_id: str, email_address: str, display_name: str,
        credential_id: str, public_key: str, sign_count: int,
        device_type: str, backed_up: bool, transports: list[str],
    ) -> SessionUser:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            if self._connection.execute(
                "SELECT 1 FROM users WHERE status='active' LIMIT 1"
            ).fetchone():
                raise ValueError("the owner account is already configured")
            self._connection.execute(
                """INSERT INTO users
                   (user_id, email_address, display_name, status, created_at, updated_at)
                   VALUES (?, ?, ?, 'active', ?, ?)""",
                (user_id, email_address, display_name, _iso(now), _iso(now)),
            )
            self._connection.execute(
                """INSERT INTO passkeys
                   (credential_id, user_id, public_key, sign_count, device_type,
                    backed_up, transports, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (credential_id, user_id, public_key, sign_count, device_type,
                 int(backed_up), json.dumps(transports), _iso(now)),
            )
            self._append_audit(
                user_id, "auth.owner_registered", "user", user_id,
                {"credential_id": credential_id, "backed_up": backed_up}, now,
            )
        return SessionUser(
            user_id=user_id, email_address=email_address,
            display_name=display_name,
        )

    def get_passkey(self, credential_id: str) -> StoredPasskey:
        row = self._connection.execute(
            """SELECT p.*, u.email_address, u.display_name
               FROM passkeys p JOIN users u ON u.user_id=p.user_id
               WHERE p.credential_id=? AND u.status='active'""",
            (credential_id,),
        ).fetchone()
        if row is None:
            raise KeyError("passkey does not exist")
        return StoredPasskey(
            credential_id=row["credential_id"],
            user=SessionUser(
                user_id=row["user_id"], email_address=row["email_address"],
                display_name=row["display_name"],
            ),
            public_key=row["public_key"], sign_count=row["sign_count"],
        )

    def update_passkey_use(self, credential_id: str, sign_count: int,
                           device_type: str, backed_up: bool) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            result = self._connection.execute(
                """UPDATE passkeys SET sign_count=?, device_type=?, backed_up=?,
                   last_used_at=? WHERE credential_id=?""",
                (sign_count, device_type, int(backed_up), _iso(now), credential_id),
            )
            if result.rowcount != 1:
                raise KeyError("passkey does not exist")

    def create_session(self, token_hash: str, user_id: str,
                       expires_at: datetime) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM sessions WHERE expires_at<=?", (_iso(now),)
            )
            self._connection.execute(
                """INSERT INTO sessions
                   (token_hash, user_id, expires_at, created_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (token_hash, user_id, _iso(expires_at), _iso(now), _iso(now)),
            )
            self._append_audit(
                user_id, "auth.session_created", "user", user_id,
                {"expires_at": _iso(expires_at)}, now,
            )

    def get_session_user(self, token_hash: str) -> SessionUser:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT s.expires_at, u.user_id, u.email_address, u.display_name
                   FROM sessions s JOIN users u ON u.user_id=s.user_id
                   WHERE s.token_hash=? AND u.status='active'""",
                (token_hash,),
            ).fetchone()
            if row is None or _time(row["expires_at"]) <= now:
                if row is not None:
                    self._connection.execute(
                        "DELETE FROM sessions WHERE token_hash=?", (token_hash,)
                    )
                raise KeyError("session is invalid or expired")
            self._connection.execute(
                "UPDATE sessions SET last_seen_at=? WHERE token_hash=?",
                (_iso(now), token_hash),
            )
        return SessionUser(
            user_id=row["user_id"], email_address=row["email_address"],
            display_name=row["display_name"],
        )

    def delete_session(self, token_hash: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM sessions WHERE token_hash=?", (token_hash,)
            )

    def delete_user_sessions(self, user_id: str) -> int:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            result = self._connection.execute(
                "DELETE FROM sessions WHERE user_id=?", (user_id,)
            )
            removed = result.rowcount
            self._append_audit(
                user_id, "auth.sessions_revoked", "user", user_id,
                {"sessions_revoked": removed}, now,
            )
        return removed

    def create_oauth_state(self, state_hash: str, provider: str,
                           redirect_uri: str, verifier_sealed: str,
                           expires_at: datetime) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM oauth_states WHERE expires_at<=?", (_iso(now),)
            )
            self._connection.execute(
                """INSERT INTO oauth_states
                   (state_hash, provider, redirect_uri, verifier_sealed,
                    expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)""",
                (state_hash, provider, redirect_uri, verifier_sealed,
                 _iso(expires_at), _iso(now)),
            )
            self._append_audit(
                "api", "email.connection_started", "email_provider", provider,
                {"expires_at": _iso(expires_at)}, now,
            )

    def consume_oauth_state(self, state_hash: str, provider: str) -> PendingOAuth:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM oauth_states WHERE state_hash=?", (state_hash,)
            ).fetchone()
            if row is not None:
                self._connection.execute(
                    "DELETE FROM oauth_states WHERE state_hash=?", (state_hash,)
                )
            if row is None or row["provider"] != provider:
                raise ValueError("OAuth state is invalid or was already used")
            if _time(row["expires_at"]) <= now:
                raise ValueError("OAuth state expired")
            return PendingOAuth(
                provider=row["provider"], redirect_uri=row["redirect_uri"],
                verifier_sealed=row["verifier_sealed"],
                expires_at=_time(row["expires_at"]),
            )

    def upsert_email_connection(self, provider: str, email_address: str,
                                scopes: list[str], token_sealed: str,
                                token_expires_at: datetime) -> EmailConnection:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT connection_id, created_at FROM email_connections WHERE provider=?",
                (provider,),
            ).fetchone()
            connection_id = existing["connection_id"] if existing else str(uuid.uuid4())
            created_at = _time(existing["created_at"]) if existing else now
            self._connection.execute(
                """INSERT INTO email_connections
                   (provider, connection_id, email_address, scopes, token_sealed,
                    token_expires_at, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
                   ON CONFLICT(provider) DO UPDATE SET
                     email_address=excluded.email_address,
                     scopes=excluded.scopes,
                     token_sealed=excluded.token_sealed,
                     token_expires_at=excluded.token_expires_at,
                     status='active', updated_at=excluded.updated_at""",
                (provider, connection_id, email_address, json.dumps(scopes),
                 token_sealed, _iso(token_expires_at), _iso(created_at), _iso(now)),
            )
            self._append_audit(
                "email-oauth", "email.connection_linked", "email_connection",
                connection_id, {"provider": provider}, now,
            )
        return EmailConnection(
            connection_id=connection_id, provider=provider,
            email_address=email_address, scopes=scopes,
            status=EmailConnectionStatus.ACTIVE,
            token_expires_at=token_expires_at, created_at=created_at,
            updated_at=now,
        )

    def list_email_connections(self) -> list[EmailConnection]:
        rows = self._connection.execute(
            "SELECT * FROM email_connections ORDER BY provider"
        ).fetchall()
        return [self._email_connection_from_row(row) for row in rows]

    def revoke_email_connection(self, provider: str) -> EmailConnection:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM email_connections WHERE provider=?", (provider,)
            ).fetchone()
            if row is None:
                raise KeyError("email connection does not exist")
            self._connection.execute(
                """UPDATE email_connections
                   SET status='revoked', token_sealed=NULL, updated_at=?
                   WHERE provider=?""",
                (_iso(now), provider),
            )
            self._append_audit(
                "api", "email.connection_revoked", "email_connection",
                row["connection_id"], {"provider": provider}, now,
            )
            updated = self._connection.execute(
                "SELECT * FROM email_connections WHERE provider=?", (provider,)
            ).fetchone()
        return self._email_connection_from_row(updated)

    def active_email_credentials(self) -> list[dict[str, object]]:
        rows = self._connection.execute(
            """SELECT provider, scopes, token_sealed, token_expires_at
               FROM email_connections
               WHERE status='active' AND token_sealed IS NOT NULL"""
        ).fetchall()
        return [{
            "provider": row["provider"],
            "scopes": json.loads(row["scopes"]),
            "token_sealed": row["token_sealed"],
            "token_expires_at": _time(row["token_expires_at"]),
        } for row in rows]

    def update_email_token(self, provider: str, token_sealed: str,
                           expires_at: datetime) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            result = self._connection.execute(
                """UPDATE email_connections SET token_sealed=?, token_expires_at=?,
                   updated_at=? WHERE provider=? AND status='active'""",
                (token_sealed, _iso(expires_at), _iso(now), provider),
            )
            if result.rowcount != 1:
                raise KeyError("active email connection does not exist")

    def save_email_security_events(self, events: list[EmailSecurityEvent]) -> int:
        inserted = 0
        with self._lock, self._connection:
            for event in events:
                result = self._connection.execute(
                    """INSERT OR IGNORE INTO email_security_events
                       (event_id, provider, category, source_domain,
                        occurred_at, detected_at) VALUES (?, ?, ?, ?, ?, ?)""",
                    (event.event_id, event.provider, event.category,
                     event.source_domain, _iso(event.occurred_at),
                     _iso(event.detected_at)),
                )
                inserted += result.rowcount
        return inserted

    def list_email_security_events(self, limit: int = 100) -> list[EmailSecurityEvent]:
        rows = self._connection.execute(
            """SELECT * FROM email_security_events
               ORDER BY occurred_at DESC LIMIT ?""", (max(1, min(limit, 500)),)
        ).fetchall()
        return [EmailSecurityEvent(
            event_id=row["event_id"], provider=row["provider"],
            category=row["category"], source_domain=row["source_domain"],
            occurred_at=_time(row["occurred_at"]),
            detected_at=_time(row["detected_at"]),
        ) for row in rows]

    def unplanned_email_events(self, limit: int = 25) -> list[EmailSecurityEvent]:
        rows = self._connection.execute(
            """SELECT e.* FROM email_security_events e
               LEFT JOIN ai_recommendations r ON r.event_id=e.event_id
               WHERE r.event_id IS NULL ORDER BY e.occurred_at LIMIT ?""",
            (max(1, min(limit, 100)),),
        ).fetchall()
        return [EmailSecurityEvent(**{
            "event_id": row["event_id"], "provider": row["provider"],
            "category": row["category"], "source_domain": row["source_domain"],
            "occurred_at": _time(row["occurred_at"]),
            "detected_at": _time(row["detected_at"]),
        }) for row in rows]

    def save_ai_recommendation(self, value: AIRecommendation) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT OR IGNORE INTO ai_recommendations
                   (recommendation_id, event_id, action, risk, reason_code,
                    model, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (value.recommendation_id, value.event_id, value.action, value.risk,
                 value.reason_code, value.model, _iso(value.created_at)),
            )

    def list_ai_recommendations(self, limit: int = 100) -> list[AIRecommendation]:
        rows = self._connection.execute(
            "SELECT * FROM ai_recommendations ORDER BY created_at DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return [AIRecommendation(
            recommendation_id=row["recommendation_id"], event_id=row["event_id"],
            action=row["action"], risk=row["risk"], reason_code=row["reason_code"],
            model=row["model"], created_at=_time(row["created_at"]),
        ) for row in rows]

    def upsert_item(self, item: VaultEnvelope) -> StoredVaultEnvelope:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            first = self._connection.execute(
                "SELECT envelope FROM vault_items WHERE item_id<>? LIMIT 1",
                (item.item_id,),
            ).fetchone()
            if first and json.loads(first["envelope"])["kdf_salt"] != item.kdf_salt:
                raise ValueError("all items in a vault must use the same KDF salt")
            existing = self._connection.execute(
                "SELECT created_at FROM vault_items WHERE item_id=?", (item.item_id,)
            ).fetchone()
            if existing and self._connection.execute(
                """SELECT 1 FROM rotation_jobs
                   WHERE item_id=?
                     AND status IN ('proposed', 'approved', 'running', 'failed')
                   LIMIT 1""",
                (item.item_id,),
            ).fetchone():
                raise ValueError(
                    "vault item cannot change while a rotation job is unfinished"
                )
            created = _time(existing["created_at"]) if existing else now
            self._connection.execute(
                """INSERT INTO vault_items
                   (item_id, provider_id, site_origin, envelope, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(item_id) DO UPDATE SET
                     provider_id=excluded.provider_id,
                     site_origin=excluded.site_origin,
                     envelope=excluded.envelope,
                     updated_at=excluded.updated_at""",
                (item.item_id, item.provider_id, item.site_origin,
                 item.model_dump_json(), _iso(created), _iso(now)),
            )
            self._append_audit(
                "api", "vault.item_saved", "vault_item", item.item_id,
                {"provider_id": item.provider_id, "key_version": item.key_version}, now,
            )
        return StoredVaultEnvelope(**item.model_dump(), created_at=created, updated_at=now)

    def put_vault_key_envelope(self, envelope: VaultKeyEnvelope,
                               actor_id: str) -> StoredVaultKeyEnvelope:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            existed = self._connection.execute(
                "SELECT 1 FROM vault_key_envelopes WHERE singleton=1"
            ).fetchone() is not None
            self._connection.execute(
                """INSERT INTO vault_key_envelopes (singleton, envelope, updated_at)
                   VALUES (1, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                     envelope=excluded.envelope, updated_at=excluded.updated_at""",
                (envelope.model_dump_json(), _iso(now)),
            )
            self._append_audit(
                actor_id,
                "vault.key_rewrapped" if existed else "vault.key_created",
                "vault_key", "primary",
                {"key_version": envelope.key_version, "kdf": envelope.kdf}, now,
            )
        return StoredVaultKeyEnvelope(
            **envelope.model_dump(), updated_at=now
        )

    def get_vault_key_envelope(self) -> StoredVaultKeyEnvelope:
        row = self._connection.execute(
            "SELECT envelope, updated_at FROM vault_key_envelopes WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise KeyError("vault key is not configured")
        return StoredVaultKeyEnvelope(
            **json.loads(row["envelope"]), updated_at=_time(row["updated_at"])
        )

    def list_items(self) -> list[StoredVaultEnvelope]:
        rows = self._connection.execute(
            "SELECT envelope, created_at, updated_at FROM vault_items ORDER BY updated_at DESC"
        ).fetchall()
        return [self._envelope_from_row(row) for row in rows]

    def delete_item(self, item_id: str) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT provider_id FROM vault_items WHERE item_id=?", (item_id,)
            ).fetchone()
            if row is None:
                raise KeyError("vault item does not exist")
            if self._connection.execute(
                """SELECT 1 FROM rotation_jobs
                   WHERE item_id=?
                     AND status IN ('proposed', 'approved', 'running', 'failed')
                   LIMIT 1""",
                (item_id,),
            ).fetchone():
                raise ValueError(
                    "vault item cannot be deleted while a rotation job is unfinished"
                )
            self._append_audit(
                "api", "vault.item_deleted", "vault_item", item_id,
                {"provider_id": row["provider_id"]}, now,
            )
            self._connection.execute("DELETE FROM vault_items WHERE item_id=?", (item_id,))

    def put_policy(self, request: RotationPolicyCreate) -> RotationPolicy:
        now = datetime.now(timezone.utc)
        due = request.next_due_at or next_rotation(now, request.interval_days)
        with self._lock, self._connection:
            if not self._connection.execute(
                    "SELECT 1 FROM vault_items WHERE item_id=?", (request.item_id,)).fetchone():
                raise KeyError("vault item does not exist")
            self._connection.execute(
                """INSERT INTO rotation_policies
                   (item_id, interval_days, approval_mode, enabled, next_due_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(item_id) DO UPDATE SET
                     interval_days=excluded.interval_days,
                     approval_mode=excluded.approval_mode,
                     enabled=excluded.enabled,
                     next_due_at=excluded.next_due_at,
                     updated_at=excluded.updated_at""",
                (request.item_id, int(request.interval_days), request.approval_mode.value,
                 int(request.enabled), _iso(due), _iso(now)),
            )
            self._append_audit(
                "api", "rotation.policy_saved", "vault_item", request.item_id,
                {"interval_days": int(request.interval_days),
                 "approval_mode": request.approval_mode.value,
                 "enabled": request.enabled}, now,
            )
            if not request.enabled:
                self._cancel_waiting_jobs(
                    request.item_id, "policy_disabled", now
                )
        values = request.model_dump(exclude={"next_due_at"})
        return RotationPolicy(**values, next_due_at=due, updated_at=now)

    def list_policies(self) -> list[RotationPolicy]:
        rows = self._connection.execute(
            "SELECT * FROM rotation_policies ORDER BY next_due_at"
        ).fetchall()
        return [RotationPolicy(
            item_id=row["item_id"], interval_days=row["interval_days"],
            approval_mode=ApprovalMode(row["approval_mode"]), enabled=bool(row["enabled"]),
            next_due_at=_time(row["next_due_at"]), updated_at=_time(row["updated_at"]),
        ) for row in rows]

    def put_automation_grant(self, request: AutomationGrantCreate) -> AutomationGrant:
        now = datetime.now(timezone.utc)
        if request.expires_at.astimezone(timezone.utc) <= now:
            raise ValueError("automation grant must expire in the future")
        with self._lock, self._connection:
            if not self._connection.execute(
                    "SELECT 1 FROM vault_items WHERE item_id=?", (request.item_id,)).fetchone():
                raise KeyError("vault item does not exist")
            if not self._connection.execute(
                """SELECT 1 FROM devices
                   WHERE device_id=? AND status='active'""",
                (request.agent_id,),
            ).fetchone():
                raise ValueError(
                    "automation grant requires an active trusted agent"
                )
            existing = self._connection.execute(
                "SELECT created_at FROM automation_grants WHERE item_id=?",
                (request.item_id,),
            ).fetchone()
            created = _time(existing["created_at"]) if existing else now
            self._connection.execute(
                """INSERT INTO automation_grants
                   (item_id, agent_id, expires_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(item_id) DO UPDATE SET
                     agent_id=excluded.agent_id,
                     expires_at=excluded.expires_at,
                     updated_at=excluded.updated_at""",
                (request.item_id, request.agent_id, _iso(request.expires_at),
                 _iso(created), _iso(now)),
            )
            self._append_audit(
                "api", "automation.grant_saved", "vault_item", request.item_id,
                {"agent_id": request.agent_id,
                 "expires_at": _iso(request.expires_at)}, now,
            )
        return AutomationGrant(
            **request.model_dump(), created_at=created, updated_at=now
        )

    def list_automation_grants(self) -> list[AutomationGrant]:
        rows = self._connection.execute(
            "SELECT * FROM automation_grants ORDER BY expires_at"
        ).fetchall()
        return [AutomationGrant(
            item_id=row["item_id"], agent_id=row["agent_id"],
            expires_at=_time(row["expires_at"]), created_at=_time(row["created_at"]),
            updated_at=_time(row["updated_at"]),
        ) for row in rows]

    def revoke_automation_grant(self, item_id: str) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT agent_id FROM automation_grants WHERE item_id=?", (item_id,)
            ).fetchone()
            if row is None:
                raise KeyError("automation grant does not exist")
            self._append_audit(
                "api", "automation.grant_revoked", "vault_item", item_id,
                {"agent_id": row["agent_id"]}, now,
            )
            self._connection.execute(
                "DELETE FROM automation_grants WHERE item_id=?", (item_id,)
            )
            self._cancel_waiting_jobs(
                item_id, "automation_grant_revoked", now, row["agent_id"]
            )

    def _cancel_waiting_jobs(
        self, item_id: str, error_code: str, now: datetime,
        agent_id: str | None = None,
    ) -> None:
        query = (
            """SELECT job_id, status FROM rotation_jobs
               WHERE item_id=? AND status IN ('proposed', 'approved')"""
        )
        parameters: tuple[str, ...] = (item_id,)
        if agent_id is not None:
            query += " AND authorized_agent_id=?"
            parameters = (item_id, agent_id)
        rows = self._connection.execute(query, parameters).fetchall()
        for row in rows:
            self._connection.execute(
                """UPDATE rotation_jobs
                   SET status='canceled', updated_at=?, error_code=?
                   WHERE job_id=?""",
                (_iso(now), error_code, row["job_id"]),
            )
            self._append_audit(
                "api", "rotation.job_canceled", "rotation_job", row["job_id"],
                {"previous_status": row["status"], "error_code": error_code},
                now,
            )

    def create_device_enrollment(self, code_hash: str, created_by: str,
                                 expires_at: datetime) -> None:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM device_enrollment_codes WHERE expires_at<=?", (_iso(now),)
            )
            self._connection.execute(
                """INSERT INTO device_enrollment_codes
                   (code_hash, created_by, expires_at, created_at)
                   VALUES (?, ?, ?, ?)""",
                (code_hash, created_by, _iso(expires_at), _iso(now)),
            )
            self._append_audit(
                created_by, "device.enrollment_created", "device_enrollment",
                code_hash[:12], {"expires_at": _iso(expires_at)}, now,
            )

    def redeem_device_enrollment(self, code_hash: str,
                                 request: DeviceEnrollmentRequest) -> RegisteredDevice:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            code = self._connection.execute(
                "SELECT * FROM device_enrollment_codes WHERE code_hash=?",
                (code_hash,),
            ).fetchone()
            if code is None:
                raise ValueError("device enrollment code is invalid or was already used")
            if _time(code["expires_at"]) <= now:
                self._connection.execute(
                    "DELETE FROM device_enrollment_codes WHERE code_hash=?", (code_hash,)
                )
                raise ValueError("device enrollment code expired")
            if self._connection.execute(
                    "SELECT 1 FROM devices WHERE device_id=?",
                    (request.device_id,),
            ).fetchone():
                raise ValueError("device id is already registered")
            self._connection.execute(
                """INSERT INTO devices
                   (device_id, display_name, public_key, platform, status,
                    created_at, last_seen_at) VALUES (?, ?, ?, ?, 'active', ?, ?)""",
                (request.device_id, request.display_name, request.public_key,
                 request.platform, _iso(now), _iso(now)),
            )
            self._connection.execute(
                "DELETE FROM device_enrollment_codes WHERE code_hash=?", (code_hash,)
            )
            self._append_audit(
                request.device_id, "device.registered", "device", request.device_id,
                {"display_name": request.display_name,
                 "platform": request.platform, "enrolled_by": code["created_by"]}, now,
            )
        values = request.model_dump(exclude={"enrollment_code"})
        return RegisteredDevice(
            **values, status="active", created_at=now, last_seen_at=now
        )

    def register_device(self, request: DeviceRegistration) -> RegisteredDevice:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            if self._connection.execute(
                    "SELECT 1 FROM devices WHERE device_id=?", (request.device_id,)).fetchone():
                raise ValueError("device id is already registered")
            self._connection.execute(
                """INSERT INTO devices
                   (device_id, display_name, public_key, platform, status,
                    created_at, last_seen_at) VALUES (?, ?, ?, ?, 'active', ?, ?)""",
                (request.device_id, request.display_name, request.public_key,
                 request.platform, _iso(now), _iso(now)),
            )
            self._append_audit(
                "api", "device.registered", "device", request.device_id,
                {"display_name": request.display_name, "platform": request.platform}, now,
            )
        return RegisteredDevice(
            **request.model_dump(), status="active", created_at=now, last_seen_at=now
        )

    def list_devices(self) -> list[RegisteredDevice]:
        rows = self._connection.execute(
            "SELECT * FROM devices ORDER BY created_at"
        ).fetchall()
        return [RegisteredDevice(
            device_id=row["device_id"], display_name=row["display_name"],
            public_key=row["public_key"], platform=row["platform"],
            status=row["status"], created_at=_time(row["created_at"]),
            last_seen_at=_time(row["last_seen_at"]),
        ) for row in rows]

    def get_active_device_key(self, device_id: str) -> str:
        row = self._connection.execute(
            "SELECT public_key FROM devices WHERE device_id=? AND status='active'",
            (device_id,),
        ).fetchone()
        if row is None:
            raise KeyError("active device does not exist")
        return row["public_key"]

    def revoke_device(self, device_id: str,
                      actor_id: str = "api") -> RegisteredDevice:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if row is None:
                raise KeyError("device does not exist")
            self._connection.execute(
                "UPDATE devices SET status='revoked', last_seen_at=? WHERE device_id=?",
                (_iso(now), device_id),
            )
            self._connection.execute(
                "DELETE FROM automation_grants WHERE agent_id=?", (device_id,)
            )
            self._append_audit(
                actor_id, "device.revoked", "device", device_id,
                {"automation_grants_removed": True}, now,
            )
        return RegisteredDevice(
            device_id=row["device_id"], display_name=row["display_name"],
            public_key=row["public_key"], platform=row["platform"],
            status="revoked", created_at=_time(row["created_at"]), last_seen_at=now,
        )

    def consume_device_nonce(self, device_id: str, nonce: str) -> None:
        if not 16 <= len(nonce) <= 128:
            raise ValueError("nonce length is invalid")
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    "INSERT INTO device_nonces(device_id, nonce, used_at) VALUES (?, ?, ?)",
                    (device_id, nonce, _iso(now)),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("signed request nonce was already used") from exc
            self._connection.execute(
                "UPDATE devices SET last_seen_at=? WHERE device_id=?",
                (_iso(now), device_id),
            )

    def create_due_jobs(self, now: datetime | None = None) -> list[RotationJob]:
        now = now or datetime.now(timezone.utc)
        rows = self._connection.execute(
            """SELECT p.*, v.provider_id, d.device_id AS grant_agent,
                      g.expires_at AS grant_expires
               FROM rotation_policies p
               JOIN vault_items v ON v.item_id=p.item_id
               LEFT JOIN automation_grants g ON g.item_id=p.item_id
               LEFT JOIN devices d
                 ON d.device_id=g.agent_id AND d.status='active'
               WHERE p.enabled=1 AND p.next_due_at<=?""", (_iso(now),)
        ).fetchall()
        created: list[RotationJob] = []
        with self._lock, self._connection:
            for row in rows:
                open_job = self._connection.execute(
                    """SELECT 1 FROM rotation_jobs WHERE item_id=?
                       AND status IN ('proposed', 'approved', 'running')""",
                    (row["item_id"],),
                ).fetchone()
                if open_job:
                    continue
                automatic = (
                    row["approval_mode"] == ApprovalMode.AUTOMATIC.value
                    and row["grant_agent"] is not None
                    and _time(row["grant_expires"]) > now
                )
                initial_status = JobStatus.APPROVED if automatic else JobStatus.PROPOSED
                job = RotationJob(
                    job_id=str(uuid.uuid4()), item_id=row["item_id"],
                    provider_id=row["provider_id"], status=initial_status,
                    due_at=_time(row["next_due_at"]), created_at=now, updated_at=now,
                    authorized_agent_id=row["grant_agent"] if automatic else None,
                )
                self._connection.execute(
                    """INSERT INTO rotation_jobs
                       (job_id, item_id, provider_id, status, due_at, created_at, updated_at,
                        authorized_agent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (job.job_id, job.item_id, job.provider_id, job.status.value,
                     _iso(job.due_at), _iso(now), _iso(now), job.authorized_agent_id),
                )
                self._append_audit(
                    "scheduler",
                    "rotation.job_auto_approved" if automatic else "rotation.job_proposed",
                    "rotation_job", job.job_id,
                    {"item_id": job.item_id, "provider_id": job.provider_id}, now,
                )
                created.append(job)
        return created

    def list_jobs(self) -> list[RotationJob]:
        rows = self._connection.execute(
            "SELECT * FROM rotation_jobs ORDER BY created_at DESC"
        ).fetchall()
        return [self._job_from_row(row) for row in rows]

    def list_available_jobs(self, agent_id: str) -> list[RotationJob]:
        now = datetime.now(timezone.utc)
        rows = self._connection.execute(
            """SELECT * FROM rotation_jobs
               WHERE (
                   (status='approved'
                    AND (authorized_agent_id IS NULL OR authorized_agent_id=?))
                   OR
                   (status='running' AND lease_owner=?
                    AND lease_expires_at IS NOT NULL AND lease_expires_at<=?)
                 )
                 AND (
                   authorized_agent_id IS NULL OR EXISTS (
                     SELECT 1 FROM automation_grants g
                     JOIN devices d
                       ON d.device_id=g.agent_id AND d.status='active'
                     WHERE g.item_id=rotation_jobs.item_id
                       AND g.agent_id=rotation_jobs.authorized_agent_id
                       AND g.expires_at>?
                   )
                 )
               ORDER BY due_at LIMIT 50""",
            (agent_id, agent_id, _iso(now), _iso(now)),
        ).fetchall()
        return [self._job_from_row(row) for row in rows]

    def get_agent_job_package(self, job_id: str,
                              agent_id: str) -> AgentJobPackage:
        now = datetime.now(timezone.utc)
        row = self._connection.execute(
            "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None:
            raise KeyError("rotation job does not exist")
        if row["status"] != JobStatus.RUNNING.value or row["lease_owner"] != agent_id:
            raise PermissionError("rotation job is not leased to this agent")
        if not row["lease_expires_at"] or _time(row["lease_expires_at"]) <= now:
            raise PermissionError("rotation job lease expired")
        item = self._connection.execute(
            """SELECT envelope, created_at, updated_at FROM vault_items
               WHERE item_id=?""",
            (row["item_id"],),
        ).fetchone()
        if item is None:
            raise KeyError("vault item does not exist")
        try:
            key_envelope = self.get_vault_key_envelope()
        except KeyError:
            key_envelope = None
        return AgentJobPackage(
            job=self._job_from_row(row), envelope=self._envelope_from_row(item),
            vault_key_envelope=key_envelope,
        )

    def commit_agent_rotation(self, job_id: str, agent_id: str,
                              envelope: VaultEnvelope) -> RotationCommitResult:
        now = datetime.now(timezone.utc)
        with self._lock, self._connection:
            job_row = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if job_row is None:
                raise KeyError("rotation job does not exist")
            if job_row["status"] == JobStatus.SUCCEEDED.value:
                item_row = self._connection.execute(
                    """SELECT envelope, created_at, updated_at FROM vault_items
                       WHERE item_id=?""",
                    (job_row["item_id"],),
                ).fetchone()
                completed = self._connection.execute(
                    """SELECT actor_id FROM audit_events
                       WHERE action='rotation.job_succeeded' AND target_id=?
                       ORDER BY sequence DESC LIMIT 1""",
                    (job_id,),
                ).fetchone()
                current = VaultEnvelope(**json.loads(item_row["envelope"]))
                if (
                    completed is not None
                    and completed["actor_id"] == agent_id
                    and current == envelope
                ):
                    return RotationCommitResult(
                        job=self._job_from_row(job_row),
                        envelope=self._envelope_from_row(item_row),
                    )
                raise ValueError(
                    "rotation is already completed with a different result"
                )
            if (job_row["status"] != JobStatus.RUNNING.value
                    or job_row["lease_owner"] != agent_id):
                raise PermissionError("rotation job is not leased to this agent")
            if envelope.item_id != job_row["item_id"]:
                raise ValueError("rotated envelope does not match the job item")

            item_row = self._connection.execute(
                "SELECT * FROM vault_items WHERE item_id=?", (envelope.item_id,)
            ).fetchone()
            if item_row is None:
                raise KeyError("vault item does not exist")
            current = VaultEnvelope(**json.loads(item_row["envelope"]))
            if (envelope.provider_id != current.provider_id
                    or envelope.site_origin != current.site_origin
                    or envelope.kdf_salt != current.kdf_salt
                    or envelope.key_version != current.key_version):
                raise ValueError("rotation may only replace encrypted credential contents")
            if envelope.nonce == current.nonce or envelope.ciphertext == current.ciphertext:
                raise ValueError("rotation must provide fresh encrypted credential contents")

            self._connection.execute(
                """UPDATE vault_items SET envelope=?, updated_at=? WHERE item_id=?""",
                (envelope.model_dump_json(), _iso(now), envelope.item_id),
            )
            self._append_audit(
                agent_id, "vault.item_rotated", "vault_item", envelope.item_id,
                {"provider_id": envelope.provider_id,
                 "key_version": envelope.key_version}, now,
            )
            self._connection.execute(
                """UPDATE rotation_jobs SET status='succeeded', updated_at=?,
                   error_code=NULL, lease_owner=NULL, lease_expires_at=NULL
                   WHERE job_id=?""",
                (_iso(now), job_id),
            )
            self._append_audit(
                agent_id, "rotation.job_succeeded", "rotation_job", job_id,
                {"previous_status": JobStatus.RUNNING.value, "error_code": None}, now,
            )
            policy = self._connection.execute(
                "SELECT interval_days FROM rotation_policies WHERE item_id=?",
                (envelope.item_id,),
            ).fetchone()
            if policy:
                next_due = next_rotation(now, policy["interval_days"])
                self._connection.execute(
                    """UPDATE rotation_policies SET next_due_at=?, updated_at=?
                       WHERE item_id=?""",
                    (_iso(next_due), _iso(now), envelope.item_id),
                )
            updated_job = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            updated_item = self._connection.execute(
                """SELECT envelope, created_at, updated_at FROM vault_items
                   WHERE item_id=?""",
                (envelope.item_id,),
            ).fetchone()
        return RotationCommitResult(
            job=self._job_from_row(updated_job),
            envelope=self._envelope_from_row(updated_item),
        )

    def transition_job(self, job_id: str, target: JobStatus,
                       error_code: str | None = None,
                       actor_id: str = "api") -> RotationJob:
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError("rotation job does not exist")
            current = JobStatus(row["status"])
            require_transition(current, target)
            now = datetime.now(timezone.utc)
            self._connection.execute(
                "UPDATE rotation_jobs SET status=?, updated_at=?, error_code=? WHERE job_id=?",
                (target.value, _iso(now), error_code, job_id),
            )
            self._append_audit(
                actor_id, f"rotation.job_{target.value}", "rotation_job", job_id,
                {"previous_status": current.value, "error_code": error_code}, now,
            )
            if target is JobStatus.SUCCEEDED:
                policy = self._connection.execute(
                    "SELECT interval_days FROM rotation_policies WHERE item_id=?",
                    (row["item_id"],),
                ).fetchone()
                if policy:
                    next_due = next_rotation(now, policy["interval_days"])
                    self._connection.execute(
                        "UPDATE rotation_policies SET next_due_at=?, updated_at=? WHERE item_id=?",
                        (_iso(next_due), _iso(now), row["item_id"]),
                    )
            updated = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        return self._job_from_row(updated)

    def claim_job(self, job_id: str, agent_id: str,
                  lease_seconds: int = 300) -> RotationJob:
        if not 30 <= lease_seconds <= 900:
            raise ValueError("lease must be between 30 and 900 seconds")
        now = datetime.now(timezone.utc)
        lease_expires = now + timedelta(seconds=lease_seconds)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError("rotation job does not exist")
            if row["authorized_agent_id"] and row["authorized_agent_id"] != agent_id:
                raise PermissionError("job is restricted to its authorized agent")
            if row["authorized_agent_id"]:
                grant = self._connection.execute(
                    """SELECT g.expires_at FROM automation_grants g
                       JOIN devices d
                         ON d.device_id=g.agent_id AND d.status='active'
                       WHERE g.item_id=? AND g.agent_id=?""",
                    (row["item_id"], agent_id),
                ).fetchone()
                if grant is None or _time(grant["expires_at"]) <= now:
                    raise PermissionError(
                        "automation grant is expired or revoked"
                    )
            reclaiming = row["status"] == JobStatus.RUNNING.value
            if reclaiming:
                if row["lease_owner"] != agent_id:
                    raise PermissionError("job is leased to a different agent")
                if (
                    not row["lease_expires_at"]
                    or _time(row["lease_expires_at"]) > now
                ):
                    raise PermissionError("job lease is still active")
            else:
                require_transition(JobStatus(row["status"]), JobStatus.RUNNING)
            self._connection.execute(
                """UPDATE rotation_jobs SET status='running', updated_at=?,
                   lease_owner=?, lease_expires_at=?, attempt_count=attempt_count+1
                   WHERE job_id=?""",
                (_iso(now), agent_id, _iso(lease_expires), job_id),
            )
            self._append_audit(
                agent_id,
                "rotation.job_reclaimed" if reclaiming else "rotation.job_claimed",
                "rotation_job", job_id,
                {
                    "lease_seconds": lease_seconds,
                    "previous_status": row["status"],
                },
                now,
            )
            updated = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
        return self._job_from_row(updated)

    def finish_claimed_job(self, job_id: str, agent_id: str, target: JobStatus,
                           error_code: str | None = None) -> RotationJob:
        if target not in {JobStatus.SUCCEEDED, JobStatus.FAILED}:
            raise ValueError("claimed jobs may only succeed or fail")
        now = datetime.now(timezone.utc)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError("rotation job does not exist")
            if row["lease_owner"] != agent_id:
                raise PermissionError("job is leased to a different agent")
            result = self.transition_job(job_id, target, error_code, actor_id=agent_id)
            with self._connection:
                self._connection.execute(
                    "UPDATE rotation_jobs SET lease_owner=NULL, lease_expires_at=NULL WHERE job_id=?",
                    (job_id,),
                )
            return result.model_copy(update={"lease_owner": None, "lease_expires_at": None})

    def list_audit_events(self, limit: int = 200) -> list[AuditEvent]:
        rows = self._connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        ).fetchall()
        return [self._audit_from_row(row) for row in rows]

    def verify_audit_chain(self) -> AuditVerification:
        rows = self._connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence"
        ).fetchall()
        previous = "0" * 64
        for checked, row in enumerate(rows, start=1):
            event_hash = self._hash_audit_row(row, previous)
            if row["previous_hash"] != previous or not hmac.compare_digest(
                    row["event_hash"], event_hash):
                return AuditVerification(
                    valid=False, events_checked=checked,
                    first_invalid_sequence=row["sequence"],
                )
            previous = row["event_hash"]
        return AuditVerification(valid=True, events_checked=len(rows))

    def _append_audit(self, actor_id: str, action: str, target_type: str,
                      target_id: str, details: dict, occurred_at: datetime) -> None:
        previous_row = self._connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = previous_row["event_hash"] if previous_row else "0" * 64
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
        fields = {
            "occurred_at": _iso(occurred_at), "actor_id": actor_id,
            "action": action, "target_type": target_type, "target_id": target_id,
            "details": details_json,
        }
        digest = self._hash_audit_fields(fields, previous)
        self._connection.execute(
            """INSERT INTO audit_events
               (occurred_at, actor_id, action, target_type, target_id, details,
                previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (*fields.values(), previous, digest),
        )

    @staticmethod
    def _hash_audit_fields(fields: dict[str, str], previous: str) -> str:
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{previous}:{canonical}".encode("utf-8")).hexdigest()

    def _hash_audit_row(self, row: sqlite3.Row, previous: str) -> str:
        fields = {key: row[key] for key in (
            "occurred_at", "actor_id", "action", "target_type", "target_id", "details"
        )}
        return self._hash_audit_fields(fields, previous)

    @staticmethod
    def _audit_from_row(row: sqlite3.Row) -> AuditEvent:
        return AuditEvent(
            sequence=row["sequence"], occurred_at=_time(row["occurred_at"]),
            actor_id=row["actor_id"], action=row["action"],
            target_type=row["target_type"], target_id=row["target_id"],
            details=json.loads(row["details"]), previous_hash=row["previous_hash"],
            event_hash=row["event_hash"],
        )

    def summary(self, now: datetime | None = None) -> dict[str, int]:
        now = now or datetime.now(timezone.utc)
        query = self._connection.execute
        return {
            "vault_items": query("SELECT COUNT(*) FROM vault_items").fetchone()[0],
            "active_policies": query(
                "SELECT COUNT(*) FROM rotation_policies WHERE enabled=1").fetchone()[0],
            "rotations_due": query(
                "SELECT COUNT(*) FROM rotation_policies WHERE enabled=1 AND next_due_at<=?",
                (_iso(now),),
            ).fetchone()[0],
            "jobs_needing_approval": query(
                "SELECT COUNT(*) FROM rotation_jobs WHERE status='proposed'").fetchone()[0],
        }

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> RotationJob:
        return RotationJob(
            job_id=row["job_id"], item_id=row["item_id"],
            provider_id=row["provider_id"], status=JobStatus(row["status"]),
            due_at=_time(row["due_at"]), created_at=_time(row["created_at"]),
            updated_at=_time(row["updated_at"]), error_code=row["error_code"],
            lease_owner=row["lease_owner"],
            lease_expires_at=_time(row["lease_expires_at"])
            if row["lease_expires_at"] else None,
            attempt_count=row["attempt_count"],
            authorized_agent_id=row["authorized_agent_id"],
        )

    @staticmethod
    def _envelope_from_row(row: sqlite3.Row) -> StoredVaultEnvelope:
        return StoredVaultEnvelope(
            **json.loads(row["envelope"]),
            created_at=_time(row["created_at"]),
            updated_at=_time(row["updated_at"]),
        )

    @staticmethod
    def _email_connection_from_row(row: sqlite3.Row) -> EmailConnection:
        return EmailConnection(
            connection_id=row["connection_id"], provider=row["provider"],
            email_address=row["email_address"], scopes=json.loads(row["scopes"]),
            status=EmailConnectionStatus(row["status"]),
            token_expires_at=_time(row["token_expires_at"]),
            created_at=_time(row["created_at"]),
            updated_at=_time(row["updated_at"]),
        )

    def close(self) -> None:
        self._connection.close()
