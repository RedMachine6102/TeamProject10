from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, IntEnum
import base64
from typing import Literal

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RotationInterval(IntEnum):
    DAYS_30 = 30
    DAYS_60 = 60
    DAYS_90 = 90


class ApprovalMode(str, Enum):
    MANUAL = "manual"
    AUTOMATIC = "automatic"


class JobStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


class VaultEnvelope(BaseModel):
    """Opaque client-encrypted vault record.

    The API can route a record but cannot read the username, password, notes,
    or recovery data stored inside its ciphertext.
    """

    item_id: str = Field(min_length=8, max_length=128)
    provider_id: str = Field(min_length=2, max_length=80)
    site_origin: str = Field(pattern=r"^https://[A-Za-z0-9.-]+(?::\d+)?$")
    kdf_salt: str = Field(min_length=20, max_length=32)
    nonce: str = Field(min_length=16, max_length=64)
    ciphertext: str = Field(min_length=24, max_length=1_500_000)
    key_version: int = Field(default=1, ge=1)

    @field_validator("item_id")
    @classmethod
    def validate_item_id(cls, value: str) -> str:
        if not value.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                "item_id may contain letters, numbers, hyphens, and underscores"
            )
        return value

    @field_validator("provider_id")
    @classmethod
    def normalize_provider(cls, value: str) -> str:
        value = value.strip().lower()
        if not value.replace("-", "").replace("_", "").isalnum():
            raise ValueError("provider_id may contain letters, numbers, hyphens, and underscores")
        return value

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("nonce must be valid base64") from exc
        if len(raw) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        return value

    @field_validator("kdf_salt")
    @classmethod
    def validate_kdf_salt(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("kdf_salt must be valid base64") from exc
        if len(raw) != 16:
            raise ValueError("PBKDF2 salt must be 16 bytes")
        return value

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("ciphertext must be valid base64") from exc
        if len(raw) < 16:
            raise ValueError("ciphertext must include an authentication tag")
        return value


class StoredVaultEnvelope(VaultEnvelope):
    created_at: datetime
    updated_at: datetime


class VaultKeyEnvelope(BaseModel):
    """Passphrase-wrapped vault data key stored as opaque ciphertext."""

    kdf: Literal["pbkdf2-sha256"] = "pbkdf2-sha256"
    iterations: int = Field(default=600_000, ge=600_000, le=5_000_000)
    salt: str = Field(min_length=20, max_length=32)
    nonce: str = Field(min_length=16, max_length=64)
    wrapped_key: str = Field(min_length=64, max_length=128)
    key_version: int = Field(default=2, ge=2)

    @field_validator("salt")
    @classmethod
    def validate_salt(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("vault key salt must be valid base64") from exc
        if len(raw) != 16:
            raise ValueError("vault key salt must be 16 bytes")
        return value

    @field_validator("nonce")
    @classmethod
    def validate_wrapping_nonce(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("vault key nonce must be valid base64") from exc
        if len(raw) != 12:
            raise ValueError("vault key nonce must be 12 bytes")
        return value

    @field_validator("wrapped_key")
    @classmethod
    def validate_wrapped_key(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("wrapped key must be valid base64") from exc
        if len(raw) != 48:
            raise ValueError("wrapped key must contain a 32-byte key and authentication tag")
        return value


class StoredVaultKeyEnvelope(VaultKeyEnvelope):
    updated_at: datetime


class RotationPolicyCreate(BaseModel):
    item_id: str = Field(min_length=8, max_length=128)
    interval_days: RotationInterval
    approval_mode: ApprovalMode = ApprovalMode.MANUAL
    enabled: bool = True
    next_due_at: datetime | None = None

    @field_validator("next_due_at")
    @classmethod
    def require_due_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("next_due_at must include a timezone")
        return value


class RotationPolicy(RotationPolicyCreate):
    next_due_at: datetime
    updated_at: datetime


class RotationJob(BaseModel):
    job_id: str
    item_id: str
    provider_id: str
    status: JobStatus
    due_at: datetime
    created_at: datetime
    updated_at: datetime
    error_code: str | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    attempt_count: int = 0
    authorized_agent_id: str | None = None


class AutomationGrantCreate(BaseModel):
    item_id: str = Field(min_length=8, max_length=128)
    agent_id: str = Field(min_length=8, max_length=128)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_expiry_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value


class AutomationGrant(AutomationGrantCreate):
    created_at: datetime
    updated_at: datetime


class DashboardSummary(BaseModel):
    vault_items: int
    active_policies: int
    rotations_due: int
    jobs_needing_approval: int


class AuditEvent(BaseModel):
    sequence: int
    occurred_at: datetime
    actor_id: str
    action: str
    target_type: str
    target_id: str
    details: dict[str, str | int | bool | None]
    previous_hash: str
    event_hash: str


class AuditVerification(BaseModel):
    valid: bool
    events_checked: int
    first_invalid_sequence: int | None = None


class DeviceRegistration(BaseModel):
    device_id: str = Field(min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=120)
    public_key: str = Field(min_length=40, max_length=64)
    platform: str = Field(min_length=2, max_length=40)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, altchars=b"-_", validate=True)
        except ValueError as exc:
            raise ValueError("public_key must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        return value


class RegisteredDevice(DeviceRegistration):
    status: str
    created_at: datetime
    last_seen_at: datetime


class DeviceEnrollmentRequest(DeviceRegistration):
    enrollment_code: str = Field(min_length=32, max_length=128)


class DeviceEnrollmentCode(BaseModel):
    code: str
    expires_at: datetime


class EmailConnectionStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class EmailConnection(BaseModel):
    connection_id: str
    provider: str
    email_address: str = Field(
        min_length=3, max_length=320,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    scopes: list[str]
    status: EmailConnectionStatus
    token_expires_at: datetime
    created_at: datetime
    updated_at: datetime


class EmailSecurityEvent(BaseModel):
    event_id: str
    provider: str
    category: str
    source_domain: str
    occurred_at: datetime
    detected_at: datetime


class AIRecommendation(BaseModel):
    recommendation_id: str
    event_id: str
    action: Literal["ignore", "review", "propose_rotation"]
    risk: Literal["low", "medium", "high"]
    reason_code: Literal[
        "routine_code", "confirmed_change", "possible_compromise", "unknown"
    ]
    model: str
    created_at: datetime


class OAuthStartResponse(BaseModel):
    authorization_url: str
    state_expires_at: datetime


class OwnerSetupRequest(BaseModel):
    email_address: str = Field(
        min_length=3, max_length=320,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
    )
    display_name: str = Field(min_length=1, max_length=120)

    @field_validator("email_address")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class PasskeyOptions(BaseModel):
    ceremony_id: str
    public_key: dict[str, object]


class PasskeyFinishRequest(BaseModel):
    ceremony_id: str = Field(min_length=32, max_length=128)
    credential: dict[str, object]


class SessionUser(BaseModel):
    user_id: str
    email_address: str
    display_name: str


class AuthStatus(BaseModel):
    owner_exists: bool
    authenticated: bool
    user: SessionUser | None = None


class AgentJobPackage(BaseModel):
    job: RotationJob
    envelope: StoredVaultEnvelope
    vault_key_envelope: VaultKeyEnvelope | None = None


class RotationCommitResult(BaseModel):
    job: RotationJob
    envelope: StoredVaultEnvelope
