from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import (
    Depends, FastAPI, Header, HTTPException, Query, Request, Response, status,
)
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .models import (
    AuthStatus,
    AIRecommendation,
    AgentJobPackage,
    DashboardSummary,
    AuditEvent,
    AuditVerification,
    AutomationGrant,
    AutomationGrantCreate,
    DeviceRegistration,
    DeviceEnrollmentCode,
    DeviceEnrollmentRequest,
    EmailConnection,
    EmailSecurityEvent,
    JobStatus,
    RegisteredDevice,
    RotationJob,
    RotationPolicy,
    RotationPolicyCreate,
    RotationCommitResult,
    StoredVaultEnvelope,
    StoredVaultKeyEnvelope,
    VaultEnvelope,
    VaultKeyEnvelope,
    OAuthStartResponse,
    OwnerSetupRequest,
    PasskeyFinishRequest,
    PasskeyOptions,
    SessionUser,
)
from .storage import Database
from .device import payload_digest, signed_message, verify_signature
from .crypto import SealedSecret, SecretBox
from .email import (
    PROVIDERS, EmailProvider, OAuthClient, build_authorization_url, provider_spec,
)
from .auth import (
    AttemptLimiter, PasskeyConfig, PasskeyManager, base64url, decode_base64url,
)
from webauthn.helpers.exceptions import WebAuthnException

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEB_ROOT = Path(os.getenv("VAULTMIND_WEB_ROOT", PROJECT_ROOT / "web"))


class AgentClaim(BaseModel):
    agent_id: str = Field(min_length=8, max_length=128)
    lease_seconds: int = Field(default=300, ge=30, le=900)
    timestamp: datetime
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=80, max_length=128)


class AgentAction(BaseModel):
    agent_id: str = Field(min_length=8, max_length=128)
    timestamp: datetime
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=80, max_length=128)


class AgentCommit(AgentAction):
    envelope: VaultEnvelope


class AgentResult(BaseModel):
    agent_id: str = Field(min_length=8, max_length=128)
    error_code: str | None = Field(default=None, min_length=3, max_length=80)
    timestamp: datetime
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=80, max_length=128)


def create_app(database_path: str | None = None, api_key: str | None = None,
               oauth_client: OAuthClient | None = None,
               passkey_manager: PasskeyManager | None = None) -> FastAPI:
    environment = os.getenv("VAULTMIND_ENV", "development")
    token = api_key or os.getenv(
        "VAULTMIND_API_KEY", "development-token-change-before-deploying"
    )
    if environment != "development" and len(token) < 32:
        raise RuntimeError("VAULTMIND_API_KEY must contain at least 32 characters")

    database = Database(database_path or os.getenv(
        "VAULTMIND_DATABASE", str(PROJECT_ROOT / "data" / "vaultmind-next.db")
    ))
    secret_box = _load_secret_box(environment)
    oauth_client = oauth_client or OAuthClient()
    public_url = _public_url(environment)
    passkey_manager = passkey_manager or PasskeyManager(
        PasskeyConfig.from_origin(public_url)
    )
    login_limiter = AttemptLimiter()
    session_minutes = _session_minutes()
    secure_cookie = urlparse(public_url).scheme == "https"
    app = FastAPI(
        title="VaultMind Next",
        version="0.1.0",
        docs_url="/api/docs" if environment == "development" else None,
        redoc_url=None,
    )
    app.state.database = database

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.cookies.get(
            "vaultmind_session"
        ):
            if request.headers.get("origin") != public_url:
                return Response(status_code=403, content="request origin was rejected")
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def valid_token(authorization: str) -> bool:
        scheme, _, supplied = authorization.partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(supplied, token)

    def require_bootstrap_token(authorization: str = Header(default="")) -> None:
        if not valid_token(authorization):
            raise HTTPException(status_code=401, detail="bootstrap token required")

    def session_user(request: Request) -> SessionUser | None:
        session_token = request.cookies.get("vaultmind_session", "")
        if len(session_token) < 32:
            return None
        try:
            return database.get_session_user(_token_hash(session_token))
        except KeyError:
            return None

    def require_access(request: Request,
                       authorization: str = Header(default="")) -> SessionUser | None:
        user = session_user(request)
        if user is not None:
            return user
        if not database.owner_exists() and valid_token(authorization):
            return None
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="passkey session or valid bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    protected = [Depends(require_access)]

    def issue_session(response: Response, user: SessionUser) -> None:
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=session_minutes)
        database.create_session(_token_hash(session_token), user.user_id, expires_at)
        response.set_cookie(
            "vaultmind_session", session_token, max_age=session_minutes * 60,
            httponly=True, secure=secure_cookie, samesite="strict", path="/",
        )

    def clear_session_cookie(response: Response) -> None:
        response.delete_cookie(
            "vaultmind_session", path="/", httponly=True,
            secure=secure_cookie, samesite="strict",
        )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "vaultmind-next"}

    @app.get("/api/health/ready")
    def readiness(response: Response) -> dict[str, str]:
        if not database.is_ready():
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            return {"status": "unavailable", "database": "failed"}
        return {"status": "ready", "database": "ok"}

    def check_auth_attempt(request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        if not login_limiter.allow(client_ip):
            raise HTTPException(
                status_code=429, detail="too many authentication attempts",
                headers={"Retry-After": "300"},
            )

    @app.get("/api/v1/auth/status", response_model=AuthStatus)
    def auth_status(request: Request) -> AuthStatus:
        user = session_user(request)
        return AuthStatus(
            owner_exists=database.owner_exists(),
            authenticated=user is not None, user=user,
        )

    @app.post("/api/v1/auth/register/options", response_model=PasskeyOptions,
              dependencies=[Depends(require_bootstrap_token)])
    def registration_options(request: Request,
                             owner: OwnerSetupRequest) -> PasskeyOptions:
        check_auth_attempt(request)
        if database.owner_exists():
            raise HTTPException(status_code=409, detail="owner is already configured")
        user_uuid = uuid4()
        options, challenge = passkey_manager.registration_options(
            user_uuid.bytes, owner.email_address, owner.display_name
        )
        ceremony_id = secrets.token_urlsafe(32)
        database.create_passkey_challenge(
            _token_hash(ceremony_id), "register", base64url(challenge),
            datetime.now(timezone.utc) + timedelta(minutes=5),
            user_id=str(user_uuid), email_address=owner.email_address,
            display_name=owner.display_name,
        )
        return PasskeyOptions(ceremony_id=ceremony_id, public_key=options)

    @app.post("/api/v1/auth/register/finish", response_model=AuthStatus,
              dependencies=[Depends(require_bootstrap_token)])
    def finish_registration(request: Request, response: Response,
                            finish: PasskeyFinishRequest) -> AuthStatus:
        check_auth_attempt(request)
        try:
            pending = database.consume_passkey_challenge(
                _token_hash(finish.ceremony_id), "register"
            )
            if not pending.user_id or not pending.email_address or not pending.display_name:
                raise ValueError("registration identity is missing")
            verified = passkey_manager.verify_registration(
                finish.credential, decode_base64url(pending.challenge)
            )
            response_data = finish.credential.get("response", {})
            transports = response_data.get("transports", []) \
                if isinstance(response_data, dict) else []
            transports = [str(value) for value in transports]
            user = database.register_owner_passkey(
                pending.user_id, pending.email_address, pending.display_name,
                base64url(verified.credential_id),
                base64url(verified.credential_public_key), verified.sign_count,
                verified.credential_device_type.value,
                verified.credential_backed_up, transports,
            )
            issue_session(response, user)
            return AuthStatus(owner_exists=True, authenticated=True, user=user)
        except (KeyError, ValueError, WebAuthnException) as exc:
            raise HTTPException(status_code=400, detail="passkey registration failed") from exc

    @app.post("/api/v1/auth/login/options", response_model=PasskeyOptions)
    def authentication_options(request: Request) -> PasskeyOptions:
        check_auth_attempt(request)
        if not database.owner_exists():
            raise HTTPException(status_code=409, detail="owner is not configured")
        options, challenge = passkey_manager.authentication_options()
        ceremony_id = secrets.token_urlsafe(32)
        database.create_passkey_challenge(
            _token_hash(ceremony_id), "authenticate", base64url(challenge),
            datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        return PasskeyOptions(ceremony_id=ceremony_id, public_key=options)

    @app.post("/api/v1/auth/login/finish", response_model=AuthStatus)
    def finish_authentication(request: Request, response: Response,
                              finish: PasskeyFinishRequest) -> AuthStatus:
        check_auth_attempt(request)
        try:
            pending = database.consume_passkey_challenge(
                _token_hash(finish.ceremony_id), "authenticate"
            )
            credential_id = finish.credential.get("id")
            if not isinstance(credential_id, str) or len(credential_id) > 1024:
                raise ValueError("credential id is invalid")
            passkey = database.get_passkey(credential_id)
            verified = passkey_manager.verify_authentication(
                finish.credential, decode_base64url(pending.challenge),
                decode_base64url(passkey.public_key), passkey.sign_count,
            )
            database.update_passkey_use(
                credential_id, verified.new_sign_count,
                verified.credential_device_type.value,
                verified.credential_backed_up,
            )
            issue_session(response, passkey.user)
            return AuthStatus(
                owner_exists=True, authenticated=True, user=passkey.user
            )
        except (KeyError, ValueError, WebAuthnException) as exc:
            raise HTTPException(status_code=401, detail="passkey sign-in failed") from exc

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(request: Request, response: Response) -> None:
        session_token = request.cookies.get("vaultmind_session", "")
        if not session_token:
            raise HTTPException(status_code=401, detail="no active session")
        database.delete_session(_token_hash(session_token))
        clear_session_cookie(response)

    @app.post("/api/v1/auth/logout-all", status_code=204)
    def logout_all(
        request: Request, response: Response,
        user: SessionUser | None = Depends(require_access),
    ) -> None:
        if user is None:
            raise HTTPException(status_code=409, detail="owner is not configured")
        database.delete_user_sessions(user.user_id)
        clear_session_cookie(response)

    @app.get("/api/v1/dashboard", response_model=DashboardSummary,
             dependencies=protected)
    def dashboard() -> dict[str, int]:
        return database.summary()

    @app.get("/api/v1/audit/events", response_model=list[AuditEvent],
             dependencies=protected)
    def audit_events(limit: int = 200) -> list[AuditEvent]:
        return database.list_audit_events(limit)

    @app.get("/api/v1/audit/verify", response_model=AuditVerification,
             dependencies=protected)
    def verify_audit() -> AuditVerification:
        return database.verify_audit_chain()

    @app.post("/api/v1/devices", response_model=RegisteredDevice,
              dependencies=protected, status_code=201)
    def register_device(request: DeviceRegistration) -> RegisteredDevice:
        try:
            return database.register_device(request)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/devices", response_model=list[RegisteredDevice],
             dependencies=protected)
    def list_devices() -> list[RegisteredDevice]:
        return database.list_devices()

    @app.post("/api/v1/devices/enrollment-code",
              response_model=DeviceEnrollmentCode)
    def create_device_enrollment(
        actor: SessionUser | None = Depends(require_access),
    ) -> DeviceEnrollmentCode:
        code = secrets.token_urlsafe(24)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        database.create_device_enrollment(
            _token_hash(code), actor.user_id if actor else "bootstrap", expires_at
        )
        return DeviceEnrollmentCode(code=code, expires_at=expires_at)

    @app.post("/api/v1/devices/enroll", response_model=RegisteredDevice,
              status_code=201)
    def enroll_device(request: DeviceEnrollmentRequest) -> RegisteredDevice:
        try:
            return database.redeem_device_enrollment(
                _token_hash(request.enrollment_code), request
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/devices/{device_id}/revoke", response_model=RegisteredDevice)
    def revoke_device(
        device_id: str,
        actor: SessionUser | None = Depends(require_access),
    ) -> RegisteredDevice:
        try:
            return database.revoke_device(
                device_id, actor.user_id if actor else "bootstrap"
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/email/providers", dependencies=protected)
    def email_providers() -> list[dict[str, object]]:
        return [
            {
                "provider": spec.provider.value,
                "scopes": list(spec.scopes),
                "configured": _oauth_credentials(spec.provider) is not None,
            }
            for spec in PROVIDERS.values()
        ]

    @app.get("/api/v1/email/connections", response_model=list[EmailConnection],
             dependencies=protected)
    def email_connections() -> list[EmailConnection]:
        return database.list_email_connections()

    @app.get("/api/v1/email/security-events",
             response_model=list[EmailSecurityEvent], dependencies=protected)
    def email_security_events(limit: int = 100) -> list[EmailSecurityEvent]:
        return database.list_email_security_events(limit)

    @app.get("/api/v1/ai/recommendations",
             response_model=list[AIRecommendation], dependencies=protected)
    def ai_recommendations(limit: int = 100) -> list[AIRecommendation]:
        return database.list_ai_recommendations(limit)

    @app.post("/api/v1/email/connections/{provider}/start",
              response_model=OAuthStartResponse, dependencies=protected)
    def start_email_connection(provider: EmailProvider) -> OAuthStartResponse:
        credentials = _oauth_credentials(provider)
        if credentials is None:
            raise HTTPException(status_code=503, detail="OAuth provider is not configured")
        public_url = _public_url(environment)
        redirect_uri = (
            f"{public_url}/api/v1/email/oauth/callback?provider={provider.value}"
        )
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        state_hash = hashlib.sha256(state.encode("ascii")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        sealed_verifier = secret_box.seal(
            verifier.encode("ascii"), f"oauth-state:{state_hash}"
        )
        database.create_oauth_state(
            state_hash, provider.value, redirect_uri,
            sealed_verifier.to_json(), expires_at,
        )
        try:
            authorization_url = build_authorization_url(
                provider, credentials[0], redirect_uri, state, challenge
            )
        except ValueError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return OAuthStartResponse(
            authorization_url=authorization_url, state_expires_at=expires_at
        )

    @app.get("/api/v1/email/oauth/callback", include_in_schema=False)
    def complete_email_connection(
        provider: EmailProvider,
        state_value: str = Query(alias="state", min_length=32, max_length=256),
        code: str = Query(min_length=8, max_length=8192),
    ) -> RedirectResponse:
        credentials = _oauth_credentials(provider)
        if credentials is None:
            raise HTTPException(status_code=503, detail="OAuth provider is not configured")
        try:
            state_hash = hashlib.sha256(state_value.encode("ascii")).hexdigest()
            pending = database.consume_oauth_state(state_hash, provider.value)
            sealed = SealedSecret.from_json(pending.verifier_sealed)
            verifier = secret_box.open(
                sealed, f"oauth-state:{state_hash}"
            ).decode("ascii")
            tokens = oauth_client.exchange(
                provider, credentials[0], credentials[1], code,
                pending.redirect_uri, verifier,
            )
            token_payload = json.dumps({
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
            }, separators=(",", ":")).encode("utf-8")
            token_sealed = secret_box.seal(
                token_payload, f"email-provider:{provider.value}"
            ).to_json()
            database.upsert_email_connection(
                provider.value, tokens.email_address, list(tokens.scopes),
                token_sealed, tokens.expires_at,
            )
        except (UnicodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse(
            url=f"/?email_connected={provider.value}#connections", status_code=303
        )

    @app.delete("/api/v1/email/connections/{provider}",
                response_model=EmailConnection, dependencies=protected)
    def revoke_email_connection(provider: EmailProvider) -> EmailConnection:
        try:
            return database.revoke_email_connection(provider.value)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/api/v1/vault/items", response_model=StoredVaultEnvelope,
             dependencies=protected)
    def save_item(item: VaultEnvelope) -> StoredVaultEnvelope:
        try:
            return database.upsert_item(item)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.put("/api/v1/vault/key-envelope", response_model=StoredVaultKeyEnvelope,
             dependencies=protected)
    def save_vault_key_envelope(
        envelope: VaultKeyEnvelope, request: Request,
    ) -> StoredVaultKeyEnvelope:
        user = session_user(request)
        actor_id = user.user_id if user else "bootstrap"
        return database.put_vault_key_envelope(envelope, actor_id)

    @app.get("/api/v1/vault/key-envelope", response_model=StoredVaultKeyEnvelope,
             dependencies=protected)
    def get_vault_key_envelope() -> StoredVaultKeyEnvelope:
        try:
            return database.get_vault_key_envelope()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/vault/items", response_model=list[StoredVaultEnvelope],
             dependencies=protected)
    def list_items() -> list[StoredVaultEnvelope]:
        return database.list_items()

    @app.delete("/api/v1/vault/items/{item_id}", status_code=204,
                dependencies=protected)
    def delete_item(item_id: str) -> None:
        try:
            database.delete_item(item_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/api/v1/rotation/policies", response_model=RotationPolicy,
             dependencies=protected)
    def save_policy(request: RotationPolicyCreate) -> RotationPolicy:
        try:
            return database.put_policy(request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/v1/rotation/policies", response_model=list[RotationPolicy],
             dependencies=protected)
    def list_policies() -> list[RotationPolicy]:
        return database.list_policies()

    @app.put("/api/v1/automation/grants", response_model=AutomationGrant,
             dependencies=protected)
    def save_automation_grant(request: AutomationGrantCreate) -> AutomationGrant:
        try:
            return database.put_automation_grant(request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/automation/grants", response_model=list[AutomationGrant],
             dependencies=protected)
    def list_automation_grants() -> list[AutomationGrant]:
        return database.list_automation_grants()

    @app.delete("/api/v1/automation/grants/{item_id}", status_code=204,
                dependencies=protected)
    def revoke_automation_grant(item_id: str) -> None:
        try:
            database.revoke_automation_grant(item_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/v1/rotation/scan", response_model=list[RotationJob],
              dependencies=protected)
    def scan_due_rotations() -> list[RotationJob]:
        return database.create_due_jobs()

    @app.get("/api/v1/rotation/jobs", response_model=list[RotationJob],
             dependencies=protected)
    def list_jobs() -> list[RotationJob]:
        return database.list_jobs()

    @app.post("/api/v1/rotation/jobs/{job_id}/approve", response_model=RotationJob,
              dependencies=protected)
    def approve_job(job_id: str) -> RotationJob:
        return _transition(database, job_id, JobStatus.APPROVED)

    @app.post("/api/v1/agent/jobs/available", response_model=list[RotationJob])
    def available_agent_jobs(action: AgentAction) -> list[RotationJob]:
        _verify_agent_action(
            database, action.agent_id, action.timestamp, action.nonce,
            action.signature, "rotation.available", {},
        )
        return database.list_available_jobs(action.agent_id)

    @app.post("/api/v1/agent/jobs/{job_id}/claim", response_model=RotationJob)
    def agent_claim_job(job_id: str, claim: AgentClaim) -> RotationJob:
        try:
            _verify_agent_action(
                database, claim.agent_id, claim.timestamp, claim.nonce,
                claim.signature, "rotation.claim",
                {"job_id": job_id, "lease_seconds": claim.lease_seconds},
            )
            return database.claim_job(job_id, claim.agent_id, claim.lease_seconds)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/agent/jobs/{job_id}/package",
              response_model=AgentJobPackage)
    def agent_job_package(job_id: str, action: AgentAction) -> AgentJobPackage:
        try:
            _verify_agent_action(
                database, action.agent_id, action.timestamp, action.nonce,
                action.signature, "rotation.package", {"job_id": job_id},
            )
            return database.get_agent_job_package(job_id, action.agent_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/agent/jobs/{job_id}/commit",
              response_model=RotationCommitResult)
    def commit_agent_job(job_id: str, commit: AgentCommit) -> RotationCommitResult:
        digest = payload_digest(commit.envelope.model_dump(mode="json"))
        try:
            _verify_agent_action(
                database, commit.agent_id, commit.timestamp, commit.nonce,
                commit.signature, "rotation.commit",
                {"job_id": job_id, "envelope_sha256": digest},
            )
            return database.commit_agent_rotation(
                job_id, commit.agent_id, commit.envelope
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/agent/jobs/{job_id}/fail", response_model=RotationJob)
    def fail_agent_job(job_id: str, result: AgentResult) -> RotationJob:
        _verify_agent_action(
            database, result.agent_id, result.timestamp, result.nonce,
            result.signature, "rotation.fail",
            {"job_id": job_id, "error_code": result.error_code},
        )
        return _finish(
            database, job_id, result.agent_id, JobStatus.FAILED, result.error_code
        )

    @app.post("/api/v1/rotation/jobs/{job_id}/claim", response_model=RotationJob,
              dependencies=protected)
    def claim_job(job_id: str, claim: AgentClaim) -> RotationJob:
        try:
            _verify_agent_action(
                database, claim.agent_id, claim.timestamp, claim.nonce,
                claim.signature, "rotation.claim",
                {"job_id": job_id, "lease_seconds": claim.lease_seconds},
            )
            return database.claim_job(job_id, claim.agent_id, claim.lease_seconds)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (PermissionError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/rotation/jobs/{job_id}/fail", response_model=RotationJob,
              dependencies=protected)
    def fail_job(job_id: str, result: AgentResult) -> RotationJob:
        _verify_agent_action(
            database, result.agent_id, result.timestamp, result.nonce,
            result.signature, "rotation.fail",
            {"job_id": job_id, "error_code": result.error_code},
        )
        return _finish(
            database, job_id, result.agent_id, JobStatus.FAILED, result.error_code
        )

    if WEB_ROOT.exists():
        app.mount("/assets", StaticFiles(directory=WEB_ROOT), name="assets")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(WEB_ROOT / "index.html")

    return app


def _load_secret_box(environment: str) -> SecretBox:
    encoded = os.getenv("VAULTMIND_ROOT_KEY", "")
    if not encoded:
        if environment != "development":
            raise RuntimeError("VAULTMIND_ROOT_KEY is required in production")
        return SecretBox.generate()[0]
    try:
        root_key = base64.urlsafe_b64decode(encoded)
        return SecretBox(root_key)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError(
            "VAULTMIND_ROOT_KEY must be a base64-encoded 32-byte key"
        ) from exc


def _oauth_credentials(provider: EmailProvider) -> tuple[str, str] | None:
    prefix = f"VAULTMIND_{provider.value.upper()}"
    client_id = os.getenv(f"{prefix}_CLIENT_ID", "").strip()
    client_secret = os.getenv(f"{prefix}_CLIENT_SECRET", "").strip()
    if len(client_id) < 8 or len(client_secret) < 16:
        return None
    return client_id, client_secret


def _public_url(environment: str) -> str:
    default = "http://localhost:8080" if environment == "development" else ""
    value = os.getenv("VAULTMIND_PUBLIC_URL", default).rstrip("/")
    parsed = urlparse(value)
    local = parsed.hostname in {"127.0.0.1", "localhost"}
    if not value or parsed.path or parsed.query or parsed.fragment:
        raise HTTPException(status_code=503, detail="public URL is not configured")
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise HTTPException(status_code=503, detail="public URL must use HTTPS")
    return value


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _session_minutes() -> int:
    try:
        minutes = int(os.getenv("VAULTMIND_SESSION_MINUTES", "30"))
    except ValueError as exc:
        raise RuntimeError("VAULTMIND_SESSION_MINUTES must be an integer") from exc
    if not 5 <= minutes <= 60:
        raise RuntimeError("VAULTMIND_SESSION_MINUTES must be between 5 and 60")
    return minutes


def _transition(database: Database, job_id: str, target: JobStatus,
                error_code: str | None = None) -> RotationJob:
    try:
        return database.transition_job(job_id, target, error_code)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _finish(database: Database, job_id: str, agent_id: str, target: JobStatus,
            error_code: str | None = None) -> RotationJob:
    try:
        return database.finish_claimed_job(job_id, agent_id, target, error_code)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _verify_agent_action(database: Database, agent_id: str, timestamp: datetime,
                         nonce: str, signature: str, action: str,
                         values: dict[str, str | int | None]) -> None:
    if timestamp.tzinfo is None:
        raise HTTPException(status_code=400, detail="signed timestamp needs a timezone")
    now = datetime.now(timezone.utc)
    if abs(now - timestamp.astimezone(timezone.utc)) > timedelta(seconds=90):
        raise HTTPException(status_code=401, detail="signed request timestamp expired")
    try:
        public_key = database.get_active_device_key(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    message = signed_message(action, agent_id, timestamp, nonce, values)
    if not verify_signature(public_key, signature, message):
        raise HTTPException(status_code=401, detail="invalid device signature")
    try:
        database.consume_device_nonce(agent_id, nonce)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


app = create_app()
