import os
import json
from datetime import datetime, timedelta, timezone

import pytest

from vaultmind_agent.adapters import (
    PasswordChangeAttempt,
    HttpProviderAdapter,
    TrustedProviderAdapter,
    VerifiedRotationExecutor,
)
from vaultmind_agent.email_challenge import (
    EmailMessage,
    LocalEmailCodeSource,
    LocalEmailCredentials,
)
from vaultmind_next.automation import CredentialMaterial


class FakeMailboxClient:
    def __init__(self, messages: list[EmailMessage]):
        self.messages = messages

    def refresh_access_token(self, credentials: LocalEmailCredentials) -> str:
        return "local-test-access-token-value"

    def recent_messages(self, provider: str, access_token: str,
                        received_after: datetime) -> list[EmailMessage]:
        return self.messages


class FixedCodeSource:
    def __init__(self, code: str | None):
        self.code = code

    def get_code(self, rotation_provider: str,
                 requested_after: datetime) -> str | None:
        return self.code


class ChallengeAdapter(TrustedProviderAdapter):
    provider_id = "demo"

    def __init__(self):
        self.password = "old-password"
        self.pending_password: str | None = None

    def change_password(self, credential: CredentialMaterial,
                        new_password: str) -> PasswordChangeAttempt:
        if credential.current_password != self.password:
            return PasswordChangeAttempt(False)
        self.pending_password = new_password
        return PasswordChangeAttempt(False, "challenge-id-123456789")

    def complete_email_challenge(
        self, credential: CredentialMaterial, new_password: str,
        challenge_id: str, code: str,
    ) -> bool:
        if (
            challenge_id != "challenge-id-123456789"
            or code != "482951"
            or new_password != self.pending_password
        ):
            return False
        self.password = new_password
        self.pending_password = None
        return True

    def verify_password(self, username: str, password: str) -> bool:
        return username == "owner@example.com" and password == self.password


def email_credentials() -> LocalEmailCredentials:
    return LocalEmailCredentials(
        provider="google",
        client_id="local-client-id",
        client_secret="",
        refresh_token="refresh-token-value-long-enough",
        sender_domains={"demo": ["accounts.example"]},
    )


def test_email_code_source_uses_fresh_exact_allowlisted_sender():
    requested_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    messages = [
        EmailMessage(
            "Security <notice@accounts.example>",
            requested_at + timedelta(seconds=1),
            "Your verification code is 482951.",
        ),
        EmailMessage(
            "attacker@sub.accounts.example",
            requested_at + timedelta(seconds=2),
            "Your verification code is 111111.",
        ),
        EmailMessage(
            "notice@accounts.example",
            requested_at - timedelta(seconds=1),
            "Your old verification code is 222222.",
        ),
    ]
    source = LocalEmailCodeSource(
        email_credentials(), FakeMailboxClient(messages), timeout_seconds=10
    )
    assert source.get_code("demo", requested_at) == "482951"


def test_email_code_source_rejects_ambiguous_message_codes():
    requested_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    source = LocalEmailCodeSource(
        email_credentials(),
        FakeMailboxClient([EmailMessage(
            "notice@accounts.example",
            datetime.now(timezone.utc),
            "Use 482951. If that fails, use 739204.",
        )]),
        timeout_seconds=10,
    )
    assert source.get_code("demo", requested_at) is None


def test_email_code_source_requires_timezone():
    source = LocalEmailCodeSource(
        email_credentials(), FakeMailboxClient([]), timeout_seconds=10
    )
    with pytest.raises(ValueError, match="timezone"):
        source.get_code("demo", datetime.now())


def test_rotation_completes_email_challenge_before_verification():
    adapter = ChallengeAdapter()
    result = VerifiedRotationExecutor(
        [adapter], FixedCodeSource("482951")
    ).rotate(
        "demo", CredentialMaterial("owner@example.com", "old-password")
    )
    assert result.changed is True
    assert result.new_password == adapter.password


def test_rotation_fails_closed_without_email_code_source():
    result = VerifiedRotationExecutor([ChallengeAdapter()]).rotate(
        "demo", CredentialMaterial("owner@example.com", "old-password")
    )
    assert result.changed is False
    assert result.error_code == "email_challenge_unavailable"


def test_http_adapter_handles_provider_challenge(monkeypatch):
    responses = [
        {
            "ok": False,
            "challenge_required": True,
            "challenge_id": "challenge-id-123456789",
        },
        {"ok": True},
        {"ok": True},
    ]

    class Response:
        def __init__(self, value: dict):
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size: int) -> bytes:
            return json.dumps(self.value).encode()

    monkeypatch.setattr(
        "vaultmind_agent.adapters.urlopen",
        lambda request, timeout: Response(responses.pop(0)),
    )
    adapter = HttpProviderAdapter("demo", "https://provider.example")
    credential = CredentialMaterial("owner@example.com", "old-password")
    attempt = adapter.change_password(credential, "New-password-value-123!")
    assert attempt.challenge_id == "challenge-id-123456789"
    assert adapter.complete_email_challenge(
        credential, "New-password-value-123!",
        attempt.challenge_id, "482951",
    ) is True
    assert adapter.verify_password(
        "owner@example.com", "New-password-value-123!"
    ) is True


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI test")
def test_email_credentials_are_protected_by_windows_account(tmp_path):
    path = tmp_path / "email-credentials.dat"
    credentials = email_credentials()
    credentials.save(path)
    assert credentials.refresh_token.encode() not in path.read_bytes()
    assert LocalEmailCredentials.load(path) == credentials
