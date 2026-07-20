import json
import sqlite3
from datetime import datetime, timedelta, timezone

from vaultmind_next.crypto import SecretBox
from vaultmind_next.email_monitor import (
    EmailMetadataClient, MessageMetadata, poll_once,
)
from vaultmind_next.storage import Database


class FakeMetadataClient:
    def __init__(self):
        self.refreshes = 0

    def refresh(self, provider, client_id, client_secret, refresh_token, scopes):
        self.refreshes += 1
        assert refresh_token == "old-refresh-token-value"
        return {
            "access_token": "new-access-token-value-long-enough",
            "refresh_token": "rotated-refresh-token-value",
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        }

    def list_metadata(self, provider, access_token):
        assert access_token == "new-access-token-value-long-enough"
        return [
            MessageMetadata(
                "provider-message-1", "Security alert: new sign-in",
                "Account Security <alerts@example.com>",
                datetime.now(timezone.utc),
            ),
            MessageMetadata(
                "provider-message-2", "Your weekly newsletter",
                "news@example.com", datetime.now(timezone.utc),
            ),
        ]


def test_monitor_refreshes_tokens_and_stores_only_sanitized_deduplicated_events(
    tmp_path, monkeypatch,
):
    path = tmp_path / "email-monitor.db"
    database = Database(str(path))
    secret_box, _ = SecretBox.generate()
    sealed = secret_box.seal(json.dumps({
        "access_token": "old-access-token-value",
        "refresh_token": "old-refresh-token-value",
    }).encode(), "email-provider:google").to_json()
    database.upsert_email_connection(
        "google", "owner@example.com", ["gmail.metadata"], sealed,
        datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    monkeypatch.setenv("VAULTMIND_GOOGLE_CLIENT_ID", "google-client-id")
    monkeypatch.setenv("VAULTMIND_GOOGLE_CLIENT_SECRET", "google-client-secret-value")
    client = FakeMetadataClient()

    assert poll_once(database, secret_box, client) == 1
    assert poll_once(database, secret_box, client) == 0
    assert client.refreshes == 1
    events = database.list_email_security_events()
    assert len(events) == 1
    assert events[0].category == "suspicious_signin"
    assert events[0].source_domain == "example.com"

    database.close()
    raw = path.read_bytes()
    assert b"Security alert: new sign-in" not in raw
    assert b"alerts@example.com" not in raw
    assert b"rotated-refresh-token-value" not in raw


class RecordingGoogleClient(EmailMetadataClient):
    def __init__(self):
        self.urls = []

    def _request_json(self, url, form=None, headers=None):
        self.urls.append(url)
        if url.endswith("messages?maxResults=25"):
            return {"messages": [{"id": "message-1"}]}
        return {
            "internalDate": "1704067200000",
            "payload": {"headers": [
                {"name": "Subject", "value": "Password changed"},
                {"name": "From", "value": "security@example.com"},
            ]},
        }


def test_google_poll_requests_only_bounded_metadata_headers():
    client = RecordingGoogleClient()
    messages = client.list_metadata("google", "access-token-value-long-enough")
    assert len(messages) == 1
    assert "maxResults=25" in client.urls[0]
    assert "format=METADATA" in client.urls[1]
    assert "metadataHeaders=Subject" in client.urls[1]
    assert "metadataHeaders=From" in client.urls[1]
    assert "q=" not in client.urls[0]
    assert all("body" not in url.lower() for url in client.urls)
