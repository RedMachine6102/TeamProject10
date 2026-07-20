from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .crypto import SealedSecret, SecretBox
from .email import EmailProvider, provider_spec
from .models import EmailSecurityEvent
from .storage import Database


@dataclass(frozen=True)
class MessageMetadata:
    external_id: str
    subject: str
    sender: str
    occurred_at: datetime


class EmailMetadataClient:
    def refresh(self, provider: str, client_id: str, client_secret: str,
                refresh_token: str, scopes: list[str]) -> dict[str, object]:
        spec = provider_spec(provider)
        values = self._request_json(spec.token_url, form={
            "client_id": client_id, "client_secret": client_secret,
            "refresh_token": refresh_token, "grant_type": "refresh_token",
            "scope": " ".join(scopes),
        })
        access_token = str(values.get("access_token", ""))
        if len(access_token) < 20:
            raise ValueError("provider refresh did not return an access token")
        lifetime = max(60, min(int(values.get("expires_in", 3600)), 86400))
        return {
            "access_token": access_token,
            "refresh_token": str(values.get("refresh_token") or refresh_token),
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=lifetime),
        }

    def list_metadata(self, provider: str, access_token: str) -> list[MessageMetadata]:
        headers = {"Authorization": f"Bearer {access_token}"}
        if provider == EmailProvider.GOOGLE.value:
            listing = self._request_json(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=25",
                headers=headers,
            )
            values = []
            for row in list(listing.get("messages", []))[:25]:
                message_id = str(row.get("id", ""))
                if not message_id:
                    continue
                query = urlencode([
                    ("format", "METADATA"), ("metadataHeaders", "Subject"),
                    ("metadataHeaders", "From"),
                ])
                data = self._request_json(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?{query}",
                    headers=headers,
                )
                header_values = {
                    str(value.get("name", "")).lower(): str(value.get("value", ""))
                    for value in data.get("payload", {}).get("headers", [])
                }
                occurred = datetime.fromtimestamp(
                    int(data.get("internalDate", "0")) / 1000, timezone.utc
                )
                values.append(MessageMetadata(
                    message_id, header_values.get("subject", ""),
                    header_values.get("from", ""), occurred,
                ))
            return values
        url = (
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?"
            + urlencode({
                "$select": "id,subject,sender,receivedDateTime",
                "$orderby": "receivedDateTime desc", "$top": "25",
            })
        )
        data = self._request_json(url, headers=headers)
        return [MessageMetadata(
            str(row.get("id", "")), str(row.get("subject", "")),
            str(row.get("sender", {}).get("emailAddress", {}).get("address", "")),
            datetime.fromisoformat(str(row.get("receivedDateTime", "")).replace("Z", "+00:00")),
        ) for row in list(data.get("value", []))[:25] if row.get("id")]

    @staticmethod
    def _request_json(url: str, form: dict[str, str] | None = None,
                      headers: dict[str, str] | None = None) -> dict:
        body = urlencode(form).encode() if form else None
        request_headers = {"Accept": "application/json", **(headers or {})}
        if body is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            with urlopen(Request(url, data=body, headers=request_headers), timeout=20) as response:
                raw = response.read(2_000_001)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise ValueError("email provider request failed") from exc
        if len(raw) > 2_000_000:
            raise ValueError("email provider response was too large")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("email provider returned invalid JSON")
        return value


def classify_message(provider: str, message: MessageMetadata) -> EmailSecurityEvent | None:
    text = message.subject.lower()
    categories = (
        ("password_changed", ("password changed", "password was changed")),
        ("password_reset", ("password reset", "reset your password")),
        ("suspicious_signin", ("new sign-in", "unusual activity", "suspicious sign")),
        ("verification_code", ("verification code", "security code")),
        ("security_alert", ("security alert", "security notification")),
    )
    category = next((name for name, terms in categories if any(term in text for term in terms)), None)
    if category is None:
        return None
    address = parseaddr(message.sender)[1].lower()
    domain = address.rsplit("@", 1)[-1] if "@" in address else "unknown"
    if not domain.replace(".", "").replace("-", "").isalnum():
        domain = "unknown"
    event_id = hashlib.sha256(
        f"{provider}:{message.external_id}".encode()
    ).hexdigest()
    return EmailSecurityEvent(
        event_id=event_id, provider=provider, category=category,
        source_domain=domain, occurred_at=message.occurred_at,
        detected_at=datetime.now(timezone.utc),
    )


def poll_once(database: Database, secret_box: SecretBox,
              client: EmailMetadataClient) -> int:
    inserted = 0
    for connection in database.active_email_credentials():
        provider = str(connection["provider"])
        prefix = f"VAULTMIND_{provider.upper()}"
        client_id = os.getenv(f"{prefix}_CLIENT_ID", "")
        client_secret = os.getenv(f"{prefix}_CLIENT_SECRET", "")
        if not client_id or not client_secret:
            raise RuntimeError(f"{provider} OAuth credentials are not configured")
        token_data = json.loads(secret_box.open(
            SealedSecret.from_json(str(connection["token_sealed"])),
            f"email-provider:{provider}",
        ))
        if connection["token_expires_at"] <= datetime.now(timezone.utc) + timedelta(minutes=2):
            refreshed = client.refresh(
                provider, client_id, client_secret,
                str(token_data["refresh_token"]), list(connection["scopes"]),
            )
            token_data.update(refreshed)
            sealed = secret_box.seal(json.dumps({
                "access_token": token_data["access_token"],
                "refresh_token": token_data["refresh_token"],
            }, separators=(",", ":")).encode(), f"email-provider:{provider}").to_json()
            database.update_email_token(provider, sealed, refreshed["expires_at"])
        events = [
            event for message in client.list_metadata(provider, str(token_data["access_token"]))
            if (event := classify_message(provider, message)) is not None
        ]
        inserted += database.save_email_security_events(events)
    return inserted


def main() -> int:
    encoded_key = os.getenv("VAULTMIND_ROOT_KEY", "")
    root_key = base64.urlsafe_b64decode(encoded_key)
    secret_box = SecretBox(root_key)
    database = Database(os.getenv("VAULTMIND_DATABASE", "/app/data/vaultmind-next.db"))
    interval = max(60, min(int(os.getenv("VAULTMIND_EMAIL_POLL_SECONDS", "300")), 3600))
    heartbeat = Path("/tmp/vaultmind-email-monitor.heartbeat")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    signal.signal(signal.SIGINT, lambda signum, frame: stop.set())
    while not stop.is_set():
        created = poll_once(database, secret_box, EmailMetadataClient())
        heartbeat.touch()
        if created:
            print(f"stored {created} sanitized email security event(s)", flush=True)
        stop.wait(interval)
    database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
