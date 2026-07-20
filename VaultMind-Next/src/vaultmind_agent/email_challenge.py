from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .identity import protect_for_current_user, unprotect_for_current_user

CODE_PATTERN = re.compile(r"(?<!\d)(\d{6,8})(?!\d)")
MAIL_PROVIDERS = {"google", "microsoft"}


def _valid_domain(value: str) -> bool:
    if not 3 <= len(value) <= 253 or value != value.lower():
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(
        1 <= len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def _sender_domain(sender: str) -> str:
    address = parseaddr(sender)[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def normalize_sender_domains(
    sender_domains: dict[str, list[str]],
    allow_empty: bool = False,
) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for rotation_provider, domains in sender_domains.items():
        provider_id = rotation_provider.lower()
        if not provider_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("rotation provider id is invalid")
        values = sorted(set(domain.lower() for domain in domains))
        if not values or not all(_valid_domain(domain) for domain in values):
            raise ValueError("sender domain allowlist is invalid")
        normalized[provider_id] = values
    if not normalized and not allow_empty:
        raise ValueError("at least one sender domain is required")
    return normalized


@dataclass
class LocalEmailCredentials:
    provider: str
    client_id: str
    client_secret: str
    refresh_token: str
    sender_domains: dict[str, list[str]]

    def __post_init__(self) -> None:
        self.provider = self.provider.lower()
        if self.provider not in MAIL_PROVIDERS:
            raise ValueError("unsupported local email provider")
        if len(self.client_id) < 8 or len(self.refresh_token) < 20:
            raise ValueError("local email credentials are incomplete")
        self.sender_domains = normalize_sender_domains(
            self.sender_domains, allow_empty=True
        )

    def save(self, path: Path) -> None:
        raw = json.dumps(asdict(self), separators=(",", ":")).encode("utf-8")
        protected = protect_for_current_user(raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(protected)
        os.chmod(temporary, 0o600)
        temporary.replace(path)

    @classmethod
    def load(cls, path: Path) -> "LocalEmailCredentials":
        raw = unprotect_for_current_user(path.read_bytes())
        try:
            values = json.loads(raw)
        finally:
            del raw
        if not isinstance(values, dict):
            raise ValueError("stored local email credentials are invalid")
        return cls(**values)


@dataclass(frozen=True)
class EmailMessage:
    sender: str
    received_at: datetime
    text: str


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[str] = []

    def handle_data(self, data: str) -> None:
        self.values.append(data)

    def text(self) -> str:
        return " ".join(self.values)


class MailboxClient:
    def exchange_authorization_code(
        self, provider: str, client_id: str, client_secret: str,
        code: str, verifier: str, redirect_uri: str,
    ) -> str:
        if provider == "google":
            url = "https://oauth2.googleapis.com/token"
            scope = ""
        elif provider == "microsoft":
            url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            scope = (
                "openid email offline_access "
                "https://graph.microsoft.com/Mail.Read"
            )
        else:
            raise ValueError("unsupported local email provider")
        form = {
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        if client_secret:
            form["client_secret"] = client_secret
        if scope:
            form["scope"] = scope
        result = self._request_json(url, form=form)
        refresh_token = str(result.get("refresh_token", ""))
        if len(refresh_token) < 20:
            raise ValueError("email provider did not return a refresh token")
        return refresh_token

    def refresh_access_token(
        self, credentials: LocalEmailCredentials,
    ) -> tuple[str, str | None]:
        if credentials.provider == "google":
            url = "https://oauth2.googleapis.com/token"
            scope = ""
        else:
            url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            scope = "openid email offline_access https://graph.microsoft.com/Mail.Read"
        form = {
            "client_id": credentials.client_id,
            "refresh_token": credentials.refresh_token,
            "grant_type": "refresh_token",
        }
        if credentials.client_secret:
            form["client_secret"] = credentials.client_secret
        if scope:
            form["scope"] = scope
        result = self._request_json(url, form=form)
        access_token = str(result.get("access_token", ""))
        if len(access_token) < 20:
            raise ValueError("email provider did not return an access token")
        refresh_token = str(result.get("refresh_token", ""))
        if refresh_token and len(refresh_token) < 20:
            raise ValueError("email provider returned an invalid refresh token")
        return access_token, refresh_token or None

    def recent_messages(self, provider: str, access_token: str,
                        received_after: datetime) -> list[EmailMessage]:
        if provider == "google":
            return self._google_messages(access_token, received_after)
        if provider == "microsoft":
            return self._microsoft_messages(access_token, received_after)
        raise ValueError("unsupported local email provider")

    def _google_messages(self, access_token: str,
                         received_after: datetime) -> list[EmailMessage]:
        headers = {"Authorization": f"Bearer {access_token}"}
        query = urlencode({
            "maxResults": "10",
            "q": f"after:{int(received_after.timestamp())}",
        })
        listing = self._request_json(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages?{query}",
            headers=headers,
        )
        messages: list[EmailMessage] = []
        for row in list(listing.get("messages", []))[:10]:
            message_id = str(row.get("id", ""))
            if not message_id:
                continue
            data = self._request_json(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
                f"{message_id}?format=full",
                headers=headers,
            )
            header_values = {
                str(value.get("name", "")).lower(): str(value.get("value", ""))
                for value in data.get("payload", {}).get("headers", [])
            }
            try:
                received_at = datetime.fromtimestamp(
                    int(data.get("internalDate", "0")) / 1000, timezone.utc
                )
            except (TypeError, ValueError, OSError):
                continue
            text = " ".join((
                str(data.get("snippet", ""))[:2048],
                self._gmail_plain_text(data.get("payload", {})),
            ))[:32768]
            messages.append(EmailMessage(
                sender=header_values.get("from", ""),
                received_at=received_at,
                text=text,
            ))
        return messages

    @classmethod
    def _gmail_plain_text(cls, payload: object) -> str:
        if not isinstance(payload, dict):
            return ""
        values: list[str] = []
        if payload.get("mimeType") == "text/plain":
            encoded = payload.get("body", {}).get("data", "")
            if encoded:
                try:
                    padding = "=" * (-len(encoded) % 4)
                    raw = base64.urlsafe_b64decode(encoded + padding)
                    values.append(raw[:32768].decode("utf-8", errors="replace"))
                except (ValueError, TypeError):
                    pass
        for part in list(payload.get("parts", []))[:25]:
            values.append(cls._gmail_plain_text(part))
        return " ".join(values)[:32768]

    def _microsoft_messages(self, access_token: str,
                            received_after: datetime) -> list[EmailMessage]:
        timestamp = received_after.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
        query = urlencode({
            "$select": "id,sender,receivedDateTime,body",
            "$filter": f"receivedDateTime ge {timestamp}",
            "$orderby": "receivedDateTime desc",
            "$top": "10",
        })
        data = self._request_json(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?"
            f"{query}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Prefer": 'outlook.body-content-type="text"',
            },
        )
        messages: list[EmailMessage] = []
        for row in list(data.get("value", []))[:10]:
            try:
                received_at = datetime.fromisoformat(
                    str(row.get("receivedDateTime", "")).replace("Z", "+00:00")
                )
            except ValueError:
                continue
            body = row.get("body", {})
            text = str(body.get("content", ""))[:32768]
            if str(body.get("contentType", "")).lower() == "html":
                extractor = _TextExtractor()
                extractor.feed(text)
                text = extractor.text()[:32768]
            messages.append(EmailMessage(
                sender=str(
                    row.get("sender", {}).get("emailAddress", {}).get("address", "")
                ),
                received_at=received_at,
                text=text,
            ))
        return messages

    @staticmethod
    def _request_json(url: str, form: dict[str, str] | None = None,
                      headers: dict[str, str] | None = None) -> dict:
        body = urlencode(form).encode("utf-8") if form is not None else None
        request_headers = {"Accept": "application/json", **(headers or {})}
        if body is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = Request(url, data=body, headers=request_headers)
        try:
            with urlopen(request, timeout=15) as response:
                raw = response.read(1_000_001)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise ValueError("email provider request failed") from exc
        if len(raw) > 1_000_000:
            raise ValueError("email provider response was too large")
        try:
            result = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("email provider returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ValueError("email provider returned an invalid response")
        return result


class LocalEmailCodeSource:
    def __init__(self, credentials: LocalEmailCredentials,
                 client: MailboxClient | None = None,
                 timeout_seconds: int = 120,
                 credential_path: Path | None = None):
        if not 10 <= timeout_seconds <= 300:
            raise ValueError("email challenge timeout must be 10 to 300 seconds")
        self.credentials = credentials
        self.client = client or MailboxClient()
        self.timeout_seconds = timeout_seconds
        self.credential_path = credential_path

    def get_code(self, rotation_provider: str,
                 requested_after: datetime) -> str | None:
        if requested_after.tzinfo is None:
            raise ValueError("email challenge timestamp must include a timezone")
        domains = set(self.credentials.sender_domains.get(
            rotation_provider.lower(), []
        ))
        if not domains:
            return None
        now = datetime.now(timezone.utc)
        earliest = max(
            requested_after.astimezone(timezone.utc),
            now - timedelta(minutes=5),
        )
        access_token, new_refresh_token = self.client.refresh_access_token(
            self.credentials
        )
        if (
            new_refresh_token
            and new_refresh_token != self.credentials.refresh_token
        ):
            old_refresh_token = self.credentials.refresh_token
            self.credentials.refresh_token = new_refresh_token
            try:
                if self.credential_path is not None:
                    self.credentials.save(self.credential_path)
            except Exception:
                self.credentials.refresh_token = old_refresh_token
                raise
            finally:
                del old_refresh_token
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            found: set[str] = set()
            messages = self.client.recent_messages(
                self.credentials.provider, access_token, earliest
            )
            checked_at = datetime.now(timezone.utc)
            for message in messages:
                if message.received_at.tzinfo is None:
                    continue
                received = message.received_at.astimezone(timezone.utc)
                if not earliest <= received <= checked_at + timedelta(minutes=1):
                    continue
                if _sender_domain(message.sender) not in domains:
                    continue
                found.update(CODE_PATTERN.findall(message.text[:32768]))
            if len(found) == 1:
                code = found.pop()
                del access_token
                return code
            if len(found) > 1:
                del access_token
                return None
            time.sleep(3)
        del access_token
        return None
