from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class EmailProvider(str, Enum):
    GOOGLE = "google"
    MICROSOFT = "microsoft"


@dataclass(frozen=True)
class EmailProviderSpec:
    provider: EmailProvider
    authorization_url: str
    token_url: str
    identity_url: str
    scopes: tuple[str, ...]


PROVIDERS = {
    EmailProvider.GOOGLE: EmailProviderSpec(
        provider=EmailProvider.GOOGLE,
        authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        identity_url="https://openidconnect.googleapis.com/v1/userinfo",
        scopes=(
            "openid", "email",
            "https://www.googleapis.com/auth/gmail.metadata",
        ),
    ),
    EmailProvider.MICROSOFT: EmailProviderSpec(
        provider=EmailProvider.MICROSOFT,
        authorization_url=(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        ),
        token_url=(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        ),
        identity_url=(
            "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName"
        ),
        scopes=(
            "openid", "email", "offline_access",
            "https://graph.microsoft.com/User.Read",
            "https://graph.microsoft.com/Mail.ReadBasic",
        ),
    ),
}


def provider_spec(provider: EmailProvider | str) -> EmailProviderSpec:
    return PROVIDERS[EmailProvider(provider)]


def build_authorization_url(provider: EmailProvider | str, client_id: str,
                            redirect_uri: str, state: str,
                            code_challenge: str) -> str:
    if len(client_id) < 8 or len(state) < 32 or len(code_challenge) < 43:
        raise ValueError("OAuth request values are too short")
    parsed = urlparse(redirect_uri)
    local = parsed.hostname in {"127.0.0.1", "localhost"}
    if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
        raise ValueError("OAuth redirect must use HTTPS except on localhost")
    spec = provider_spec(provider)
    query = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(spec.scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline" if spec.provider is EmailProvider.GOOGLE else "",
        "prompt": "consent" if spec.provider is EmailProvider.GOOGLE else "select_account",
    })
    return f"{spec.authorization_url}?{query}"


def security_message(subject: str, sender: str) -> bool:
    """Conservative metadata-only filter; message bodies remain inaccessible."""
    text = f"{subject} {sender}".lower()
    security_terms = (
        "password changed", "password reset", "security alert",
        "new sign-in", "unusual activity", "verification code",
    )
    return any(term in text for term in security_terms)


@dataclass(frozen=True)
class OAuthTokens:
    email_address: str
    access_token: str
    refresh_token: str
    expires_at: datetime
    scopes: tuple[str, ...]


class OAuthClient:
    """Exchanges an OAuth code and reads only the account identity."""

    def exchange(self, provider: EmailProvider | str, client_id: str,
                 client_secret: str, code: str, redirect_uri: str,
                 code_verifier: str) -> OAuthTokens:
        spec = provider_spec(provider)
        token_data = self._request_json(spec.token_url, {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "scope": " ".join(spec.scopes),
        })
        access_token = str(token_data.get("access_token", ""))
        refresh_token = str(token_data.get("refresh_token", ""))
        if len(access_token) < 20 or len(refresh_token) < 20:
            raise ValueError("OAuth provider did not return reusable credentials")

        identity = self._request_json(
            spec.identity_url, headers={"Authorization": f"Bearer {access_token}"}
        )
        if spec.provider is EmailProvider.GOOGLE:
            email_address = str(identity.get("email", ""))
            if identity.get("email_verified") is not True:
                raise ValueError("Google account email is not verified")
        else:
            email_address = str(
                identity.get("mail") or identity.get("userPrincipalName") or ""
            )
        if "@" not in email_address:
            raise ValueError("OAuth provider did not return an email address")

        try:
            lifetime = int(token_data.get("expires_in", 3600))
        except (TypeError, ValueError) as exc:
            raise ValueError("OAuth provider returned an invalid token lifetime") from exc
        lifetime = max(60, min(lifetime, 86400))
        scope_text = str(token_data.get("scope", "")).strip()
        scopes = tuple(scope_text.split()) if scope_text else spec.scopes
        return OAuthTokens(
            email_address=email_address.lower(), access_token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime),
            scopes=scopes,
        )

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
                data = response.read(1_000_001)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise ValueError("OAuth provider request failed") from exc
        if len(data) > 1_000_000:
            raise ValueError("OAuth provider response was too large")
        try:
            value = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("OAuth provider returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("OAuth provider returned an invalid response")
        return value
