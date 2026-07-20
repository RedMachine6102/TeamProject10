from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from .email_challenge import (
    LocalEmailCredentials,
    MailboxClient,
    normalize_sender_domains,
)

AUTHORIZATION_ENDPOINTS = {
    "google": "https://accounts.google.com/o/oauth2/v2/auth",
    "microsoft": (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    ),
}
MAIL_SCOPES = {
    "google": "https://www.googleapis.com/auth/gmail.readonly",
    "microsoft": (
        "openid email offline_access https://graph.microsoft.com/Mail.Read"
    ),
}


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorization_url(
    provider: str, client_id: str, redirect_uri: str,
    state: str, challenge: str,
) -> str:
    endpoint = AUTHORIZATION_ENDPOINTS.get(provider)
    scope = MAIL_SCOPES.get(provider)
    if endpoint is None or scope is None:
        raise ValueError("unsupported local email provider")
    values = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if provider == "google":
        values["access_type"] = "offline"
        values["prompt"] = "consent"
    else:
        values["response_mode"] = "query"
        values["prompt"] = "select_account"
    return f"{endpoint}?{urlencode(values)}"


class _CallbackHandler(BaseHTTPRequestHandler):
    result: dict[str, str] | None = None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            values = parse_qs(
                parsed.query, keep_blank_values=True, max_num_fields=8
            )
        except ValueError:
            self.send_error(400)
            return
        codes = values.get("code", [])
        states = values.get("state", [])
        errors = values.get("error", [])
        if (
            parsed.path != "/"
            or len(codes) > 1
            or len(states) != 1
            or len(errors) > 1
        ):
            self.send_error(400)
            return
        code = codes[0] if codes else ""
        state = states[0]
        error = errors[0] if errors else ""
        if len(code) > 4096 or len(state) > 256:
            self.send_error(400)
            return
        type(self).result = {
            "code": code,
            "state": state,
            "error": error[:128],
        }
        body = (
            b"<!doctype html><meta charset=utf-8>"
            b"<title>Authorization received</title>"
            b"<p>You can close this window and return to VaultMind.</p>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class NativeMailboxOAuth:
    def __init__(
        self, client: MailboxClient | None = None,
        opener: Callable[[str], bool] | None = None,
    ):
        self.client = client or MailboxClient()
        self.opener = opener or webbrowser.open

    def connect(
        self, provider: str, client_id: str, client_secret: str,
        sender_domains: dict[str, list[str]], timeout_seconds: int = 180,
    ) -> LocalEmailCredentials:
        provider = provider.lower()
        if provider not in AUTHORIZATION_ENDPOINTS:
            raise ValueError("unsupported local email provider")
        if len(client_id) < 8:
            raise ValueError("OAuth client id is incomplete")
        if not 30 <= timeout_seconds <= 300:
            raise ValueError("OAuth timeout must be 30 to 300 seconds")
        sender_domains = normalize_sender_domains(
            sender_domains, allow_empty=True
        )

        host = "127.0.0.1" if provider == "google" else "localhost"
        _CallbackHandler.result = None
        server = HTTPServer((host, 0), _CallbackHandler)
        server.timeout = 1
        port = server.server_address[1]
        redirect_uri = f"http://{host}:{port}"
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = _pkce_challenge(verifier)
        authorization_url = build_authorization_url(
            provider, client_id, redirect_uri, state, challenge
        )
        try:
            if not self.opener(authorization_url):
                raise ValueError("the system browser could not be opened")
            result = self._wait_for_callback(server, timeout_seconds)
            if result["error"]:
                raise ValueError("email authorization was declined or failed")
            if (
                not result["code"]
                or not hmac.compare_digest(result["state"], state)
            ):
                raise ValueError("email authorization response was invalid")
            refresh_token = self.client.exchange_authorization_code(
                provider, client_id, client_secret, result["code"],
                verifier, redirect_uri,
            )
            return LocalEmailCredentials(
                provider=provider,
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
                sender_domains=sender_domains,
            )
        finally:
            server.server_close()
            _CallbackHandler.result = None
            del state
            del verifier

    @staticmethod
    def _wait_for_callback(
        server: HTTPServer, timeout_seconds: int,
    ) -> dict[str, str]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            server.handle_request()
            if _CallbackHandler.result is not None:
                return _CallbackHandler.result
        raise ValueError("email authorization timed out")
