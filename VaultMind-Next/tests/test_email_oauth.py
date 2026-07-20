import base64
import hashlib
import threading
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import urlopen

import pytest

from vaultmind_agent.email_challenge import MailboxClient
from vaultmind_agent.email_oauth import (
    MAIL_SCOPES,
    NativeMailboxOAuth,
    build_authorization_url,
)


class FakeMailboxClient:
    def __init__(self):
        self.exchange: tuple | None = None

    def exchange_authorization_code(
        self, provider: str, client_id: str, client_secret: str,
        code: str, verifier: str, redirect_uri: str,
    ) -> str:
        self.exchange = (
            provider, client_id, client_secret, code, verifier, redirect_uri,
        )
        return "refresh-token-value-long-enough"


class RecordingMailboxClient(MailboxClient):
    def __init__(self):
        self.request: tuple | None = None

    def _request_json(self, url: str, form=None, headers=None) -> dict:
        self.request = (url, form, headers)
        return {"refresh_token": "refresh-token-value-long-enough"}


class CallbackBrowser:
    def __init__(self, wrong_state: bool = False):
        self.authorization_url = ""
        self.wrong_state = wrong_state
        self.response_body = ""
        self.thread: threading.Thread | None = None

    def __call__(self, authorization_url: str) -> bool:
        self.authorization_url = authorization_url
        values = parse_qs(urlparse(authorization_url).query)
        state = "wrong-state" if self.wrong_state else values["state"][0]
        callback_url = (
            f"{values['redirect_uri'][0]}?"
            + urlencode({
                "code": "authorization-code-value-long-enough",
                "state": state,
            })
        )

        def send_callback() -> None:
            with urlopen(callback_url, timeout=5) as response:
                self.response_body = response.read().decode()

        self.thread = threading.Thread(target=send_callback, daemon=True)
        self.thread.start()
        return True


@pytest.mark.parametrize("provider", ["google", "microsoft"])
def test_native_oauth_uses_state_pkce_and_narrow_mail_scope(provider):
    url = build_authorization_url(
        provider,
        "client-id-value-12345",
        "http://127.0.0.1:34567",
        "random-state-value",
        "pkce-challenge-value",
    )
    values = parse_qs(urlparse(url).query)
    assert values["response_type"] == ["code"]
    assert values["state"] == ["random-state-value"]
    assert values["code_challenge"] == ["pkce-challenge-value"]
    assert values["code_challenge_method"] == ["S256"]
    assert values["scope"] == [MAIL_SCOPES[provider]]
    if provider == "google":
        assert values["access_type"] == ["offline"]
        assert values["prompt"] == ["consent"]
    else:
        assert values["response_mode"] == ["query"]
        assert values["prompt"] == ["select_account"]


@pytest.mark.parametrize("provider", ["google", "microsoft"])
def test_native_oauth_receives_loopback_code_and_returns_credentials(provider):
    client = FakeMailboxClient()
    browser = CallbackBrowser()
    credentials = NativeMailboxOAuth(client, browser).connect(
        provider=provider,
        client_id="client-id-value-12345",
        client_secret="",
        sender_domains={"demo": ["Accounts.Example"]},
        timeout_seconds=30,
    )
    browser.thread.join(timeout=5)
    assert credentials.provider == provider
    assert credentials.refresh_token == "refresh-token-value-long-enough"
    assert credentials.sender_domains == {"demo": ["accounts.example"]}
    assert client.exchange is not None
    assert client.exchange[0] == provider
    assert 43 <= len(client.exchange[4]) <= 128
    assert client.exchange[5].startswith(
        "http://127.0.0.1:" if provider == "google" else "http://localhost:"
    )
    verifier = client.exchange[4]
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    authorization = parse_qs(urlparse(browser.authorization_url).query)
    assert authorization["code_challenge"] == [expected_challenge]
    assert browser.thread.is_alive() is False
    assert "close this window" in browser.response_body
    assert "authorization-code-value" not in browser.response_body


@pytest.mark.parametrize("provider", ["google", "microsoft"])
def test_authorization_code_exchange_sends_verifier_without_logging(provider):
    client = RecordingMailboxClient()
    token = client.exchange_authorization_code(
        provider=provider,
        client_id="client-id-value-12345",
        client_secret="",
        code="authorization-code-value-long-enough",
        verifier="v" * 64,
        redirect_uri="http://localhost:34567",
    )
    assert token == "refresh-token-value-long-enough"
    url, form, headers = client.request
    assert url.startswith("https://")
    assert form["grant_type"] == "authorization_code"
    assert form["code_verifier"] == "v" * 64
    assert "client_secret" not in form
    assert headers is None
    if provider == "microsoft":
        assert "offline_access" in form["scope"]
    else:
        assert "scope" not in form


def test_native_oauth_rejects_wrong_callback_state():
    client = FakeMailboxClient()
    browser = CallbackBrowser(wrong_state=True)
    with pytest.raises(ValueError, match="response was invalid"):
        NativeMailboxOAuth(client, browser).connect(
            provider="google",
            client_id="client-id-value-12345",
            client_secret="",
            sender_domains={"demo": ["accounts.example"]},
            timeout_seconds=30,
        )
    browser.thread.join(timeout=5)
    assert client.exchange is None


def test_native_oauth_validates_sender_allowlist_before_opening_browser():
    opened = False

    def opener(url: str) -> bool:
        nonlocal opened
        opened = True
        return True

    with pytest.raises(ValueError, match="sender domain"):
        NativeMailboxOAuth(FakeMailboxClient(), opener).connect(
            provider="google",
            client_id="client-id-value-12345",
            client_secret="",
            sender_domains={"demo": ["not-a-domain"]},
            timeout_seconds=30,
        )
    assert opened is False
