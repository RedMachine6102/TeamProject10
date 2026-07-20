from __future__ import annotations

import hmac
import secrets
import threading

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from fastapi import FastAPI
from pydantic import BaseModel, Field


class PasswordChange(BaseModel):
    username: str = Field(min_length=3, max_length=320)
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=16, max_length=1024)


class PasswordVerification(BaseModel):
    username: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChallenge(PasswordChange):
    challenge_id: str = Field(min_length=16, max_length=256)
    code: str = Field(pattern=r"^\d{6,8}$")


class DemoAccount:
    def __init__(self, username: str, password: str,
                 verification_code: str | None = None):
        if verification_code is not None and (
            not verification_code.isdigit()
            or not 6 <= len(verification_code) <= 8
        ):
            raise ValueError("verification code must contain 6 to 8 digits")
        self.username = username
        self._lock = threading.Lock()
        self._salt = secrets.token_bytes(16)
        self._password_hash = self._hash(password, self._salt)
        self._code_key = secrets.token_bytes(32)
        self._code_hash = (
            self._hash_code(verification_code) if verification_code else None
        )
        self._pending: tuple[str, bytes, bytes] | None = None

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1).derive(
            password.encode("utf-8")
        )

    def _hash_code(self, code: str) -> bytes:
        return hmac.digest(self._code_key, code.encode("ascii"), "sha256")

    def verify(self, username: str, password: str) -> bool:
        candidate = self._hash(password, self._salt)
        return hmac.compare_digest(username, self.username) and hmac.compare_digest(
            candidate, self._password_hash
        )

    def change(self, username: str, current_password: str,
               new_password: str) -> bool | str:
        with self._lock:
            if not self.verify(username, current_password):
                return False
            salt = secrets.token_bytes(16)
            password_hash = self._hash(new_password, salt)
            if self._code_hash is not None:
                challenge_id = secrets.token_urlsafe(24)
                self._pending = (challenge_id, salt, password_hash)
                return challenge_id
            self._salt = salt
            self._password_hash = password_hash
            return True

    def complete_challenge(self, request: PasswordChallenge) -> bool:
        with self._lock:
            if self._pending is None:
                return False
            challenge_id, salt, password_hash = self._pending
            supplied_hash = self._hash(request.new_password, salt)
            valid = (
                self.verify(request.username, request.current_password)
                and hmac.compare_digest(request.challenge_id, challenge_id)
                and hmac.compare_digest(
                    self._hash_code(request.code), self._code_hash or b""
                )
                and hmac.compare_digest(supplied_hash, password_hash)
            )
            if not valid:
                return False
            self._salt = salt
            self._password_hash = password_hash
            self._pending = None
            return True


def create_demo_provider(username: str, password: str,
                         verification_code: str | None = None) -> FastAPI:
    account = DemoAccount(username, password, verification_code)
    app = FastAPI(title="VaultMind Demo Provider", docs_url=None, redoc_url=None)

    @app.post("/password/change")
    def change_password(request: PasswordChange) -> dict:
        result = account.change(
            request.username, request.current_password, request.new_password
        )
        if isinstance(result, str):
            return {
                "ok": False,
                "challenge_required": True,
                "challenge_id": result,
            }
        return {"ok": result}

    @app.post("/password/challenge")
    def complete_challenge(request: PasswordChallenge) -> dict[str, bool]:
        return {"ok": account.complete_challenge(request)}

    @app.post("/session/verify")
    def verify_password(request: PasswordVerification) -> dict[str, bool]:
        return {"ok": account.verify(request.username, request.password)}

    return app
