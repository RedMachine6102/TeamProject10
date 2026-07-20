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


class DemoAccount:
    def __init__(self, username: str, password: str):
        self.username = username
        self._lock = threading.Lock()
        self._salt = secrets.token_bytes(16)
        self._password_hash = self._hash(password, self._salt)

    @staticmethod
    def _hash(password: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1).derive(
            password.encode("utf-8")
        )

    def verify(self, username: str, password: str) -> bool:
        candidate = self._hash(password, self._salt)
        return hmac.compare_digest(username, self.username) and hmac.compare_digest(
            candidate, self._password_hash
        )

    def change(self, username: str, current_password: str,
               new_password: str) -> bool:
        with self._lock:
            if not self.verify(username, current_password):
                return False
            salt = secrets.token_bytes(16)
            password_hash = self._hash(new_password, salt)
            self._salt = salt
            self._password_hash = password_hash
            return True


def create_demo_provider(username: str, password: str) -> FastAPI:
    account = DemoAccount(username, password)
    app = FastAPI(title="VaultMind Demo Provider", docs_url=None, redoc_url=None)

    @app.post("/password/change")
    def change_password(request: PasswordChange) -> dict[str, bool]:
        return {"ok": account.change(
            request.username, request.current_password, request.new_password
        )}

    @app.post("/session/verify")
    def verify_password(request: PasswordVerification) -> dict[str, bool]:
        return {"ok": account.verify(request.username, request.password)}

    return app
