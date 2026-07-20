"""Pure-Python security core for the VaultMind web demo.

This mirrors the API of the desktop app's C++ core (`vaultmind.corelib`) so
the storage, auth, audit, search, generator, and breach modules can run
unchanged in an environment where the compiled C++ library can't be built
(e.g. Streamlit Community Cloud).

Same algorithms as the desktop build:
  - PBKDF2-HMAC-SHA256 key derivation
  - AES-256-GCM authenticated encryption ([12B nonce][ciphertext][16B tag])
  - SHA-1 for HaveIBeenPwned k-anonymity
The C++ build remains the production security core; this exists only so the
identical features are demonstrable in a browser.
"""
from __future__ import annotations

import hashlib
import math
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 600_000

_COMMON_TOKENS = [
    "password", "passwd", "qwerty", "asdf", "zxcv", "admin", "login",
    "welcome", "letmein", "monkey", "dragon", "master", "shadow", "abc123",
    "iloveyou", "sunshine", "princess", "football", "baseball", "superman",
    "trustno1", "whatever", "starwars", "hello", "test", "guest", "root",
    "111111", "123456", "12345678", "000000", "654321", "121212", "696969",
]


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def derive_key(password: str, salt: bytes,
               iterations: int = PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def encrypt(key32: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key32).encrypt(nonce, plaintext, None)  # ct includes 16B tag
    return nonce + ct


def decrypt(key32: bytes, blob: bytes) -> bytes | None:
    if len(blob) < 12 + 16:
        return None
    nonce, ct = blob[:12], blob[12:]
    try:
        return AESGCM(key32).decrypt(nonce, ct, None)
    except Exception:
        return None  # wrong key or tampered data (auth failure)


def sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest().upper()


# ---- password analysis (mirrors the C++ scoring) ----------------------------
def entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 33
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def repetition_ratio(password: str) -> float:
    if len(password) < 2:
        return 0.0
    weak = sum(1 for i in range(1, len(password))
               if abs(ord(password[i]) - ord(password[i - 1])) <= 1)
    return weak / (len(password) - 1)


def common_penalty(password: str) -> float:
    if not password:
        return 0.0
    low = password.lower()
    n = len(low)
    penalty = 0.0
    for tok in _COMMON_TOKENS:
        if tok in low:
            penalty = max(penalty, 0.5 + 0.5 * (len(tok) / n))
    m = re.search(r"(\d+)$", low)
    if m and len(m.group(1)) >= 3 and len(m.group(1)) >= n - len(m.group(1)):
        penalty = max(penalty, 0.6)
    if low.isdigit() and n <= 10:
        penalty = max(penalty, 0.7)
    return min(1.0, penalty)


def strength_score(password: str) -> int:
    if not password:
        return 0
    base = min(100.0, entropy_bits(password) / 80.0 * 100.0)
    base *= (1.0 - 0.6 * repetition_ratio(password))
    common = common_penalty(password)
    if common > 0.0:
        base *= (1.0 - 0.7 * common)
        base = min(base, 40.0 * (1.0 - common))
    classes = sum([
        any(c.islower() for c in password), any(c.isupper() for c in password),
        any(c.isdigit() for c in password), any(not c.isalnum() for c in password),
    ])
    if classes == 1:
        base = min(base, 55.0)
    elif classes == 2:
        base = min(base, 80.0)
    return max(0, min(100, round(base)))


def generate_password(length: int = 20, use_upper: bool = True,
                      use_digits: bool = True, use_symbols: bool = True,
                      allowed_symbols: str | None = None) -> str:
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = allowed_symbols if allowed_symbols else "!@#$%^&*()-_=+[]{};:,.?"
    pool = lower + (upper if use_upper else "") + \
        (digits if use_digits else "") + (symbols if use_symbols else "")
    enabled = 1 + use_upper + use_digits + use_symbols
    if length < enabled:
        raise ValueError("length too short for the selected policy")
    for _ in range(64):
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if (any(c in lower for c in pw)
                and (not use_upper or any(c in upper for c in pw))
                and (not use_digits or any(c in digits for c in pw))
                and (not use_symbols or any(c in symbols for c in pw))):
            return pw
    raise ValueError("generation failed")
