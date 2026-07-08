"""ctypes bindings to the VaultMind C++ core (libvaultcore.so)."""
from __future__ import annotations

import ctypes
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = [
    os.path.join(_HERE, "..", "build", "libvaultcore.so"),
    os.path.join(_HERE, "..", "build", "libvaultcore.dylib"),
    os.path.join(_HERE, "..", "build", "vaultcore.dll"),
]


def _load() -> ctypes.CDLL:
    for path in _CANDIDATES:
        if os.path.exists(path):
            return ctypes.CDLL(os.path.abspath(path))
    sys.exit("libvaultcore not found — run ./build.sh first.")


_lib = _load()

_lib.vc_random_bytes.argtypes = [ctypes.c_char_p, ctypes.c_int]
_lib.vc_random_bytes.restype = ctypes.c_int

_lib.vc_derive_key.argtypes = [ctypes.c_char_p, ctypes.c_int,
                               ctypes.c_char_p, ctypes.c_int,
                               ctypes.c_int, ctypes.c_char_p]
_lib.vc_derive_key.restype = ctypes.c_int

_lib.vc_encrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
                            ctypes.c_char_p, ctypes.c_int]
_lib.vc_encrypt.restype = ctypes.c_int

_lib.vc_decrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
                            ctypes.c_char_p, ctypes.c_int]
_lib.vc_decrypt.restype = ctypes.c_int

_lib.vc_sha1_hex.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
_lib.vc_sha1_hex.restype = ctypes.c_int

_lib.vc_entropy_bits.argtypes = [ctypes.c_char_p]
_lib.vc_entropy_bits.restype = ctypes.c_double

_lib.vc_repetition_ratio.argtypes = [ctypes.c_char_p]
_lib.vc_repetition_ratio.restype = ctypes.c_double

_lib.vc_strength_score.argtypes = [ctypes.c_char_p]
_lib.vc_strength_score.restype = ctypes.c_int

_lib.vc_generate_password.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_char_p,
                                      ctypes.c_char_p, ctypes.c_int]
_lib.vc_generate_password.restype = ctypes.c_int

PBKDF2_ITERATIONS = 600_000  # OWASP 2023+ guidance for PBKDF2-HMAC-SHA256


def random_bytes(n: int) -> bytes:
    buf = ctypes.create_string_buffer(n)
    if _lib.vc_random_bytes(buf, n) != 0:
        raise RuntimeError("CSPRNG failure")
    return buf.raw


def derive_key(password: str, salt: bytes,
               iterations: int = PBKDF2_ITERATIONS) -> bytes:
    pw = password.encode("utf-8")
    out = ctypes.create_string_buffer(32)
    if _lib.vc_derive_key(pw, len(pw), salt, len(salt), iterations, out) != 0:
        raise RuntimeError("key derivation failed")
    return out.raw


def encrypt(key32: bytes, plaintext: bytes) -> bytes:
    cap = len(plaintext) + 64
    out = ctypes.create_string_buffer(cap)
    n = _lib.vc_encrypt(key32, plaintext, len(plaintext), out, cap)
    if n < 0:
        raise RuntimeError("encryption failed")
    return out.raw[:n]


def decrypt(key32: bytes, blob: bytes) -> bytes | None:
    """Returns plaintext, or None if the key is wrong / data was tampered."""
    cap = max(len(blob), 32)
    out = ctypes.create_string_buffer(cap)
    n = _lib.vc_decrypt(key32, blob, len(blob), out, cap)
    if n < 0:
        return None
    return out.raw[:n]


def sha1_hex(data: bytes) -> str:
    out = ctypes.create_string_buffer(41)
    if _lib.vc_sha1_hex(data, len(data), out) != 0:
        raise RuntimeError("sha1 failed")
    return out.value.decode("ascii")


def entropy_bits(password: str) -> float:
    return _lib.vc_entropy_bits(password.encode("utf-8"))


def repetition_ratio(password: str) -> float:
    return _lib.vc_repetition_ratio(password.encode("utf-8"))


def strength_score(password: str) -> int:
    return _lib.vc_strength_score(password.encode("utf-8"))


def generate_password(length: int = 20, use_upper: bool = True,
                      use_digits: bool = True, use_symbols: bool = True,
                      allowed_symbols: str | None = None) -> str:
    cap = length + 1
    out = ctypes.create_string_buffer(cap)
    sym = allowed_symbols.encode("utf-8") if allowed_symbols else None
    rc = _lib.vc_generate_password(length, int(use_upper), int(use_digits),
                                   int(use_symbols), sym, out, cap)
    if rc != 0:
        raise ValueError("generation failed (length too short for policy?)")
    return out.value.decode("ascii")
