"""Breach monitor — HaveIBeenPwned via the k-anonymity protocol.

Design-doc requirement: the SHA-1 k-anonymity range API is used so that
no password (and no full password hash) ever leaves the machine.

Protocol:
  1. SHA-1 the password locally (C++ core).
  2. Send ONLY the first 5 hex characters to
     https://api.pwnedpasswords.com/range/{prefix}
  3. HIBP returns every known-breached suffix sharing that prefix
     (typically ~800 candidates), and the match is checked locally.
"""
from __future__ import annotations

import urllib.request
import urllib.error

from . import corelib

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
TIMEOUT_S = 8


class BreachResult:
    def __init__(self, breached: bool, count: int = 0, error: str | None = None):
        self.breached = breached
        self.count = count
        self.error = error


def check_password(password: str) -> BreachResult:
    digest = corelib.sha1_hex(password.encode("utf-8"))
    prefix, suffix = digest[:5], digest[5:]
    try:
        req = urllib.request.Request(
            HIBP_RANGE_URL + prefix,
            headers={"User-Agent": "VaultMind-Prototype",
                     "Add-Padding": "true"})   # HIBP padding hides response size
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return BreachResult(False, error=f"offline / unreachable ({exc})")

    for line in body.splitlines():
        cand, _, count = line.partition(":")
        if cand.strip().upper() == suffix:
            try:
                return BreachResult(True, int(count.strip() or 0))
            except ValueError:
                return BreachResult(True, 0)
    return BreachResult(False, 0)
