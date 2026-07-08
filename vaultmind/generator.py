"""AI password suggestion — policy-aware generation.

Design-doc requirement: suggestions must respect site password
guidelines, e.g. a maximum length and a whitelist of permitted special
characters. Generation itself (CSPRNG, unbiased sampling, class
coverage) happens in the C++ core.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import corelib


@dataclass
class PasswordPolicy:
    length: int = 20
    max_length: int | None = None          # site-imposed cap
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    allowed_symbols: str | None = None     # site-permitted specials, e.g. "!@#_-"

    def effective_length(self) -> int:
        n = self.length
        if self.max_length is not None:
            n = min(n, self.max_length)
        return max(4, n)


def generate(policy: PasswordPolicy | None = None) -> str:
    policy = policy or PasswordPolicy()
    return corelib.generate_password(
        length=policy.effective_length(),
        use_upper=policy.use_upper,
        use_digits=policy.use_digits,
        use_symbols=policy.use_symbols,
        allowed_symbols=policy.allowed_symbols,
    )


def analyze(password: str) -> dict:
    return {
        "entropy_bits": corelib.entropy_bits(password),
        "repetition": corelib.repetition_ratio(password),
        "score": corelib.strength_score(password),
    }
