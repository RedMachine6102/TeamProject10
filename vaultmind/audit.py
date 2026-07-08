"""AI password audit engine.

Design-doc requirement: evaluate every password in the vault for
entropy, repetition, and time-in-use, and offer a one-click upgrade to
a stronger password.

The numeric heavy lifting (entropy, repetition analysis, strength
scoring) runs in the C++ core; this module orchestrates the vault-wide
sweep, detects reuse across entries, and produces the recommendation
plus the ready-to-apply replacement password.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import corelib
from .storage import Entry
from .generator import PasswordPolicy, generate

OLD_AGE_DAYS = 180
WEAK_SCORE = 60
LOW_ENTROPY_BITS = 50.0


@dataclass
class Finding:
    entry: Entry
    score: int
    entropy: float
    repetition: float
    age_days: int
    issues: list[str] = field(default_factory=list)
    suggestion: str | None = None   # one-click replacement

    @property
    def severity(self) -> str:
        if self.score < 35 or "breached" in self.issues:
            return "critical"
        if self.issues:
            return "warning"
        return "ok"


@dataclass
class AuditReport:
    findings: list[Finding]
    vault_score: int
    weak: int
    reused: int
    old: int


def run_audit(entries: list[Entry],
              policy: PasswordPolicy | None = None) -> AuditReport:
    policy = policy or PasswordPolicy()

    # reuse detection across the whole vault
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.password] = counts.get(e.password, 0) + 1

    findings: list[Finding] = []
    weak = reused = old = 0

    for e in entries:
        score = corelib.strength_score(e.password)
        ent = corelib.entropy_bits(e.password)
        rep = corelib.repetition_ratio(e.password)
        age = e.age_days()
        issues: list[str] = []

        if score < WEAK_SCORE:
            issues.append("weak")
            weak += 1
        if ent < LOW_ENTROPY_BITS:
            issues.append("low entropy")
        if rep > 0.30:
            issues.append("repetitive pattern")
        if counts[e.password] > 1:
            issues.append("reused")
            reused += 1
        if age > OLD_AGE_DAYS:
            issues.append(f"in use {age}d")
            old += 1

        suggestion = generate(policy) if issues else None
        findings.append(Finding(e, score, ent, rep, age, issues, suggestion))

    if entries:
        avg = sum(f.score for f in findings) / len(findings)
        penalty = 6 * reused + 3 * old
        vault_score = max(0, min(100, int(avg - penalty / max(1, len(entries)) * 10)))
    else:
        vault_score = 100

    findings.sort(key=lambda f: f.score)
    return AuditReport(findings, vault_score, weak, reused, old)
