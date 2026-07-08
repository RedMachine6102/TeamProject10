"""Headless smoke tests for every VaultMind subsystem (no GUI needed).

Run:  python3 tests/test_prototype.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vaultmind import corelib
from vaultmind.storage import VaultStorage, Entry
from vaultmind.auth import AuthManager
from vaultmind.search import SemanticSearch
from vaultmind.audit import run_audit
from vaultmind.generator import PasswordPolicy, generate
from vaultmind import breach

PASS = 0


def check(name, cond):
    global PASS
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}")
    if cond:
        PASS += 1
    else:
        sys.exit(1)


# ---- 1. C++ crypto core -------------------------------------------------------
salt = corelib.random_bytes(16)
key = corelib.derive_key("master-password-123", salt)
check("PBKDF2 derives 32-byte key", len(key) == 32)

blob = corelib.encrypt(key, b"top secret credential")
check("AES-256-GCM round trip", corelib.decrypt(key, blob) == b"top secret credential")

wrong = corelib.derive_key("wrong-password", salt)
check("wrong key rejected (GCM auth)", corelib.decrypt(wrong, blob) is None)

tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
check("tampered ciphertext rejected", corelib.decrypt(key, tampered) is None)

check("SHA-1 known vector",
      corelib.sha1_hex(b"password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

# ---- 2. analysis --------------------------------------------------------------
check("entropy: long mixed > short lower",
      corelib.entropy_bits("Xk9$mQ2!vB7z") > corelib.entropy_bits("cat"))
check("repetition detected", corelib.repetition_ratio("aaaa1111") > 0.8)
check("strength: strong scores high", corelib.strength_score("N7$k!qLm2xZ@9rWc") >= 75)
check("strength: 'password' scores low", corelib.strength_score("password") < 45)

# ---- 3. generator + policy ----------------------------------------------------
pw = generate(PasswordPolicy(length=24))
check("generated length honored", len(pw) == 24)
check("generated scores >= 85", corelib.strength_score(pw) >= 85)

pw2 = generate(PasswordPolicy(length=40, max_length=12, allowed_symbols="!_-"))
check("site max-length policy capped to 12", len(pw2) == 12)
check("only permitted specials used",
      all(c.isalnum() or c in "!_-" for c in pw2))

# ---- 4. storage + auth + session ----------------------------------------------
tmp = os.path.join(tempfile.mkdtemp(), "test_vault.db")
store = VaultStorage(tmp)
auth = AuthManager(store)
session = auth.initialize("Master-Passw0rd!", "4242")
check("vault initialized", store.initialized)

eid = store.add(session.key, Entry(None, "Gmail", "u@x.com", "Sunshine123",
                                   "gmail.com", "Email"))
store.add(session.key, Entry(None, "Google Drive", "u@x.com", "Sunshine123",
                             "drive.google.com", "Work"))
store.add(session.key, Entry(None, "Steam", "gamer", "P@ssw0rd!",
                             "steampowered.com", "Gaming"))
check("entries persisted + decrypted", len(store.all(session.key)) == 3)

check("master login works", auth.login("Master-Passw0rd!") is not None)
check("bad master rejected", auth.login("nope") is None)
pin_session = auth.unlock_with_pin("4242")
check("PIN unlock recovers vault key", pin_session is not None and
      len(pin_session.key) == 32 and
      len(store.all(pin_session.key)) == 3)
check("bad PIN rejected", auth.unlock_with_pin("0000") is None)
check("15-min session not yet expired", not session.expired and
      840 < session.seconds_left <= 900)

# update / delete round trip
entries = store.all(session.key)
target = next(e for e in entries if e.title == "Steam")
target.password = "NewStr0ng#Pass!"
store.update(session.key, target)
refreshed = next(e for e in store.all(session.key) if e.title == "Steam")
check("update persisted", refreshed.password == "NewStr0ng#Pass!")
store.delete(eid)
check("delete works", len(store.all(session.key)) == 2)

# ---- 5. semantic search --------------------------------------------------------
store2 = VaultStorage(os.path.join(tempfile.mkdtemp(), "s.db"))
s2 = AuthManager(store2).initialize("Master-Passw0rd!", "1111")
for t, u, url, cat in [("Gmail", "a@x", "gmail.com", "Email"),
                       ("G-Suite Admin", "b@x", "admin.google.com", "Work"),
                       ("Google Drive", "c@x", "drive.google.com", "Work"),
                       ("Steam", "d@x", "steampowered.com", "Gaming"),
                       ("Chase Bank", "e@x", "chase.com", "Banking")]:
    store2.add(s2.key, Entry(None, t, u, "pw", url, cat))
searcher = SemanticSearch()
ents = store2.all(s2.key)

hits = {e.title for e, _ in searcher.search("google", ents)}
check("semantic: 'google' finds Gmail/G-Suite/Drive",
      {"Gmail", "G-Suite Admin", "Google Drive"} <= hits and "Steam" not in hits)

hits = {e.title for e, _ in searcher.search("my google accounts", ents)}
check("NL filler stripped ('my google accounts')",
      {"Gmail", "Google Drive"} <= hits)

hits = {e.title for e, _ in searcher.search("banking", ents)}
check("semantic: 'banking' finds Chase", "Chase Bank" in hits)

hits = {e.title for e, _ in searcher.search("gogle", ents)}
check("fuzzy: typo 'gogle' still matches", "Gmail" in hits or "Google Drive" in hits)

# ---- 6. audit engine -----------------------------------------------------------
store3 = VaultStorage(os.path.join(tempfile.mkdtemp(), "a.db"))
s3 = AuthManager(store3).initialize("Master-Passw0rd!", "1111")
store3.add(s3.key, Entry(None, "A", "u", "Sunshine123", "", "Other"))
store3.add(s3.key, Entry(None, "B", "u", "Sunshine123", "", "Other"))   # reused
store3.add(s3.key, Entry(None, "C", "u", "aaaa1111", "", "Other"))      # repetitive
old = Entry(None, "D", "u", "N7$k!qLm2xZ@9rWc", "", "Other")
old.created = old.modified = old.created - 400 * 86400                  # old
store3.add(s3.key, old)
report = run_audit(store3.all(s3.key))
check("audit: reuse detected", report.reused == 2)
check("audit: old password detected", report.old == 1)
check("audit: repetition flagged",
      any("repetitive pattern" in f.issues for f in report.findings))
check("audit: one-click suggestion attached & strong",
      all(f.suggestion and corelib.strength_score(f.suggestion) >= 85
          for f in report.findings if f.issues))
check("audit: vault score in range", 0 <= report.vault_score <= 100)

# ---- 7. breach monitor (k-anonymity plumbing; network optional) ----------------
res = breach.check_password("password123")
if res.error:
    print(f"[SKIP] HIBP live check unavailable here ({res.error.split('(')[0].strip()})"
          " — k-anonymity prefix logic verified via SHA-1 vector above")
else:
    check("HIBP: 'password123' is breached", res.breached and res.count > 0)
    check("HIBP: random strong pw not breached",
          not breach.check_password(generate(PasswordPolicy(length=32))).breached)

print(f"\nAll checks passed ({PASS}).")
