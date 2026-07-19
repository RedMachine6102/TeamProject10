"""VaultMind pytest suite.

Rewritten from the headless smoke script into independent pytest cases so
every check runs and reports on its own instead of stopping at the first
failure (test plan section 4.1). Network behavior for the breach monitor is
mocked so results don't depend on internet access.

Run:  pytest tests/test_vaultmind.py -v
"""
import os
import sys
import tempfile
import time
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vaultmind import corelib, breach
from vaultmind.storage import VaultStorage, Entry
from vaultmind.auth import AuthManager
from vaultmind.search import SemanticSearch
from vaultmind.audit import run_audit
from vaultmind.generator import PasswordPolicy, generate


@pytest.fixture
def vault(tmp_path):
    """A fresh initialized vault in a temp dir, with its session key."""
    store = VaultStorage(str(tmp_path / "vault.db"))
    session = AuthManager(store).initialize("Master-Passw0rd!", "4242")
    return store, session


# ---- C++ crypto core --------------------------------------------------------
def test_pbkdf2_key_length():
    salt = corelib.random_bytes(16)
    assert len(corelib.derive_key("pw", salt)) == 32


def test_encrypt_decrypt_round_trip():
    key = corelib.derive_key("pw", corelib.random_bytes(16))
    blob = corelib.encrypt(key, b"secret")
    assert corelib.decrypt(key, blob) == b"secret"


def test_wrong_key_rejected():
    salt = corelib.random_bytes(16)
    blob = corelib.encrypt(corelib.derive_key("right", salt), b"secret")
    assert corelib.decrypt(corelib.derive_key("wrong", salt), blob) is None


def test_tampered_ciphertext_rejected():
    key = corelib.derive_key("pw", corelib.random_bytes(16))
    blob = corelib.encrypt(key, b"secret")
    tampered = blob[:-1] + bytes([blob[-1] ^ 0xFF])
    assert corelib.decrypt(key, tampered) is None  # WB-104


def test_sha1_known_vector():
    assert corelib.sha1_hex(b"password") == \
        "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


# ---- analysis ---------------------------------------------------------------
def test_repetition_detected():
    assert corelib.repetition_ratio("aaaa1111") > 0.8  # WB-102


def test_strong_scores_high():
    assert corelib.strength_score("N7$k!qLm2xZ@9rWc") >= 75


@pytest.mark.parametrize("pw", ["password123", "Sunshine123", "12345678", "qwerty"])
def test_common_passwords_downranked(pw):
    """Risk 3: predictable passwords must not score as strong."""
    assert corelib.common_penalty(pw) >= 0.5
    assert corelib.strength_score(pw) < 45


def test_strong_password_not_flagged_common():
    assert corelib.common_penalty("N7$k!qLm2xZ@9rWc") == 0.0


# ---- generator + policy -----------------------------------------------------
def test_generated_length_and_strength():
    pw = generate(PasswordPolicy(length=24))  # WB-103
    assert len(pw) == 24
    assert corelib.strength_score(pw) >= 85


def test_site_max_length_policy():
    pw = generate(PasswordPolicy(length=40, max_length=12, allowed_symbols="!_-"))
    assert len(pw) == 12
    assert all(c.isalnum() or c in "!_-" for c in pw)


# ---- storage / auth / session ----------------------------------------------
def test_entries_persist_and_decrypt(vault):
    store, session = vault
    store.add(session.key, Entry(None, "Gmail", "u@x.com", "pw", "gmail.com", "Email"))
    assert len(store.all(session.key)) == 1


def test_master_login(vault):
    store, _ = vault
    auth = AuthManager(store)
    assert auth.login("Master-Passw0rd!") is not None
    assert auth.login("wrong") is None


def test_pin_unlock(vault):
    store, _ = vault
    session = AuthManager(store).unlock_with_pin("4242")
    assert session is not None and len(session.key) == 32


def test_bad_pin_rejected(vault):
    store, _ = vault
    assert AuthManager(store).unlock_with_pin("0000") is None


def test_session_not_expired_immediately(vault):
    _, session = vault
    assert not session.expired
    assert 840 < session.seconds_left <= 900  # BB-007 boundary


# ---- D-002: integrity failures are surfaced, not hidden ---------------------
def test_corrupted_row_reported_not_skipped_silently(vault):
    store, session = vault
    store.add(session.key, Entry(None, "Good", "u", "pw", "", "Other"))
    store.add(session.key, Entry(None, "Bad", "u", "pw", "", "Other"))
    # tamper with one stored blob directly
    row_id, blob = store._conn.execute(
        "SELECT id, blob FROM entries LIMIT 1").fetchone()
    store._conn.execute("UPDATE entries SET blob=? WHERE id=?",
                        (blob[:-1] + bytes([blob[-1] ^ 0xFF]), row_id))
    store._conn.commit()

    entries = store.all(session.key)
    assert len(entries) == 1                       # bad row not returned
    assert store.has_integrity_failures()          # BUT failure is recorded
    assert row_id in store.last_integrity_failures  # BB-008 / D-002


# ---- D-001: rollback history is kept on replacement -------------------------
def test_password_history_supports_rollback(vault):
    store, session = vault
    e = Entry(None, "Gmail", "u", "OldPass1!", "gmail.com", "Email")
    store.add(session.key, e)
    e.push_history(e.password)
    e.password = "NewStr0ng#Pass!"
    store.update(session.key, e)

    reloaded = store.all(session.key)[0]
    assert reloaded.password == "NewStr0ng#Pass!"
    assert reloaded.history[0]["password"] == "OldPass1!"  # D-001 rollback


# ---- semantic search --------------------------------------------------------
@pytest.fixture
def search_vault(vault):
    store, session = vault
    for t, url, cat in [("Gmail", "gmail.com", "Email"),
                        ("G-Suite Admin", "admin.google.com", "Work"),
                        ("Google Drive", "drive.google.com", "Work"),
                        ("Steam", "steampowered.com", "Gaming"),
                        ("Chase Bank", "chase.com", "Banking")]:
        store.add(session.key, Entry(None, t, "u@x", "pw", url, cat))
    return SemanticSearch(), store.all(session.key)


def test_semantic_google(search_vault):
    searcher, ents = search_vault
    hits = {e.title for e, _ in searcher.search("google", ents)}
    assert {"Gmail", "G-Suite Admin", "Google Drive"} <= hits
    assert "Steam" not in hits


def test_nl_filler_stripped(search_vault):
    searcher, ents = search_vault
    hits = {e.title for e, _ in searcher.search("my google accounts", ents)}
    assert {"Gmail", "Google Drive"} <= hits


def test_fuzzy_typo(search_vault):
    searcher, ents = search_vault
    hits = {e.title for e, _ in searcher.search("gogle", ents)}
    assert "Gmail" in hits or "Google Drive" in hits


# ---- audit engine (WB-101, BB-002..005) -------------------------------------
@pytest.fixture
def audit_report(vault):
    store, session = vault
    store.add(session.key, Entry(None, "A", "u", "Sunshine123", "", "Other"))
    store.add(session.key, Entry(None, "B", "u", "Sunshine123", "", "Other"))  # reuse
    store.add(session.key, Entry(None, "C", "u", "aaaa1111", "", "Other"))      # repetitive
    old = Entry(None, "D", "u", "N7$k!qLm2xZ@9rWc", "", "Other")
    old.created = old.modified = time.time() - 400 * 86400                      # old
    store.add(session.key, old)
    return run_audit(store.all(session.key))


def test_audit_reuse_count(audit_report):
    assert audit_report.reused == 2  # WB-101 / BB-003


def test_audit_old_detected(audit_report):
    assert audit_report.old == 1  # BB-004


def test_audit_repetition_flagged(audit_report):
    assert any("repetitive pattern" in f.issues for f in audit_report.findings)


def test_audit_common_flagged(audit_report):
    # Risk 3: Sunshine123 should now be flagged as a common password
    assert any("common password" in f.issues for f in audit_report.findings)


def test_audit_suggestions_are_strong(audit_report):
    for f in audit_report.findings:
        if f.issues:
            assert f.suggestion and corelib.strength_score(f.suggestion) >= 85  # BB-005


def test_vault_score_in_range(audit_report):
    assert 0 <= audit_report.vault_score <= 100


# ---- breach monitor with MOCKED network (test plan 4.1) ---------------------
def test_breach_detects_pwned_mocked():
    """HIBP match without touching the network."""
    digest = corelib.sha1_hex(b"password123")
    suffix = digest[5:]
    fake_body = f"{suffix}:99999\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"

    fake_resp = mock.MagicMock()
    fake_resp.read.return_value = fake_body.encode()
    fake_resp.__enter__ = lambda s: s
    fake_resp.__exit__ = lambda *a: False

    with mock.patch("urllib.request.urlopen", return_value=fake_resp):
        res = breach.check_password("password123")
    assert res.breached and res.count == 99999


def test_breach_clean_password_mocked():
    fake_resp = mock.MagicMock()
    fake_resp.read.return_value = b"0000000000000000000000000000000000A:5"
    fake_resp.__enter__ = lambda s: s
    fake_resp.__exit__ = lambda *a: False

    with mock.patch("urllib.request.urlopen", return_value=fake_resp):
        res = breach.check_password("N7$k!qLm2xZ@9rWc-unique-xyz")
    assert not res.breached


def test_breach_offline_degrades_gracefully():
    import urllib.error
    with mock.patch("urllib.request.urlopen",
                    side_effect=urllib.error.URLError("offline")):
        res = breach.check_password("anything")
    assert res.error is not None and not res.breached
