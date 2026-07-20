import base64
import os
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from vaultmind_next.backup import (
    backup_is_fresh, create_backup, load_backup_key, prune_backups,
    restore_backup, verify_backup,
)
from vaultmind_next.storage import Database


def populated_database(path: Path) -> None:
    database = Database(str(path))
    database.close()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE backup_probe (secret TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO backup_probe VALUES (?)", ("backup-secret-marker",)
        )
        connection.commit()


def test_encrypted_backup_verifies_and_restores_database(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "vaultmind-test.vmbak"
    restored = tmp_path / "restored.db"
    populated_database(source)
    key = secrets.token_bytes(32)

    created = create_backup(source, backup, key)
    encrypted = backup.read_bytes()
    assert b"SQLite format 3" not in encrypted
    assert b"backup-secret-marker" not in encrypted
    assert verify_backup(backup, key)["database_sha256"] == created["database_sha256"]

    restore_backup(backup, restored, key)
    with closing(sqlite3.connect(restored)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute(
            "SELECT secret FROM backup_probe"
        ).fetchone()[0] == "backup-secret-marker"


def test_backup_rejects_wrong_key_and_tampering(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "vaultmind-test.vmbak"
    populated_database(source)
    key = secrets.token_bytes(32)
    create_backup(source, backup, key)

    with pytest.raises(ValueError, match="authentication failed"):
        verify_backup(backup, secrets.token_bytes(32))

    changed = bytearray(backup.read_bytes())
    changed[-20] ^= 1
    tampered = tmp_path / "tampered.vmbak"
    tampered.write_bytes(changed)
    with pytest.raises(ValueError, match="authentication failed"):
        verify_backup(tampered, key)


def test_backup_key_validation_and_retention(tmp_path):
    encoded = base64.b64encode(bytes(range(32))).decode("ascii")
    assert load_backup_key(encoded) == bytes(range(32))
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        load_backup_key(base64.b64encode(b"short").decode("ascii"))

    backups = []
    for index in range(4):
        path = tmp_path / f"vaultmind-{index}.vmbak"
        path.write_bytes(b"test")
        os.utime(path, (index + 1, index + 1))
        backups.append(path)
    removed = prune_backups(tmp_path, retain=2)
    assert removed == [backups[1], backups[0]]
    assert sorted(path.name for path in tmp_path.glob("*.vmbak")) == [
        "vaultmind-2.vmbak", "vaultmind-3.vmbak",
    ]
    assert backup_is_fresh(tmp_path, interval_hours=1, now=3604)
    assert not backup_is_fresh(tmp_path, interval_hours=1, now=7205)
