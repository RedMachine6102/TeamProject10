"""Encrypted vault storage.

Each credential is serialized to JSON and encrypted as a single
AES-256-GCM blob by the C++ core before it touches disk. SQLite only
ever sees ciphertext; the vault key never leaves memory.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field, asdict

from . import corelib

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vault.db")


@dataclass
class Entry:
    id: int | None
    title: str
    username: str
    password: str
    url: str = ""
    category: str = "Other"
    notes: str = ""
    created: float = field(default_factory=time.time)
    modified: float = field(default_factory=time.time)

    def age_days(self) -> int:
        return int((time.time() - self.modified) / 86400)


class VaultStorage:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = os.path.abspath(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS entries "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
        self._conn.commit()

    # ---- meta ------------------------------------------------------------
    def get_meta(self, key: str) -> bytes | None:
        row = self._conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: bytes) -> None:
        self._conn.execute(
            "INSERT INTO meta(k, v) VALUES(?, ?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
        self._conn.commit()

    @property
    def initialized(self) -> bool:
        return self.get_meta("salt") is not None

    # ---- entries ---------------------------------------------------------
    def add(self, key: bytes, entry: Entry) -> int:
        blob = corelib.encrypt(key, json.dumps(asdict(entry)).encode())
        cur = self._conn.execute("INSERT INTO entries(blob) VALUES(?)", (blob,))
        self._conn.commit()
        entry.id = cur.lastrowid
        return entry.id

    def update(self, key: bytes, entry: Entry) -> None:
        entry.modified = time.time()
        blob = corelib.encrypt(key, json.dumps(asdict(entry)).encode())
        self._conn.execute("UPDATE entries SET blob=? WHERE id=?", (blob, entry.id))
        self._conn.commit()

    def delete(self, entry_id: int) -> None:
        self._conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self._conn.commit()

    def all(self, key: bytes) -> list[Entry]:
        out: list[Entry] = []
        for row_id, blob in self._conn.execute("SELECT id, blob FROM entries"):
            pt = corelib.decrypt(key, blob)
            if pt is None:
                continue  # wrong key or corrupted row
            d = json.loads(pt)
            d["id"] = row_id
            out.append(Entry(**d))
        return out

    def close(self) -> None:
        self._conn.close()
