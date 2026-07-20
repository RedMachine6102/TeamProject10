from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import signal
import sqlite3
import struct
import tempfile
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


MAGIC = b"VMBAK1\n"
TAG_BYTES = 16
CHUNK_BYTES = 1024 * 1024
REQUIRED_TABLES = {"audit_events", "users", "vault_items"}


def load_backup_key(value: str | None = None) -> bytes:
    encoded = value if value is not None else os.getenv("VAULTMIND_BACKUP_KEY", "")
    try:
        key = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ValueError("VAULTMIND_BACKUP_KEY must be valid base64") from exc
    if len(key) != 32:
        raise ValueError("VAULTMIND_BACKUP_KEY must encode exactly 32 bytes")
    return key


def snapshot_database(database: Path, destination: Path) -> None:
    if not database.is_file():
        raise FileNotFoundError(f"database does not exist: {database}")
    uri = f"file:{database.resolve().as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as source:
        with closing(sqlite3.connect(destination)) as target:
            source.backup(target)
    _check_database(destination)


def create_backup(database: Path, output: Path, key: bytes) -> dict[str, object]:
    if output.exists():
        raise FileExistsError(f"backup already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vaultmind-backup-") as directory:
        snapshot = Path(directory) / "snapshot.db"
        snapshot_database(database, snapshot)
        header = _encrypt_file(snapshot, output, key)
    _restrict_file(output)
    return header


def verify_backup(backup: Path, key: bytes) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="vaultmind-verify-") as directory:
        restored = Path(directory) / "restored.db"
        header = _decrypt_file(backup, restored, key)
        _check_database(restored)
    return header


def restore_backup(backup: Path, database: Path, key: bytes,
                   force: bool = False) -> dict[str, object]:
    if database.exists() and not force:
        raise FileExistsError("restore target exists; stop services and use --force")
    database.parent.mkdir(parents=True, exist_ok=True)
    temporary = database.with_name(f".{database.name}.{secrets.token_hex(6)}.restore")
    try:
        header = _decrypt_file(backup, temporary, key)
        _check_database(temporary)
        _restrict_file(temporary)
        os.replace(temporary, database)
        return header
    finally:
        temporary.unlink(missing_ok=True)


def prune_backups(directory: Path, retain: int) -> list[Path]:
    if retain < 2:
        raise ValueError("at least two backups must be retained")
    backups = sorted(
        directory.glob("vaultmind-*.vmbak"),
        key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True,
    )
    removed = backups[retain:]
    for path in removed:
        path.unlink()
    return removed


def newest_backup(directory: Path) -> Path:
    backups = list(directory.glob("vaultmind-*.vmbak"))
    if not backups:
        raise FileNotFoundError("no VaultMind backups were found")
    return max(backups, key=lambda path: (path.stat().st_mtime_ns, path.name))


def backup_is_fresh(directory: Path, interval_hours: int,
                    now: float | None = None) -> bool:
    try:
        backup = newest_backup(directory)
        age = (now if now is not None else time.time()) - backup.stat().st_mtime
    except OSError:
        return False
    return age <= (interval_hours + 1) * 3600


def _encrypt_file(source: Path, output: Path, key: bytes) -> dict[str, object]:
    if len(key) != 32:
        raise ValueError("backup key must contain 32 bytes")
    nonce = secrets.token_bytes(12)
    header: dict[str, object] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database_bytes": source.stat().st_size,
        "database_sha256": _file_hash(source),
        "format": 1,
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    encoded_header = json.dumps(
        header, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(encoded_header)
    temporary = output.with_name(f".{output.name}.{secrets.token_hex(6)}.tmp")
    try:
        with source.open("rb") as plain, temporary.open("xb") as encrypted:
            encrypted.write(MAGIC)
            encrypted.write(struct.pack(">I", len(encoded_header)))
            encrypted.write(encoded_header)
            while chunk := plain.read(CHUNK_BYTES):
                encrypted.write(encryptor.update(chunk))
            encrypted.write(encryptor.finalize())
            encrypted.write(encryptor.tag)
            encrypted.flush()
            os.fsync(encrypted.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return header


def _decrypt_file(source: Path, output: Path, key: bytes) -> dict[str, object]:
    if len(key) != 32:
        raise ValueError("backup key must contain 32 bytes")
    size = source.stat().st_size
    with source.open("rb") as encrypted:
        if encrypted.read(len(MAGIC)) != MAGIC:
            raise ValueError("file is not a VaultMind backup")
        length_bytes = encrypted.read(4)
        if len(length_bytes) != 4:
            raise ValueError("backup header is truncated")
        header_length = struct.unpack(">I", length_bytes)[0]
        if not 32 <= header_length <= 4096:
            raise ValueError("backup header length is invalid")
        encoded_header = encrypted.read(header_length)
        try:
            header = json.loads(encoded_header)
            nonce = base64.b64decode(
                header["nonce"], altchars=b"-_", validate=True
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("backup header is invalid") from exc
        if header.get("format") != 1 or len(nonce) != 12:
            raise ValueError("backup format is unsupported")
        ciphertext_start = len(MAGIC) + 4 + header_length
        ciphertext_bytes = size - ciphertext_start - TAG_BYTES
        if ciphertext_bytes <= 0:
            raise ValueError("backup ciphertext is missing")
        encrypted.seek(size - TAG_BYTES)
        tag = encrypted.read(TAG_BYTES)
        encrypted.seek(ciphertext_start)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(encoded_header)
        try:
            with output.open("xb") as plain:
                remaining = ciphertext_bytes
                while remaining:
                    chunk = encrypted.read(min(CHUNK_BYTES, remaining))
                    if not chunk:
                        raise ValueError("backup ciphertext is truncated")
                    remaining -= len(chunk)
                    plain.write(decryptor.update(chunk))
                plain.write(decryptor.finalize())
        except InvalidTag as exc:
            output.unlink(missing_ok=True)
            raise ValueError("backup authentication failed") from exc
    if output.stat().st_size != header.get("database_bytes"):
        output.unlink(missing_ok=True)
        raise ValueError("restored database size does not match the backup")
    if not secrets.compare_digest(_file_hash(output), str(header.get("database_sha256"))):
        output.unlink(missing_ok=True)
        raise ValueError("restored database hash does not match the backup")
    return header


def _check_database(database: Path) -> None:
    uri = f"file:{database.resolve().as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        result = connection.execute("PRAGMA integrity_check").fetchone()
        if result is None or result[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    if not REQUIRED_TABLES.issubset(tables):
        raise ValueError("backup does not contain the VaultMind schema")


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _restrict_file(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _scheduled_backup(database: Path, directory: Path, key: bytes,
                      retain: int) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = directory / f"vaultmind-{stamp}-{secrets.token_hex(4)}.vmbak"
    header = create_backup(database, output, key)
    verify_backup(output, key)
    prune_backups(directory, retain)
    print(
        f"created and verified {output.name} "
        f"({str(header['database_sha256'])[:12]})", flush=True,
    )
    return output


def _schedule(database: Path, directory: Path, key: bytes,
              interval_hours: int, retain: int) -> int:
    if not 1 <= interval_hours <= 168:
        raise ValueError("backup interval must be between 1 and 168 hours")
    if not 2 <= retain <= 365:
        raise ValueError("backup retention must be between 2 and 365 files")
    directory.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()

    def request_stop(signum, frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    while not stop.is_set():
        _scheduled_backup(database, directory, key, retain)
        stop.wait(interval_hours * 3600)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VaultMind encrypted backups")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--database", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--input", type=Path, required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--input", type=Path, required=True)
    restore.add_argument("--database", type=Path, required=True)
    restore.add_argument("--force", action="store_true")
    restore_latest = commands.add_parser("restore-latest")
    restore_latest.add_argument("--directory", type=Path, required=True)
    restore_latest.add_argument("--database", type=Path, required=True)
    restore_latest.add_argument("--force", action="store_true")
    drill = commands.add_parser("drill")
    drill.add_argument("--directory", type=Path, required=True)
    schedule = commands.add_parser("schedule")
    schedule.add_argument("--database", type=Path, required=True)
    schedule.add_argument("--directory", type=Path, required=True)
    schedule.add_argument("--interval-hours", type=int, default=24)
    schedule.add_argument("--retain", type=int, default=14)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    key = load_backup_key()
    if args.command == "create":
        create_backup(args.database, args.output, key)
        print(f"created {args.output}")
    elif args.command == "verify":
        verify_backup(args.input, key)
        print(f"verified {args.input}")
    elif args.command == "restore":
        restore_backup(args.input, args.database, key, args.force)
        print(f"restored {args.database}")
    elif args.command == "restore-latest":
        backup = newest_backup(args.directory)
        restore_backup(backup, args.database, key, args.force)
        print(f"restored {backup.name} to {args.database}")
    elif args.command == "drill":
        backup = newest_backup(args.directory)
        verify_backup(backup, key)
        print(f"restore drill passed for {backup.name}")
    elif args.command == "schedule":
        return _schedule(
            args.database, args.directory, key,
            args.interval_hours, args.retain,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
