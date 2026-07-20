from __future__ import annotations

import os
import signal
import threading
import time
from pathlib import Path

from .storage import Database


def scan_interval() -> int:
    try:
        seconds = int(os.getenv("VAULTMIND_SCAN_SECONDS", "60"))
    except ValueError as exc:
        raise RuntimeError("VAULTMIND_SCAN_SECONDS must be an integer") from exc
    if not 15 <= seconds <= 3600:
        raise RuntimeError("VAULTMIND_SCAN_SECONDS must be between 15 and 3600")
    return seconds


def scan_once(database: Database) -> int:
    return len(database.create_due_jobs())


def heartbeat_is_fresh(path: Path, interval_seconds: int,
                       now: float | None = None) -> bool:
    try:
        age = (now if now is not None else time.time()) - path.stat().st_mtime
    except OSError:
        return False
    return age <= interval_seconds * 2 + 30


def main() -> int:
    database_path = os.getenv(
        "VAULTMIND_DATABASE", "/app/data/vaultmind-next.db"
    )
    database = Database(database_path)
    stop = threading.Event()

    def request_stop(signum, frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    interval = scan_interval()
    heartbeat = Path(os.getenv(
        "VAULTMIND_SCHEDULER_HEARTBEAT", "/tmp/vaultmind-scheduler.heartbeat"
    ))
    try:
        while not stop.is_set():
            created = scan_once(database)
            heartbeat.touch()
            if created:
                print(f"created {created} due rotation job(s)", flush=True)
            stop.wait(interval)
    finally:
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
