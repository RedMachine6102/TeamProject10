from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import JobStatus, RotationInterval

ALLOWED_TRANSITIONS = {
    JobStatus.PROPOSED: {JobStatus.APPROVED, JobStatus.CANCELED},
    JobStatus.APPROVED: {JobStatus.RUNNING, JobStatus.CANCELED},
    JobStatus.RUNNING: {JobStatus.SUCCEEDED, JobStatus.FAILED},
    JobStatus.FAILED: {JobStatus.APPROVED, JobStatus.CANCELED},
    JobStatus.SUCCEEDED: set(),
    JobStatus.CANCELED: set(),
}


def next_rotation(from_time: datetime, interval: RotationInterval | int) -> datetime:
    if from_time.tzinfo is None:
        raise ValueError("rotation times must include a timezone")
    days = RotationInterval(interval)
    return from_time.astimezone(timezone.utc) + timedelta(days=int(days))


def transition_allowed(current: JobStatus, target: JobStatus) -> bool:
    return target in ALLOWED_TRANSITIONS[current]


def require_transition(current: JobStatus, target: JobStatus) -> None:
    if not transition_allowed(current, target):
        raise ValueError(f"invalid job transition: {current.value} -> {target.value}")
