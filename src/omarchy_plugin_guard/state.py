"""Run lock, append-only audit log, and first-seen tracking for incoming SHAs.

Everything here lives under the state directory so a timer run and a manual
run share one view of the world.
"""
from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from omarchy_plugin_guard.paths import state_dir


class LockHeld(RuntimeError):
    pass


def now_utc() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


@contextmanager
def run_lock() -> Iterator[None]:
    """Hold an exclusive, non-blocking lock for the whole run.

    Prevents the daily timer and an interactive `update` from fetching or
    merging the same plugin checkout at the same time.
    """
    state_dir().mkdir(parents=True, exist_ok=True)
    path = state_dir() / "lock"
    with open(path, "a+", encoding="utf-8") as handle:
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                holder = ""
                try:
                    handle.seek(0)
                    holder = handle.read().strip()
                except OSError:
                    pass
                detail = f" (held by {holder})" if holder else ""
                raise LockHeld(f"another omarchy-plugin-guard run is in progress{detail}") from exc
            handle.seek(0)
            handle.truncate()
            handle.write(f"pid {os.getpid()} since {_iso(now_utc())}\n")
            handle.flush()
            yield
        finally:
            try:
                handle.seek(0)
                handle.truncate()
            except OSError:
                pass


def audit_path() -> Path:
    return state_dir() / "audit.jsonl"


def append_audit(event: dict[str, Any]) -> None:
    """Append one JSON line. Never rewritten, so history survives."""
    state_dir().mkdir(parents=True, exist_ok=True)
    record = {"at": _iso(now_utc()), **event}
    with open(audit_path(), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def seen_dir() -> Path:
    return state_dir() / "seen"


def _seen_path(plugin_id: str) -> Path:
    return seen_dir() / f"{plugin_id}.json"


def note_first_seen(plugin_id: str, sha: str) -> datetime:
    """Record when *this machine* first fetched `sha` and return that moment.

    Used by the soak delay. Upstream commit timestamps are attacker-controlled;
    the local first-seen time is not.
    """
    seen_dir().mkdir(parents=True, exist_ok=True)
    path = _seen_path(plugin_id)
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("sha") == sha and data.get("first_seen_at"):
                return datetime.fromisoformat(data["first_seen_at"])
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    # Second precision on disk, so return the same value we will read back.
    moment = now_utc().replace(microsecond=0)
    path.write_text(
        json.dumps({"sha": sha, "first_seen_at": _iso(moment)}, indent=2) + "\n",
        encoding="utf-8",
    )
    return moment


def clear_first_seen(plugin_id: str) -> None:
    try:
        _seen_path(plugin_id).unlink()
    except FileNotFoundError:
        pass
