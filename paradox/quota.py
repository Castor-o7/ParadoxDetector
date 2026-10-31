"""Keep VirusTotal lookups inside the free tier: 4 a minute, 500 a day, 15.5K a month.

Lookups are spaced evenly, so a batch waits its turn and every IP gets the same
beacons. A lookup that would wait longer than MAX_WAIT is refused instead, and its
report says so. The ledger lives on disk so the watcher, the web app and the MCP
server share one budget.
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager

from . import config

try:
    import fcntl
except ImportError:     # Windows: threads in this process still queue, other processes don't
    fcntl = None

SPACING = 15.0          # seconds between lookups: 4 a minute
PER_DAY = 500
PER_MONTH = 15_500
DEFAULT_MAX_WAIT = 60.0

_lock = threading.Lock()
_memory: dict = {}      # used when the cache folder can't be written


class OutOfQuota(Exception):
    """No lookup now. The message says why and when one is next available."""


def max_wait() -> float:
    return float(os.environ.get("PARADOX_VT_MAX_WAIT", DEFAULT_MAX_WAIT))


@contextmanager
def _ledger():
    """Yield the ledger under a lock shared across processes, saving it afterwards."""
    path = config.CACHE_DIR / "virustotal_quota.json"
    with _lock:
        handle = None
        try:
            config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            handle = open(path.with_suffix(".lock"), "w")
            if fcntl:
                fcntl.flock(handle, fcntl.LOCK_EX)
            state = json.loads(path.read_text()) if path.exists() else {}
        except (OSError, json.JSONDecodeError):
            state = dict(_memory)
        try:
            yield state
            _memory.clear()
            _memory.update(state)
            try:
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(state))
                tmp.replace(path)
            except OSError:
                pass
        finally:
            if handle:
                handle.close()


def reserve() -> None:
    """Take the next lookup slot and wait for it, or raise OutOfQuota. Failed lookups count too."""
    limit = max_wait()
    with _ledger() as state:
        now = time.time()
        day, month = time.strftime("%Y-%m-%d", time.gmtime(now)), time.strftime("%Y-%m", time.gmtime(now))
        day_used = state.get("day_used", 0) if state.get("day") == day else 0
        month_used = state.get("month_used", 0) if state.get("month") == month else 0
        if day_used >= PER_DAY:
            raise OutOfQuota(f"VirusTotal not looked up: the free tier's {PER_DAY} lookups for {day} (UTC) are used")
        if month_used >= PER_MONTH:
            raise OutOfQuota(f"VirusTotal not looked up: the free tier's {PER_MONTH} lookups for {month} (UTC) are used")
        slot = max(now, state.get("next_slot", 0.0))
        wait = slot - now
        if wait > limit:
            raise OutOfQuota(f"VirusTotal not looked up: pacing to 4 a minute, the next slot is {wait:.0f}s away "
                             f"and the wait limit is {limit:.0f}s")
        state.update(next_slot=slot + SPACING, day=day, day_used=day_used + 1,
                     month=month, month_used=month_used + 1)
    if wait > 0:
        time.sleep(wait)
