"""Run every beacon for an IP concurrently and assemble the report."""

from __future__ import annotations

import ipaddress
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import config, history, scoring
from .sources import BEACONS, run_beacon


class InvalidTarget(ValueError):
    pass


def normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise InvalidTarget(f"'{raw}' is not a valid IPv4 or IPv6 address") from None
    if not addr.is_global:
        raise InvalidTarget(f"{addr} is a private/reserved address; threat feeds only track public IPs")
    return str(addr)


_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()
_health: dict[str, dict] = {}     # each beacon's last answer, for as long as this process runs


def scan(raw_ip: str, use_cache: bool = True, record: bool = True) -> dict:
    ip = normalize_ip(raw_ip)
    if use_cache:
        with _lock:
            hit = _cache.get(ip)
        if hit and time.time() - hit[0] < config.SCAN_CACHE_SECONDS:
            return hit[1]

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(BEACONS)) as pool:
        signals = list(pool.map(lambda b: run_beacon(b, ip), BEACONS))

    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        _health.update({s.source: {"state": s.failure or "ok", "detail": s.summary if s.failure else "",
                                   "checked_at": checked_at} for s in signals})
    report = {
        "ip": ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "score": scoring.compute(signals),
        "signals": [s.to_dict() for s in signals],
    }
    with _lock:
        _cache[ip] = (time.time(), report)
    try:
        if record:
            history.record(report)
    except Exception as exc:  # history is a convenience; never fail a scan over it
        print(f"warning: could not record scan history: {exc}", file=sys.stderr)
    return report


def cached_report(ip: str) -> dict | None:
    with _lock:
        hit = _cache.get(ip)
    return hit[1] if hit else None


def beacon_status() -> list[dict]:
    """Configuration, plus how each beacon last answered: ok, no_key, rate_limited,
    paced, bad_key, error, or untested if this process hasn't scanned with it yet."""
    out = []
    for b in BEACONS:
        key_set = bool(b.key_env and config.key(b.key_env))
        with _lock:
            health = _health.get(b.id, {})
        state = "no_key" if b.key_required and not key_set else health.get("state", "untested")
        out.append({
            "id": b.id, "name": b.name, "tier": b.tier, "cadence": b.cadence,
            "key_env": b.key_env, "key_required": b.key_required, "key_set": key_set,
            "state": state, "detail": health.get("detail", "") if state != "no_key" else f"Set {b.key_env} to enable",
            "checked_at": health.get("checked_at"),
        })
    return out
