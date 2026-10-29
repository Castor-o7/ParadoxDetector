"""Small HTTP + caching helpers built on the standard library."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from . import config

USER_AGENT = "ParadoxDetector/0.1 (threat-intel research tool)"


def fetch(url: str, *, headers: dict[str, str] | None = None, body: dict | None = None,
          timeout: float | None = None) -> tuple[int, bytes]:
    """Return (status, body bytes). HTTP error statuses are returned, not raised,
    because several beacons use 404 to mean "never seen this IP"."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if data:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout or config.HTTP_TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def fetch_json(url: str, **kwargs) -> tuple[int, Any]:
    status, raw = fetch(url, **kwargs)
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, None


_mem: dict[str, tuple[float, Any]] = {}
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def cached(name: str, ttl: float, loader: Callable[[], Any]) -> Any:
    """Memoize a bulk feed in memory and on disk (.cache/<name>.json) for `ttl` seconds."""
    with _locks_guard:
        lock = _locks.setdefault(name, threading.Lock())
    with lock:
        hit = _mem.get(name)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        path = config.CACHE_DIR / f"{name}.json"
        if path.exists() and time.time() - path.stat().st_mtime < ttl:
            try:
                value = json.loads(path.read_text())
                _mem[name] = (path.stat().st_mtime, value)
                return value
            except (OSError, json.JSONDecodeError):
                pass
        value = loader()
        _mem[name] = (time.time(), value)
        try:
            config.CACHE_DIR.mkdir(exist_ok=True)
            path.write_text(json.dumps(value))
        except OSError:
            pass
        return value
