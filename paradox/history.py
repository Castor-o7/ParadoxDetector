"""Scan history in a local SQLite file, plus beacon lag measured from it.

Every fresh scan is recorded. Over repeated scans of the same IP this shows
whether a paradox closes (slow beacons catch up), how long that took, and which
beacon flagged the IP first - real lag data instead of assumed tiers.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from . import config
from .sources import age_days, parse_dt

DB_PATH = config.DATA_DIR / "history.sqlite3"
FLAG_THREAT = 0.4
FLAG_CONFIDENCE = 0.5
OPEN_PARADOX = 35     # the score where the label becomes "Paradox"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    paradox REAL, threat REAL, fast REAL, slow REAL,
    direction TEXT, veneer INTEGER,
    report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_ip_time ON scans (ip, scanned_at);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def record(report: dict) -> None:
    sc = report["score"]
    with closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO scans (ip, scanned_at, paradox, threat, fast, slow, direction, veneer, report)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (report["ip"], report["scanned_at"], sc["paradox"], sc["threat"],
             sc["fast"]["score"], sc["slow"]["score"], sc["direction"],
             int(bool((sc.get("veneer") or {}).get("active"))), json.dumps(report)))


def scans(ip: str, limit: int = 500) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT scanned_at, paradox, threat, fast, slow, direction, veneer FROM scans"
            " WHERE ip = ? ORDER BY scanned_at DESC LIMIT ?", (ip, limit)).fetchall()
    return [dict(r) for r in reversed(rows)]


def tracked() -> list[dict]:
    """Every IP with history, newest scan first, with its latest scores and when
    its current run of scans at or above OPEN_PARADOX began (None if not open)."""
    with closing(_connect()) as conn:
        rows = conn.execute("SELECT ip, scanned_at, paradox, threat, direction, veneer FROM scans"
                            " ORDER BY ip, scanned_at").fetchall()
    by_ip: dict[str, dict] = {}
    for r in rows:
        t = by_ip.setdefault(r["ip"], {"ip": r["ip"], "scans": 0, "first_scan": r["scanned_at"], "open_since": None})
        is_open = (r["paradox"] or 0) >= OPEN_PARADOX
        t.update(scans=t["scans"] + 1, last_scan=r["scanned_at"], paradox=r["paradox"], threat=r["threat"],
                 direction=r["direction"], veneer=bool(r["veneer"]),
                 open_since=(t["open_since"] or r["scanned_at"]) if is_open else None)
    return sorted(by_ip.values(), key=lambda t: t["last_scan"], reverse=True)


def lag(ip: str, now: datetime | None = None) -> dict:
    """When each beacon first flagged the IP (threat and confidence above the
    flag thresholds), as seen across recorded scans, and the fast-to-slow lag."""
    now = now or datetime.now(timezone.utc)
    with closing(_connect()) as conn:
        rows = conn.execute("SELECT scanned_at, report FROM scans WHERE ip = ? ORDER BY scanned_at",
                            (ip,)).fetchall()
    first: dict[str, dict] = {}
    for row in rows:
        for s in json.loads(row["report"])["signals"]:
            if (s["source"] not in first and s["tier"] != "context" and s["status"] == "ok"
                    and (s["threat"] or 0) >= FLAG_THREAT and s["confidence"] >= FLAG_CONFIDENCE):
                first[s["source"]] = {"name": s["name"], "tier": s["tier"], "first_flagged": row["scanned_at"]}

    def earliest(tier: str) -> str | None:
        return min((f["first_flagged"] for f in first.values() if f["tier"] == tier), default=None)

    fast, slow = earliest("fast"), earliest("slow")
    out = {"scans": len(rows), "first_scan": rows[0]["scanned_at"] if rows else None,
           "first_fast_flag": fast, "first_slow_flag": slow,
           "beacons": sorted(first.values(), key=lambda f: f["first_flagged"]),
           "lag_days": None, "open_days": None}
    if fast and slow:
        out["lag_days"] = round((parse_dt(slow) - parse_dt(fast)).total_seconds() / 86400, 1)
    elif fast:
        out["open_days"] = round(age_days(parse_dt(fast), now), 1)
    return out
