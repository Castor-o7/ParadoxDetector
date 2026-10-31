"""Headless sensor: follow logs live, scan new IPs, alert on findings.

    paradox watch --log /var/log/auth.log --log /var/log/nginx/access.log
    paradox watch --log - --json                    # read lines from a pipe
    paradox watch --rescan-every 6                  # no logs: just keep tracked IPs fresh

Each public IP is scanned once it reaches --min-hits, then again only after
--rescan-after hours, so a busy log doesn't hammer the beacons. --max-new-per-hour
caps how many new IPs get scanned, so a log full of forged addresses can't spend
the day's quota. An alert is
emitted when an IP's flag (veneer, paradox, threat, watch) enters the alert set
or changes, as a line on stdout (JSON with --json) and, optionally, a POST to
--webhook. The payload's "text" field makes Slack/Mattermost incoming webhooks
work as-is.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import sys
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Iterator, TextIO

from . import engine, history, logscan

DEFAULT_ALERTS = ("veneer", "paradox", "threat")
DEFAULT_MAX_NEW = 15    # new IPs scanned an hour: 360 a day, inside VirusTotal's 500 with room for rescans
QUEUE_LIMIT = 1000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def follow(path: str, stop: threading.Event, from_start: bool = False, poll: float = 1.0) -> Iterator[str]:
    """Yield lines appended to a file, like `tail -F`: survives rotation
    (file replaced) and truncation, and waits for a file that doesn't exist yet.

    The file is opened now, not on first iteration, so lines written between
    starting the watcher and its first read are not skipped."""
    f, ino = None, None
    try:
        f = open(path, "rb")
        ino = os.fstat(f.fileno()).st_ino
        if not from_start:
            f.seek(0, os.SEEK_END)
    except FileNotFoundError:
        pass
    return _follow(path, stop, f, ino, poll)


def _follow(path: str, stop: threading.Event, f, ino, poll: float) -> Iterator[str]:
    partial = b""
    while not stop.is_set():
        if f is None:
            try:
                f = open(path, "rb")
            except FileNotFoundError:
                stop.wait(poll)
                continue
            ino = os.fstat(f.fileno()).st_ino   # a file created or rotated in later is read from its start
        chunk = f.readline()
        if chunk:
            partial += chunk
            if partial.endswith(b"\n"):   # a line still being written waits for its end
                yield partial.decode("utf-8", errors="replace")
                partial = b""
            continue
        try:
            st = os.stat(path)
            rotated, truncated = st.st_ino != ino, st.st_size < f.tell()
        except FileNotFoundError:
            rotated, truncated = True, False
        if rotated or truncated:
            if partial:
                yield partial.decode("utf-8", errors="replace")
                partial = b""
            if rotated:
                f.close()
                f = None
            else:
                f.seek(0)
        else:
            stop.wait(poll)
    if f:
        f.close()


def stream(src: TextIO, stop: threading.Event) -> Iterator[str]:
    for line in src:
        if stop.is_set():
            break
        yield line


class Watcher:
    def __init__(self, *, min_hits: int = 1, rescan_after_h: float = 24, alert_on=DEFAULT_ALERTS,
                 workers: int = logscan.DEFAULT_WORKERS, webhook: str | None = None, as_json: bool = False,
                 max_new_per_hour: int = DEFAULT_MAX_NEW, out: TextIO = sys.stdout, scanner: Callable[..., dict] | None = None):
        self.min_hits, self.rescan_after = min_hits, rescan_after_h * 3600
        self.alert_on, self.webhook, self.as_json, self.out = set(alert_on), webhook, as_json, out
        self.scanner = scanner or engine.scan
        self.stop = threading.Event()
        self.seen: dict[str, dict] = {}
        self.last_scan: dict[str, float] = {}
        self.last_flag: dict[str, str] = {}
        self.pending: set[str] = set()
        self.q: queue.Queue[str] = queue.Queue(QUEUE_LIMIT)
        self.lock = threading.Lock()
        self.max_new = max_new_per_hour
        self.new_scans: deque[float] = deque()
        self.warned_capped = False
        self.stats = {"lines": 0, "scans": 0, "alerts": 0, "dropped": 0, "errors": 0, "capped": 0}
        self.workers = [threading.Thread(target=self._work, daemon=True) for _ in range(max(1, workers))]

    # -- input -------------------------------------------------------------
    def feed(self, line: str, source: str) -> None:
        with self.lock:
            self.stats["lines"] += 1
        for ip, public in logscan.ips_in(line):
            if not public:
                continue
            with self.lock:
                info = self.seen.setdefault(ip, {"hits": 0, "first_seen": now_iso(), "source": source})
                info["hits"] += 1
                info["last_seen"] = now_iso()
                info["sample"] = line.strip()[:300]
                due = (info["hits"] >= self.min_hits and ip not in self.pending
                       and time.time() - self.last_scan.get(ip, 0) >= self.rescan_after)
                capped = due and ip not in self.last_scan and not self._new_scan_allowed()
                if capped:
                    due = False
                    self.stats["capped"] += 1
                warn = capped and not self.warned_capped
                if warn:
                    self.warned_capped = True
                if due:
                    self.pending.add(ip)
            if warn:
                print(f"watch: {self.max_new} new IPs scanned this hour, the limit; others wait until they're seen "
                      "again after that. Forged addresses in a log can cause this.", file=sys.stderr)
            if due:
                self._enqueue(ip)

    def _new_scan_allowed(self) -> bool:
        """A log can name endless addresses, and each scan spends quota. Call with the lock held."""
        if self.max_new <= 0:
            return True
        now = time.time()
        while self.new_scans and now - self.new_scans[0] >= 3600:
            self.new_scans.popleft()
            self.warned_capped = False
        if len(self.new_scans) >= self.max_new:
            return False
        self.new_scans.append(now)
        return True

    def _enqueue(self, ip: str) -> None:
        try:
            self.q.put_nowait(ip)
        except queue.Full:
            with self.lock:
                self.pending.discard(ip)
                self.stats["dropped"] += 1
            print(f"watch: scan queue full, skipped {ip} (it will be retried when seen again)", file=sys.stderr)

    # -- scanning ----------------------------------------------------------
    def _work(self) -> None:
        while not self.stop.is_set():
            try:
                ip = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.check(ip, fresh=ip in self.last_scan)
            finally:
                with self.lock:
                    self.pending.discard(ip)
                self.q.task_done()

    def check(self, ip: str, fresh: bool = False) -> dict | None:
        with self.lock:
            info = dict(self.seen.get(ip) or {"hits": 0, "source": "rescan"})
        try:
            report = self.scanner(ip, use_cache=not fresh)
        except Exception as exc:
            with self.lock:
                self.stats["errors"] += 1
            print(f"watch: scan of {ip} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return None
        row = logscan.row(ip, info, report)
        with self.lock:
            self.stats["scans"] += 1
            self.last_scan[ip] = time.time()
            previous = self.last_flag.get(ip)
            self.last_flag[ip] = row["flag"]
        if row["flag"] in self.alert_on and row["flag"] != previous:
            self.alert(row, previous)
        return row

    def rescan_tracked(self, every_h: float) -> None:
        """Keep history fresh (what cron did before): rescan every tracked IP."""
        while not self.stop.wait(every_h * 3600):
            for t in history.tracked():
                if self.stop.is_set():
                    return
                self.check(t["ip"], fresh=True)
                self.stop.wait(2.0)              # stay polite to keyless APIs

    # -- output ------------------------------------------------------------
    def alert(self, row: dict, previous: str | None) -> None:
        with self.lock:
            self.stats["alerts"] += 1
        verdict = f"{row['paradox_label']} [{row['direction']}], {row['threat_label']}"
        if row["veneer"]:
            verdict += " - borrowed reputation: " + "; ".join(row["veneer"])
        text = (f"Paradox Detector: {row['flag'].upper()} {row['ip']} - paradox {row['paradox']:.0f}, "
                f"threat {row['threat'] * 100:.0f}. {verdict}")
        payload = {"text": text, "time": now_iso(), "previous_flag": previous, "alert": row}
        line = json.dumps(payload) if self.as_json else f"{payload['time']}  {text}  (seen {row.get('hits', 0)}x)"
        with self.lock:
            print(line, file=self.out, flush=True)
        if self.webhook:
            threading.Thread(target=self._post, args=(payload,), daemon=True).start()

    def _post(self, payload: dict) -> None:
        req = urllib.request.Request(self.webhook, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10).close()
        except Exception as exc:
            print(f"watch: webhook failed: {type(exc).__name__}: {exc}", file=sys.stderr)

    # -- lifecycle ---------------------------------------------------------
    def run(self, logs: list[str], from_start: bool = False, rescan_every_h: float = 0) -> int:
        for sig in (signal.SIGINT, signal.SIGTERM):          # docker stop sends SIGTERM
            signal.signal(sig, lambda *_: self.stop.set())
        for w in self.workers:
            w.start()
        threads = []
        for path in logs:
            lines = stream(sys.stdin, self.stop) if path == "-" else follow(path, self.stop, from_start)
            threads.append(threading.Thread(target=self._pump, args=(lines, path), daemon=True))
        if rescan_every_h > 0:
            threads.append(threading.Thread(target=self.rescan_tracked, args=(rescan_every_h,), daemon=True))
        if not threads:
            print("watch: nothing to do; give --log FILE and/or --rescan-every HOURS", file=sys.stderr)
            return 2
        for t in threads:
            t.start()
        what = ", ".join(logs) or "no logs"
        print(f"watch: following {what}; alerting on {', '.join(sorted(self.alert_on))}"
              + (f"; rescanning tracked IPs every {rescan_every_h:g}h" if rescan_every_h > 0 else ""),
              file=sys.stderr, flush=True)
        while not self.stop.is_set():
            if logs == ["-"] and not threads[0].is_alive() and self.q.unfinished_tasks == 0:
                break                                     # piped input ended and every scan finished
            self.stop.wait(0.5)
        self.stop.set()
        s = self.stats
        print(f"watch: stopped. {s['lines']} lines, {len(self.seen)} public IPs, {s['scans']} scans, "
              f"{s['alerts']} alerts" + (f", {s['errors']} errors" if s["errors"] else "")
              + (f", {s['dropped']} dropped" if s["dropped"] else "")
              + (f", {s['capped']} sightings over the new-IP limit" if s["capped"] else ""), file=sys.stderr)
        return 1 if s["alerts"] else 0

    def _pump(self, lines: Iterator[str], source: str) -> None:
        for line in lines:
            self.feed(line, source)
