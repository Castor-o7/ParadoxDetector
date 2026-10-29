"""Web app: python3 server.py  ->  http://127.0.0.1:8787

Deployment settings (environment or .env):
  PARADOX_HOST / PARADOX_PORT   bind address (default 127.0.0.1:8787)
  PARADOX_PASSWORD              require HTTP Basic auth (any username). Required to bind a
                                non-loopback address unless PARADOX_ALLOW_OPEN=1.
  PARADOX_RATE_LIMIT            scans + summaries per client per minute (default 20, 0 = off)
  PARADOX_TRUST_PROXY=1         take the client address from X-Forwarded-For (behind a reverse proxy)
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import sys
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from paradox import config, engine, history, logscan
from paradox.engine import InvalidTarget

WEB = Path(__file__).resolve().parent / "web"
PASSWORD = config.key("PARADOX_PASSWORD")
RATE_LIMIT = int(os.environ.get("PARADOX_RATE_LIMIT", "20"))
TRUST_PROXY = os.environ.get("PARADOX_TRUST_PROXY") == "1"
MAX_LOG_BYTES = 5_000_000
MAX_LOG_LIMIT = 50
MAX_JOBS = 2                      # concurrent log scans; each fans out to every beacon per IP
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

_hits: dict[str, deque] = {}
_hits_lock = threading.Lock()


def allow(client: str) -> bool:
    """Sliding one-minute window per client."""
    if RATE_LIMIT <= 0:
        return True
    now = time.monotonic()
    with _hits_lock:
        q = _hits.setdefault(client, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def start_log_job(text: str, limit: int, min_hits: int) -> dict:
    with _jobs_lock:
        for jid in [j for j, v in _jobs.items() if v["state"] != "running" and time.time() - v["ended"] > 3600]:
            del _jobs[jid]                                   # forget finished jobs after an hour
        if sum(v["state"] == "running" for v in _jobs.values()) >= MAX_JOBS:
            raise RuntimeError("Too many log scans running; try again when one finishes.")
        jid = uuid.uuid4().hex
        job = _jobs[jid] = {"id": jid, "state": "running", "done": 0, "total": None, "result": None,
                            "error": None, "ended": 0.0}

    def progress(done, total, ip):
        job["done"], job["total"] = done, total

    def work():
        try:
            job["result"] = logscan.scan_lines(text.splitlines(), limit=limit, min_hits=min_hits,
                                               progress=progress)
            job["state"] = "done"
        except Exception as exc:
            job["error"], job["state"] = f"{type(exc).__name__}: {exc}", "error"
        job["ended"] = time.time()

    threading.Thread(target=work, daemon=True).start()
    return job


class Handler(BaseHTTPRequestHandler):
    server_version = "ParadoxDetector/0.1"

    def _send(self, status: int, body: bytes, ctype: str, headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload, headers: dict | None = None) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json", headers)

    def client(self) -> str:
        if TRUST_PROXY and self.headers.get("X-Forwarded-For"):
            return self.headers["X-Forwarded-For"].split(",")[0].strip()
        return self.client_address[0]

    def authorized(self) -> bool:
        if not PASSWORD:
            return True
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            _, _, given = base64.b64decode(auth[6:]).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(given.encode(), PASSWORD.encode())

    def gate(self, metered: bool) -> bool:
        """Auth and rate limit. Returns False after sending the refusal."""
        if not self.authorized():
            self._json(401, {"error": "authentication required"},
                       {"WWW-Authenticate": 'Basic realm="Paradox Detector", charset="UTF-8"'})
            return False
        if metered and not allow(self.client()):
            self._json(429, {"error": f"rate limit: {RATE_LIMIT} scans per minute"}, {"Retry-After": "60"})
            return False
        return True

    def do_GET(self) -> None:
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/healthz":                     # unauthenticated, for container health checks
            return self._json(200, {"ok": True})
        metered = url.path in ("/api/scan", "/api/narrate")
        if not self.gate(metered):
            return
        if url.path in ("/", "/index.html"):
            return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/beacons":
            return self._json(200, engine.beacon_status())
        if url.path == "/api/scan":
            try:
                report = engine.scan(q.get("ip", ""), use_cache=q.get("fresh") != "1")
            except InvalidTarget as err:
                return self._json(400, {"error": str(err)})
            return self._json(200, report)
        if url.path == "/api/history":
            try:
                ip = engine.normalize_ip(q.get("ip", ""))
            except InvalidTarget as err:
                return self._json(400, {"error": str(err)})
            return self._json(200, {"ip": ip, "scans": history.scans(ip), "lag": history.lag(ip)})
        if url.path == "/api/tracked":
            return self._json(200, history.tracked())
        if url.path == "/api/narrate":
            return self._narrate(q.get("ip", ""))
        if url.path == "/api/logscan":
            job = _jobs.get(q.get("job", ""))
            if not job:
                return self._json(404, {"error": "unknown job"})
            return self._json(200, {k: job[k] for k in ("id", "state", "done", "total", "result", "error")})
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        url = urlparse(self.path)
        if url.path != "/api/logscan":
            return self._json(404, {"error": "not found"})
        if not self.gate(metered=True):
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._json(415, {"error": "send JSON: {\"text\": ..., \"limit\": n}"})  # also blocks CSRF form posts
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_LOG_BYTES:
            return self._json(413, {"error": f"log must be 1 byte to {MAX_LOG_BYTES // 1_000_000} MB"})
        try:
            body = json.loads(self.rfile.read(length))
            text = str(body["text"])
            limit = max(1, min(int(body.get("limit") or logscan.DEFAULT_LIMIT), MAX_LOG_LIMIT))
            min_hits = max(1, int(body.get("min_hits") or 1))
        except (ValueError, KeyError, TypeError):
            return self._json(400, {"error": "expected JSON {\"text\": string, \"limit\": int, \"min_hits\": int}"})
        try:
            job = start_log_job(text, limit, min_hits)
        except RuntimeError as err:
            return self._json(429, {"error": str(err)}, {"Retry-After": "30"})
        self._json(202, {"id": job["id"], "state": job["state"]})

    def _narrate(self, raw_ip: str) -> None:
        from paradox.narrative import NarrativeUnavailable, summarize
        try:
            ip = engine.normalize_ip(raw_ip)
        except InvalidTarget as err:
            return self._json(400, {"error": str(err)})
        report = engine.cached_report(ip) or engine.scan(ip)
        try:
            return self._json(200, {"ip": ip, "narrative": summarize(report)})
        except NarrativeUnavailable as err:
            return self._json(503, {"error": str(err)})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"  {self.client()} " + (fmt % args) + "\n")


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> None:
    host = os.environ.get("PARADOX_HOST", "127.0.0.1")
    port = int(os.environ.get("PARADOX_PORT", "8787"))
    if not is_loopback(host) and not PASSWORD and os.environ.get("PARADOX_ALLOW_OPEN") != "1":
        sys.exit(f"Refusing to listen on {host} without PARADOX_PASSWORD: anyone who can reach it could "
                 "spend your API quotas. Set PARADOX_PASSWORD, or PARADOX_ALLOW_OPEN=1 if a proxy "
                 "in front already handles auth.")
    httpd = ThreadingHTTPServer((host, port), Handler)
    auth = "password required" if PASSWORD else "no password"
    print(f"Paradox Detector running at http://{host}:{port}  ({auth}; Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
