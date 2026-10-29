"""Batch mode: pull every IP out of a log and rank them by paradox.

    python3 -m paradox --log /var/log/nginx/access.log
    journalctl -u sshd | python3 -m paradox --log - --limit 40 --csv

Any text format works (web/ssh/firewall logs, JSON lines, CSV). Private and
reserved addresses are counted but not scanned. The most active public IPs are
scanned first, and results are ranked so the IPs worth a closer look - borrowed
reputations, fast/slow disagreement, then plain threat - come out on top.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable

from . import engine

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Loose candidate; ipaddress does the real validation, which rejects
# timestamps (12:34:56) and MAC addresses.
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")

DEFAULT_LIMIT = 25
DEFAULT_WORKERS = 2     # each scan already fans out to every beacon; stay polite


def ips_in(line: str) -> list[tuple[str, bool]]:
    """Distinct addresses in one line, as (ip, is_public)."""
    out: dict[str, bool] = {}
    for m in (*IPV4.finditer(line), *IPV6.finditer(line)):
        try:
            addr = ipaddress.ip_address(m.group())
        except ValueError:
            continue
        out.setdefault(str(addr), addr.is_global)
    return list(out.items())


def extract(lines: Iterable[str]) -> dict:
    """Count IP occurrences. Returns {"lines", "public": {ip: info}, "private": n}."""
    public: dict[str, dict] = {}
    private: set[str] = set()
    n = 0
    for n, line in enumerate(lines, 1):
        for ip, is_public in ips_in(line):
            if not is_public:
                private.add(ip)
                continue
            info = public.setdefault(ip, {"hits": 0, "first_line": n, "sample": line.strip()[:300]})
            info["hits"] += 1
            info["last_line"] = n
    return {"lines": n, "public": public, "private": len(private)}


def flag_of(score: dict) -> str:
    """Why an IP deserves attention, most specific reason first."""
    if score["veneer"].get("active"):
        return "veneer"
    if score["paradox"] >= 35:
        return "paradox"
    if score["threat"] >= 0.4:
        return "threat"
    if score["paradox"] >= 15 or score["threat"] >= 0.15:
        return "watch"
    return ""


FLAG_RANK = {"veneer": 0, "paradox": 1, "threat": 2, "watch": 3, "": 4}


def row(ip: str, info: dict, report: dict | None, error: str | None = None) -> dict:
    out = {"ip": ip, **info}   # hits, sample, and where it was seen (lines or timestamps)
    if report is None:
        return {**out, "error": error, "flag": "", "paradox": None, "threat": None}
    sc = report["score"]
    return {**out,
            "flag": flag_of(sc),
            "paradox": sc["paradox"], "paradox_label": sc["paradox_label"], "direction": sc["direction"],
            "threat": sc["threat"], "threat_label": sc["threat_label"],
            "veneer": sc["veneer"].get("labels") if sc["veneer"].get("active") else [],
            "network_risk": sc["network"].get("risk"),
            "explanation": sc["explanation"]}


def rank_key(r: dict):
    return (r.get("error") is not None, FLAG_RANK[r["flag"]], -(r["paradox"] or 0), -(r["threat"] or 0), -r["hits"])


def scan_lines(lines: Iterable[str], limit: int = DEFAULT_LIMIT, min_hits: int = 1,
               workers: int = DEFAULT_WORKERS, fresh: bool = False,
               progress: Callable[[int, int, str], None] | None = None,
               scanner: Callable[..., dict] | None = None) -> dict:
    scanner = scanner or engine.scan
    found = extract(lines)
    candidates = sorted(((ip, i) for ip, i in found["public"].items() if i["hits"] >= min_hits),
                        key=lambda x: (-x[1]["hits"], x[1]["first_line"]))
    chosen = candidates[:limit] if limit > 0 else candidates
    started = time.monotonic()
    done = 0
    lock = threading.Lock()

    def one(item):
        nonlocal done
        ip, info = item
        try:
            r = row(ip, info, scanner(ip, use_cache=not fresh))
        except Exception as exc:  # one bad IP shouldn't sink the batch
            r = row(ip, info, None, f"{type(exc).__name__}: {exc}")
        with lock:
            done += 1
            if progress:
                progress(done, len(chosen), ip)
        return r

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = sorted(pool.map(one, chosen), key=rank_key)

    flags = {f: sum(r["flag"] == f for r in results) for f in ("veneer", "paradox", "threat", "watch")}
    return {
        "summary": {"lines": found["lines"], "public_ips": len(found["public"]),
                    "private_ips": found["private"], "scanned": len(chosen),
                    "not_scanned": len(candidates) - len(chosen),
                    "below_min_hits": len(found["public"]) - len(candidates),
                    "errors": sum(r.get("error") is not None for r in results),
                    "flags": flags, "elapsed_s": round(time.monotonic() - started, 1)},
        "results": results,
    }


def render(result: dict) -> str:
    s = result["summary"]
    f = s["flags"]
    lines = [
        f"\n  {s['lines']} lines, {s['public_ips']} public IPs ({s['private_ips']} private skipped), "
        f"{s['scanned']} scanned in {s['elapsed_s']}s"
        + (f", {s['not_scanned']} less active IPs not scanned (raise --limit)" if s["not_scanned"] else ""),
        f"  veneer {f['veneer']}   paradox {f['paradox']}   threat {f['threat']}   watch {f['watch']}"
        + (f"   errors {s['errors']}" if s["errors"] else ""),
        "",
        f"  {'flag':<8}{'ip':<40}{'hits':>6}{'paradox':>9}{'threat':>8}  verdict",
    ]
    for r in result["results"]:
        if r.get("error"):
            lines.append(f"  {'error':<8}{r['ip']:<40}{r['hits']:>6}{'':>9}{'':>8}  {r['error']}")
            continue
        verdict = f"{r['paradox_label']} [{r['direction']}], {r['threat_label']}"
        if r["veneer"]:
            verdict += "  - borrowed reputation: " + "; ".join(r["veneer"])
        lines.append(f"  {r['flag'].upper() or '-':<8}{r['ip']:<40}{r['hits']:>6}{r['paradox']:>9.1f}"
                     f"{r['threat'] * 100:>8.0f}  {verdict}")
    return "\n".join(lines) + "\n"


CSV_FIELDS = ["flag", "ip", "hits", "paradox", "paradox_label", "direction", "threat", "threat_label",
              "network_risk", "veneer", "first_line", "last_line", "error", "explanation"]


def to_csv(result: dict, out) -> None:
    import csv
    w = csv.DictWriter(out, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in result["results"]:
        w.writerow({**r, "veneer": "; ".join(r.get("veneer") or [])})
