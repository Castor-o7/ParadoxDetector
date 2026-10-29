"""Command line: python3 -m paradox 45.155.205.233 [--json] [--narrate]
                  python3 -m paradox --log access.log [--limit 25] [--csv]"""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import history
from .engine import InvalidTarget, normalize_ip, scan


def bar(value: float | None, width: int = 20) -> str:
    if value is None:
        return "·" * width
    filled = round(value * width)
    return "█" * filled + "░" * (width - filled)


def render(report: dict) -> str:
    sc = report["score"]
    lines = [
        f"\n  Paradox report for {report['ip']}   ({report['elapsed_ms']} ms)",
        f"  PARADOX  {sc['paradox']:5.1f}/100  {sc['paradox_label']}  [{sc['direction']}]",
        f"  THREAT   {sc['threat'] * 100:5.1f}/100  {sc['threat_label']}",
        f"  fast tier {bar(sc['fast']['score'])}  slow tier {bar(sc['slow']['score'])}  "
        f"coverage {sc['coverage']:.2f}",
        f"  {sc['explanation']}\n",
    ]
    v = sc.get("veneer") or {}
    if v.get("active"):
        lines.insert(-1, "  !! REPUTATION VENEER: " + "; ".join(v["labels"]) + " contradicted by:")
        lines[-1:-1] = [f"       - {c}" for c in v["contradicted_by"]]
    elif v.get("labels"):
        lines.insert(-1, "  benign label (uncontradicted): " + "; ".join(v["labels"]))
        explained = (sc.get("scanner") or {}).get("explained")
        if explained:
            lines.insert(-1, "  scanning reports explained by the label: " + ", ".join(explained))
    nw = sc.get("network") or {}
    if nw.get("prefix"):
        lines.insert(-1, f"  NETWORK  {nw['risk'] * 100:5.1f}/100  {nw.get('listed_neighbors', 0)} listed neighbors in "
                         f"{nw['prefix']}, {nw.get('holder') or 'unknown ASN'}"
                         + ("  [ASN-DROP]" if nw.get("asn_drop") else "  [hosting]" if nw.get("hosting") else ""))
    for tier in ("fast", "slow", "network", "context"):
        lines.append(f"  -- {tier.upper()} --")
        for s in (x for x in report["signals"] if x["tier"] == tier):
            score = "" if tier == "context" else (
                f"{bar(s['threat'], 10)} {s['threat']:.2f} c{s['confidence']:.1f}" if s["threat"] is not None
                else f"{'[' + s['status'] + ']':<22}")
            seen = f"  seen {s['last_seen']}" if s.get("last_seen") else ""
            lines.append(f"  {s['name']:<34} {score:<22} {s['summary']}{seen}")
            for ev in s["evidence"][:3]:
                lines.append(f"      · {ev}")
        lines.append("")
    return "\n".join(lines)


def render_history(ip: str) -> str:
    rows, lag = history.scans(ip), history.lag(ip)
    if not rows:
        return f"  No recorded scans for {ip}."
    lines = [f"\n  History for {ip}: {len(rows)} scans since {rows[0]['scanned_at']}",
             f"  {'scanned at':<26}{'paradox':>8}{'fast':>7}{'slow':>7}  direction"]
    for r in rows[-30:]:
        pct = lambda v: "   -" if v is None else f"{v * 100:4.0f}"
        lines.append(f"  {r['scanned_at']:<26}{r['paradox']:>8.1f}{pct(r['fast']):>7}{pct(r['slow']):>7}"
                     f"  {r['direction']}{'  [veneer]' if r['veneer'] else ''}")
    lines.append("")
    for b in lag["beacons"]:
        lines.append(f"  first flagged by {b['name']} ({b['tier']}) at {b['first_flagged']}")
    if lag["lag_days"] is not None:
        lines.append(f"  slow tier lag behind fast tier: {lag['lag_days']} days")
    elif lag["open_days"] is not None:
        lines.append(f"  fast tier flagged it {lag['open_days']} days ago; slow tier has not caught up")
    return "\n".join(lines) + "\n"


def rescan_tracked(pause: float = 2.0) -> int:
    """Rescan every IP with history - run from cron to build timelines."""
    ips = [t["ip"] for t in history.tracked()]
    for i, ip in enumerate(ips):
        if i:
            time.sleep(pause)  # stay polite to keyless APIs
        r = scan(ip, use_cache=False)
        sc = r["score"]
        print(f"{ip:<40} paradox {sc['paradox']:5.1f}  {sc['paradox_label']:<15} {sc['direction']}")
    return 0


def scan_log(args) -> int:
    from . import logscan
    try:
        src = sys.stdin if args.log == "-" else open(args.log, encoding="utf-8", errors="replace")
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    with src:
        progress = lambda done, total, ip: print(f"  [{done}/{total}] {ip}", file=sys.stderr, flush=True)
        result = logscan.scan_lines(src, limit=args.limit, min_hits=args.min_hits, progress=progress)
    if args.json:
        print(json.dumps(result, indent=2))
    elif args.csv:
        logscan.to_csv(result, sys.stdout)
    else:
        print(logscan.render(result))
    flagged = sum(result["summary"]["flags"][f] for f in ("veneer", "paradox", "threat"))
    return 1 if flagged else 0   # nonzero exit lets scripts and CI react to findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="paradox", description="Cyber security paradox detector")
    ap.add_argument("ip", nargs="?")
    ap.add_argument("--json", action="store_true", help="print the raw report as JSON")
    ap.add_argument("--narrate", action="store_true", help="add a Claude-written analyst summary")
    ap.add_argument("--history", action="store_true", help="show recorded scans for the IP instead of scanning")
    ap.add_argument("--rescan-tracked", action="store_true", help="rescan every IP with recorded history")
    ap.add_argument("--log", metavar="FILE", help="batch mode: scan the IPs found in a log file ('-' for stdin)")
    ap.add_argument("--limit", type=int, default=25, help="with --log: scan at most N of the most active IPs (0 = all)")
    ap.add_argument("--min-hits", type=int, default=1, help="with --log: skip IPs seen fewer than N times")
    ap.add_argument("--csv", action="store_true", help="with --log: print results as CSV")
    args = ap.parse_args(argv)
    if args.rescan_tracked:
        return rescan_tracked()
    if args.log:
        return scan_log(args)
    if not args.ip:
        ap.error("an IP address is required")
    if args.history:
        try:
            print(render_history(normalize_ip(args.ip)))
        except InvalidTarget as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        return 0
    try:
        report = scan(args.ip, use_cache=False)
    except InvalidTarget as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.narrate:
        from .narrative import NarrativeUnavailable, summarize
        try:
            report["narrative"] = summarize(report)
        except NarrativeUnavailable as err:
            report["narrative_error"] = str(err)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render(report))
        if report.get("narrative"):
            print("  -- ANALYST SUMMARY --\n" + report["narrative"] + "\n")
        elif report.get("narrative_error"):
            print(f"  (summary unavailable: {report['narrative_error']})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
