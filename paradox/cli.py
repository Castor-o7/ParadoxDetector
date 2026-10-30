"""The `paradox` command. With no arguments it opens the app; every subcommand
except `app` is headless (no browser, machine-readable with --json, and an
exit status scripts can act on).

Exit status: 0 = nothing flagged, 1 = something flagged (veneer, paradox or
threat), 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__, config, history
from .engine import InvalidTarget, normalize_ip, scan

ALERT_FLAGS = ("veneer", "paradox", "threat")


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
    if sc.get("ledger"):
        lines[-1:-1] = render_ledger(sc["ledger"])
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


def render_ledger(ledger: dict) -> list[str]:
    lines = []
    for name, key in (("Paradox", "paradox"), ("Threat", "threat")):
        lines.append(f"  {name} points:")
        lines += [f"    {r['points']:+6.1f}  {r['label']}" for r in ledger[key]] or ["      none"]
    lines += [f"  adjusted: {a['beacon']} {a['field']} {a['from']:.2f} -> {a['to']:.2f} ({a['why']})"
              for a in ledger["adjustments"]]
    return lines


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


# --- subcommands ----------------------------------------------------------------

def cmd_app(args) -> int:
    from .server import run
    return run(args.host, args.port, open_browser=not args.no_browser)


def cmd_serve(args) -> int:
    from .server import run
    return run(args.host, args.port)


def cmd_scan(args) -> int:
    from .logscan import flag_of
    reports, flagged = [], False
    for raw in args.ip:
        try:
            report = scan(raw, use_cache=False)
        except InvalidTarget as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        if args.narrate:
            from .narrative import NarrativeUnavailable, summarize
            try:
                report["narrative"] = summarize(report)
            except NarrativeUnavailable as err:
                report["narrative_error"] = str(err)
        report["flag"] = flag_of(report["score"])
        flagged |= report["flag"] in ALERT_FLAGS
        reports.append(report)
        if not args.json:
            print(render(report))
            if report.get("narrative"):
                print("  -- ANALYST SUMMARY --\n" + report["narrative"] + "\n")
            elif report.get("narrative_error"):
                print(f"  (summary unavailable: {report['narrative_error']})\n")
    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2))
    return 1 if flagged else 0


def cmd_log(args) -> int:
    from . import logscan
    try:
        src = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")
    except OSError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    with src:
        progress = None if args.quiet else (
            lambda done, total, ip: print(f"  [{done}/{total}] {ip}", file=sys.stderr, flush=True))
        result = logscan.scan_lines(src, limit=args.limit, min_hits=args.min_hits, progress=progress)
    if args.json:
        print(json.dumps(result, indent=2))
    elif args.csv:
        logscan.to_csv(result, sys.stdout)
    else:
        print(logscan.render(result))
    return 1 if any(result["summary"]["flags"][f] for f in ALERT_FLAGS) else 0


def cmd_watch(args) -> int:
    from .watch import Watcher
    alert_on = [f.strip() for f in args.alert_on.split(",") if f.strip()]
    bad = set(alert_on) - {"veneer", "paradox", "threat", "watch"}
    if bad:
        print(f"error: unknown --alert-on flag(s): {', '.join(sorted(bad))}", file=sys.stderr)
        return 2
    w = Watcher(min_hits=args.min_hits, rescan_after_h=args.rescan_after, alert_on=alert_on,
                workers=args.workers, webhook=args.webhook, as_json=args.json)
    return w.run(args.log or [], from_start=args.from_start, rescan_every_h=args.rescan_every)


def cmd_history(args) -> int:
    try:
        ip = normalize_ip(args.ip)
    except InvalidTarget as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"ip": ip, "scans": history.scans(ip), "lag": history.lag(ip)}, indent=2))
    else:
        print(render_history(ip))
    return 0


def cmd_rescan(args) -> int:
    return rescan_tracked(args.pause)


def cmd_mcp(args) -> int:
    from . import mcp_server
    print(f"paradox-detector MCP server {__version__} on stdio", file=sys.stderr)
    mcp_server.serve()
    return 0


def cmd_calibrate(args) -> int:
    from . import calibrate
    return calibrate.main([])


def cmd_beacons(args) -> int:
    from .engine import beacon_status
    rows = beacon_status()
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for b in rows:
        key = ("no key needed" if not b["key_env"] else
               f"{b['key_env']} {'set' if b['key_set'] else 'MISSING (skipped)' if b['key_required'] else 'not set (keyless)'}")
        print(f"  {b['tier']:<8} {b['name']:<34} {key}")
    print(f"\n  keys file: {config.ENV_FILE}{'' if config.ENV_FILE.exists() else '  (not created yet: run paradox init)'}")
    return 0


def cmd_init(args) -> int:
    env = config.ENV_FILE
    if env.exists():
        print(f"{env} already exists; edit it to add keys.")
        return 0
    env.parent.mkdir(parents=True, exist_ok=True)
    env.write_text((config.PACKAGE / "env.example").read_text())
    env.chmod(0o600)
    print(f"Created {env} (readable only by you). Add whichever API keys you have; every one is optional.")
    return 0


def cmd_where(args) -> int:
    print(json.dumps({"home": str(config.HOME), "keys": str(config.ENV_FILE),
                      "history": str(config.DATA_DIR / "history.sqlite3"), "cache": str(config.CACHE_DIR),
                      "version": __version__}, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="paradox", description="Cyber security paradox detector. "
                                 "Run with no arguments to open the app.")
    ap.add_argument("--version", action="version", version=f"paradox {__version__}")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")

    def add(name, func, help):
        p = sub.add_parser(name, help=help, description=help)
        p.set_defaults(func=func)
        return p

    for name, func, help in (("app", cmd_app, "open the app in your browser (default)"),
                             ("serve", cmd_serve, "headless web/API server, no browser")):
        p = add(name, func, help)
        p.add_argument("--host", help="bind address (default 127.0.0.1 or PARADOX_HOST)")
        p.add_argument("--port", type=int, help="port (default 8787 or PARADOX_PORT)")
        if name == "app":
            p.add_argument("--no-browser", action="store_true", help="don't open a browser tab")

    p = add("scan", cmd_scan, "scan one or more IPs")
    p.add_argument("ip", nargs="+")
    p.add_argument("--json", action="store_true", help="print the raw report as JSON")
    p.add_argument("--narrate", action="store_true", help="add a Claude-written analyst summary")

    p = add("log", cmd_log, "rank every IP in a log file ('-' for stdin)")
    p.add_argument("file")
    p.add_argument("--limit", type=int, default=25, help="scan at most N of the most active IPs (0 = all)")
    p.add_argument("--min-hits", type=int, default=1, help="skip IPs seen fewer than N times")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true")
    out.add_argument("--csv", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress lines on stderr")

    p = add("watch", cmd_watch, "headless sensor: follow logs live and alert on findings")
    p.add_argument("--log", action="append", metavar="FILE", help="log to follow (repeatable; '-' for stdin)")
    p.add_argument("--from-start", action="store_true", help="read existing lines too, not just new ones")
    p.add_argument("--min-hits", type=int, default=1, help="scan an IP once it has appeared N times")
    p.add_argument("--rescan-after", type=float, default=24, metavar="HOURS",
                   help="rescan an IP that keeps appearing after this long (default 24)")
    p.add_argument("--rescan-every", type=float, default=0, metavar="HOURS",
                   help="also rescan every tracked IP on this interval (0 = off)")
    p.add_argument("--alert-on", default=",".join(ALERT_FLAGS),
                   help="comma-separated flags that alert (default veneer,paradox,threat; add watch)")
    p.add_argument("--webhook", metavar="URL", help="POST each alert as JSON (Slack-compatible 'text')")
    p.add_argument("--workers", type=int, default=2, help="concurrent scans (default 2)")
    p.add_argument("--json", action="store_true", help="one JSON object per alert on stdout")

    p = add("history", cmd_history, "recorded scans and beacon lag for an IP")
    p.add_argument("ip")
    p.add_argument("--json", action="store_true")

    p = add("rescan", cmd_rescan, "rescan every tracked IP once (for cron)")
    p.add_argument("--pause", type=float, default=2.0, help="seconds between scans")

    add("mcp", cmd_mcp, "MCP server on stdio, for AI assistants")

    sub.add_parser("calibrate", help="check scores against labeled IPs (paradox calibrate -h for options)",
                   add_help=False).set_defaults(func=cmd_calibrate)

    p = add("beacons", cmd_beacons, "list beacons and which API keys are set")
    p.add_argument("--json", action="store_true")
    add("init", cmd_init, "create the keys file (.env) in the app's home directory")
    add("where", cmd_where, "show where keys, history and caches are stored")
    return ap


COMMANDS = {"app", "serve", "scan", "log", "watch", "history", "rescan", "mcp", "calibrate",
            "beacons", "init", "where"}


def legacy(argv: list[str]) -> list[str]:
    """Translate the pre-subcommand CLI (`paradox 1.2.3.4`, `--log`, `--history`,
    `--rescan-tracked`) so existing scripts and cron lines keep working."""
    if not argv or argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version"):
        return argv
    if "--rescan-tracked" in argv:
        return ["rescan"]
    if "--log" in argv:
        i = argv.index("--log")
        rest = argv[:i] + argv[i + 2:]
        return ["log", argv[i + 1] if i + 1 < len(argv) else "-"] + rest
    if "--history" in argv:
        return ["history"] + [a for a in argv if a != "--history"]
    return ["scan"] + argv


def main(argv: list[str] | None = None) -> int:
    argv = legacy(list(sys.argv[1:] if argv is None else argv))
    if argv[:1] == ["calibrate"]:                # it has its own options and help
        from . import calibrate
        return calibrate.main(argv[1:])
    args = parser().parse_args(argv or ["app"])
    if not getattr(args, "func", None):
        parser().print_help()
        return 2
    return args.func(args)
