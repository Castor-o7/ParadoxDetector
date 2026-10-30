"""Check the scores against IPs with known answers.

    python3 -m paradox.calibrate              # scan the labeled set (cached) and report
    python3 -m paradox.calibrate --rescore    # re-score saved scans offline, no API calls
    python3 -m paradox.calibrate --new-labels # draw a fresh labeled set
    python3 -m paradox.calibrate --refresh abuseipdb   # re-run just these beacons on saved scans

Labels must not come from the score's own inputs, or the test grades itself:

* malicious: IPs on at least 2 of blocklist.de, CINS Army and ET compromised.
  Those lists feed only the *neighborhood* check, which excludes the IP itself,
  so an IP's own listing never reaches its score. IPs on Feodo or Spamhaus DROP
  (direct inputs) are left out.
* benign: public DNS resolvers and the front-end IPs of major sites.

Scanning blocklists also list research scanners (Shodan, Censys...), which are
reported for doing exactly what they say. The headline numbers stay *strict*:
every sampled IP counts as malicious. A second, *scanner-aware* view sets aside
IPs with a scanner label and reports them as their own class. That label is
itself a score input, so the scanner-aware view is never the headline: it
would hide the scanner rule's cost if it replaced the strict one.

Raw beacon results are saved per IP, so weights in scoring.py can be tuned and
re-scored offline (--rescore) without hitting the APIs again.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import socket
import sys
import time

from concurrent.futures import ThreadPoolExecutor

from . import config, scoring
from .sources import (BEACONS, NEIGHBOR_LISTS, Signal, _drop_networks, _feodo_index, _ip_list,
                      apply_otx, fetch_otx, run_beacon)

DIR = config.DATA_DIR / "calibration"
SCANS = DIR / "scans"
LABELS = DIR / "labels.json"

BENIGN_IPS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
              "208.67.222.222", "208.67.220.220", "94.140.14.14", "76.76.2.0"]
BENIGN_DOMAINS = ["google.com", "wikipedia.org", "github.com", "microsoft.com", "apple.com",
                  "cloudflare.com", "amazon.com", "netflix.com", "mozilla.org", "python.org",
                  "pdx.edu", "nasa.gov", "bbc.co.uk", "stackoverflow.com", "linkedin.com"]


def benign_set() -> list[str]:
    ips = list(BENIGN_IPS)
    for domain in BENIGN_DOMAINS:
        try:
            ips.append(socket.getaddrinfo(domain, 443, socket.AF_INET)[0][4][0])
        except OSError:
            print(f"  could not resolve {domain}, skipping", file=sys.stderr)
    return [ip for ip in dict.fromkeys(ips) if ipaddress.ip_address(ip).is_global]


def malicious_set(size: int, seed: int) -> list[str]:
    hits: dict[str, int] = {}
    for name, url in NEIGHBOR_LISTS:
        for entry in set(_ip_list(name, url)):
            hits[entry] = hits.get(entry, 0) + 1
    inputs = set(_feodo_index())
    drop = [ipaddress.ip_network(c, strict=False) for c, _ in _drop_networks()]
    pool = []
    for ip, n in hits.items():
        if n < 2 or ip in inputs:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_global and not any(addr.version == d.version and addr in d for d in drop):
            pool.append(ip)
    pool.sort()
    return random.Random(seed).sample(pool, min(size, len(pool)))


def load_labels(new: bool, size: int, seed: int) -> dict:
    if LABELS.exists() and not new:
        return json.loads(LABELS.read_text())
    labels = {"seed": seed, "created": time.strftime("%Y-%m-%d"),
              "benign": benign_set(), "malicious": malicious_set(size, seed)}
    DIR.mkdir(parents=True, exist_ok=True)
    LABELS.write_text(json.dumps(labels, indent=1))
    return labels


def scan_raw(ip: str) -> dict:
    """Run every beacon, keeping OTX's raw response so OTX scoring can be
    re-tuned offline (OTX is the beacon with the most tunable judgment)."""
    try:
        otx_raw, otx_error = fetch_otx(ip), None
    except Exception as exc:
        otx_raw, otx_error = None, f"{type(exc).__name__}: {exc}"
    others = [b for b in BEACONS if b.id != "otx"]
    with ThreadPoolExecutor(max_workers=len(others)) as pool:
        signals = list(pool.map(lambda b: run_beacon(b, ip), others))
    return {"signals": [s.to_dict() for s in signals], "otx_raw": otx_raw, "otx_error": otx_error}


def build_signals(ip: str, saved: dict) -> list[Signal]:
    """Rebuild a scan's signals, re-scoring OTX from its raw response with the
    current settings in sources.py."""
    otx = next(b for b in BEACONS if b.id == "otx")
    sig = Signal(source=otx.id, name=otx.name, tier=otx.tier)
    if saved.get("otx_raw") is not None:
        apply_otx(ip, sig, saved["otx_raw"])
    else:
        sig.status, sig.summary = "error", saved.get("otx_error") or "no OTX data"
    others = [Signal(**s) for s in saved["signals"]]
    for s in others:   # scans saved before GreyNoise marked scanner labels (2026-10-29)
        if s.facts.get("benign_label", "").startswith("GreyNoise benign:"):
            s.facts.setdefault("label_kind", "scanner")
        if s.source == "abuseipdb" and (m := re.search(r"by (\d+) users", s.summary)):
            s.facts.setdefault("reporters", int(m[1]))   # scans saved before reporters was a fact
    return [sig] + others


def collect(ips: list[str], pause: float, offline: bool) -> dict[str, list[Signal]]:
    SCANS.mkdir(parents=True, exist_ok=True)
    out = {}
    limited = 0
    for i, ip in enumerate(ips, 1):
        path = SCANS / f"{ip.replace(':', '_')}.json"
        saved = json.loads(path.read_text()) if path.exists() else None
        stale = isinstance(saved, dict) and any(
            m in (saved.get("otx_error") or "") for m in ("rate limit", "HTTP 429"))
        if not isinstance(saved, dict) or (stale and not offline):  # missing, old format, or OTX gap
            if offline:
                continue
            print(f"  [{i}/{len(ips)}] scanning {ip}", file=sys.stderr, flush=True)
            saved = scan_raw(ip)
            if "HTTP 429" in (saved["otx_error"] or "") or "rate limit" in (saved["otx_error"] or ""):
                # Don't freeze a scan with OTX missing: leave it for a later run
                # and stop early rather than spending other beacons' quotas.
                limited += 1
                if limited >= 3:
                    print("  OTX is rate-limiting or down; stopping. Re-run later (or set OTX_API_KEY) "
                          "to fill in the remaining IPs.", file=sys.stderr)
                    break
                time.sleep(pause)
                continue
            limited = 0
            path.write_text(json.dumps(saved))
            time.sleep(pause)
        out[ip] = build_signals(ip, saved)
    return out


def refresh(ips: list[str], beacon_ids: list[str], pause: float) -> None:
    """Re-run only some beacons on saved scans (after a beacon gains new fields),
    keeping the old reading wherever the new call fails."""
    chosen = [b for b in BEACONS if b.id in beacon_ids and b.id != "otx"]
    for i, ip in enumerate(ips, 1):
        path = SCANS / f"{ip.replace(':', '_')}.json"
        if not path.exists():
            continue
        saved = json.loads(path.read_text())
        for b in chosen:
            new = run_beacon(b, ip)
            if new.status == "ok":   # replace the saved reading, or add a beacon newer than the scan
                saved["signals"] = [s for s in saved["signals"] if s["source"] != b.id] + [new.to_dict()]
            else:
                print(f"  {ip}: {b.id} {new.status}, keeping saved reading", file=sys.stderr)
        path.write_text(json.dumps(saved))
        print(f"  [{i}/{len(ips)}] refreshed {ip}", file=sys.stderr, flush=True)
        time.sleep(pause)


def auc(pos: list[float], neg: list[float]) -> float | None:
    """Probability a random malicious IP outscores a random benign one."""
    if not pos or not neg:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def evaluate(labels: dict, scans: dict[str, list[Signal]]) -> dict:
    rows = []
    for cls in ("malicious", "benign"):
        for ip in labels[cls]:
            if ip in scans:
                sc = scoring.compute(scans[ip])
                scanner_by = sorted({s.name for s in scans[ip]
                                     if s.status == "ok" and s.facts.get("label_kind") == "scanner"})
                rows.append({"ip": ip, "label": cls, "threat": sc["threat"], "paradox": sc["paradox"],
                             "direction": sc["direction"], "network_risk": sc["network"]["risk"],
                             "scanner_by": scanner_by, "explained": sc["scanner"]["explained"],
                             "veneer": sc["veneer"]["active"], "signals": scans[ip]})
    bad = [r for r in rows if r["label"] == "malicious"]
    good = [r for r in rows if r["label"] == "benign"]
    flag = lambda r: r["threat"] >= 0.15   # "Suspicious" or worse

    beacons: dict[str, dict] = {}
    for r in rows:
        for s in r["signals"]:
            if s.tier == "context":
                continue
            b = beacons.setdefault(s.name, {"tier": s.tier, "errors": 0, "skipped": 0, "ok": 0,
                                            "hit_malicious": 0, "hit_benign": 0})
            b[{"ok": "ok", "error": "errors", "skipped": "skipped"}[s.status]] += 1
            if s.status == "ok" and (s.threat or 0) >= 0.4:
                b["hit_" + r["label"]] += 1

    mean = lambda xs: round(sum(xs) / len(xs), 3) if xs else None
    scanners = [r for r in bad if r["scanner_by"]]
    unlabeled = [r for r in bad if not r["scanner_by"]]
    scanner_aware = {
        "malicious": len(unlabeled),
        "threat_auc": auc([r["threat"] for r in unlabeled], [r["threat"] for r in good]),
        "detection_rate": mean([flag(r) for r in unlabeled]),
        "misses": [r["ip"] for r in unlabeled if not flag(r)],
    }
    scanner_class = [{
        "ip": r["ip"], "identified_by": r["scanner_by"], "threat": r["threat"], "paradox": r["paradox"],
        # What the detector should say about a scanner: either "known scanner doing scanning" or,
        # if it is doing more than scanning, a veneer.
        "verdict": "veneer" if r["veneer"] else "explained" if r["explained"] else "unexplained",
    } for r in scanners]
    return {
        "counts": {"malicious": len(bad), "benign": len(good)},
        "threat_auc": auc([r["threat"] for r in bad], [r["threat"] for r in good]),
        "threat_mean": {"malicious": mean([r["threat"] for r in bad]),
                        "benign": mean([r["threat"] for r in good])},
        "detection_rate": mean([flag(r) for r in bad]),
        "false_positive_rate": mean([flag(r) for r in good]),
        "benign_false_tension": mean([r["paradox"] >= 15 for r in good]),
        "benign_false_paradox": mean([r["paradox"] >= 35 for r in good]),
        "paradox_mean": {"malicious": mean([r["paradox"] for r in bad]),
                         "benign": mean([r["paradox"] for r in good])},
        "scanner_aware": scanner_aware,
        "scanners": scanner_class,
        "beacons": beacons,
        "misses": sorted(((r["ip"], r["threat"]) for r in bad if not flag(r)), key=lambda x: x[1]),
        "false_alarms": [(r["ip"], r["threat"], r["paradox"]) for r in good
                         if flag(r) or r["paradox"] >= 15],
        "rows": [{k: v for k, v in r.items() if k != "signals"} for r in rows],
    }


def render(ev: dict) -> str:
    pct = lambda v: "n/a" if v is None else f"{v * 100:.0f}%"
    a = ev["threat_auc"]
    lines = [
        f"\n  Calibration: {ev['counts']['malicious']} malicious, {ev['counts']['benign']} benign IPs",
        f"  Threat AUC          {'n/a' if a is None else f'{a:.3f}'}   (1.0 = perfect ranking, 0.5 = coin flip)",
        f"  Mean threat         malicious {ev['threat_mean']['malicious']}   benign {ev['threat_mean']['benign']}",
        f"  Detection rate      {pct(ev['detection_rate'])} of malicious IPs rated Suspicious or worse",
        f"  False positives     {pct(ev['false_positive_rate'])} of benign IPs rated Suspicious or worse",
        f"  Benign paradox      {pct(ev['benign_false_tension'])} >= 15 (tension), {pct(ev['benign_false_paradox'])} >= 35 (paradox)",
        f"  Mean paradox        malicious {ev['paradox_mean']['malicious']}   benign {ev['paradox_mean']['benign']}",
        "",
        f"  {'beacon':<34}{'tier':<9}{'ok':>4}{'err':>5}{'skip':>6}{'hits bad':>10}{'hits good':>11}",
    ]
    for name, b in ev["beacons"].items():
        lines.append(f"  {name:<34}{b['tier']:<9}{b['ok']:>4}{b['errors']:>5}{b['skipped']:>6}"
                     f"{b['hit_malicious']:>10}{b['hit_benign']:>11}")
    if ev["false_alarms"]:
        lines += ["", "  Benign IPs that raised flags:"]
        lines += [f"    {ip:<18} threat {t:.2f}  paradox {p:.0f}" for ip, t, p in ev["false_alarms"]]
    if ev["misses"]:
        lines += ["", f"  Malicious IPs rated Likely benign: {len(ev['misses'])} "
                      f"(e.g. {', '.join(ip for ip, _ in ev['misses'][:5])})"]
    if ev["scanners"]:
        sa = ev["scanner_aware"]
        sa_auc = "n/a" if sa["threat_auc"] is None else f"{sa['threat_auc']:.3f}"
        lines += ["", f"  Research scanners in the malicious sample: {len(ev['scanners'])} (scanner label from "
                      "a score input, so this view is secondary)"]
        lines += [f"    {r['ip']:<18} {r['verdict']:<12} threat {r['threat']:.2f}  paradox {r['paradox']:.0f}  "
                  f"via {', '.join(r['identified_by'])}" for r in ev["scanners"]]
        lines += [f"  Scanner-aware: {sa['malicious']} malicious, AUC {sa_auc}, "
                  f"detection {pct(sa['detection_rate'])}"
                  + (f", misses {', '.join(sa['misses'])}" if sa["misses"] else "")]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="paradox calibrate", description=__doc__.split("\n\n")[0])
    ap.add_argument("--rescore", action="store_true", help="score saved scans only; no API calls")
    ap.add_argument("--new-labels", action="store_true", help="draw a fresh labeled set")
    ap.add_argument("--size", type=int, default=30, help="malicious sample size (default 30)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--pause", type=float, default=1.5, help="seconds between live scans")
    ap.add_argument("--refresh", nargs="+", metavar="BEACON", help="re-run only these beacon ids on saved scans")
    args = ap.parse_args(argv)

    labels = load_labels(args.new_labels, args.size, args.seed)
    if args.new_labels:
        for f in SCANS.glob("*.json"):
            f.unlink()
    if args.refresh:
        unknown = set(args.refresh) - {b.id for b in BEACONS if b.id != "otx"}
        if unknown:
            ap.error(f"unknown beacon id(s): {', '.join(sorted(unknown))} (OTX is re-scored with --rescore)")
        refresh(labels["malicious"] + labels["benign"], args.refresh, args.pause)
    scans = collect(labels["malicious"] + labels["benign"], args.pause, offline=args.rescore or bool(args.refresh))
    ev = evaluate(labels, scans)
    print(render(ev))
    (DIR / "report.json").write_text(json.dumps(ev, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
