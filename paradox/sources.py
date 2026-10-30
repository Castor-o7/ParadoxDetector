"""Threat-intel beacons.

Each beacon turns its raw response into a Signal: a threat estimate in [0, 1]
plus how confident that estimate is. Beacons are grouped into tiers by how
quickly they react to new activity:

  fast    - live community/sensor data that updates within hours
  slow    - curated lists, vendor consensus, periodic scan data (days to weeks)
  network - the IP's surroundings: its /24 neighbors and the network (ASN) it
            lives in. Scored separately from fast/slow, because guilt by
            association is a different claim from direct evidence.
  context - useful facts that are not scored (ownership, Tor exit status)

Absence from a list is evidence too ("not listed" -> threat 0), but usually
weaker evidence than a hit, so it gets lower confidence.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import config
from .net import cached, fetch, fetch_json


@dataclass
class Signal:
    source: str
    name: str
    tier: str
    status: str = "ok"            # ok | skipped | error
    failure: str | None = None    # why it didn't answer: no_key | rate_limited | bad_key | error
    threat: float | None = None   # 0 = benign, 1 = confirmed malicious
    confidence: float = 0.0       # how much this reading should count
    last_seen: str | None = None  # ISO date of the freshest evidence
    summary: str = ""
    evidence: list[str] = field(default_factory=list)
    link: str | None = None
    latency_ms: int = 0
    facts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Beacon:
    id: str
    name: str
    tier: str
    weight: float
    check: Callable[[str, Signal], None]
    key_env: str | None = None
    key_required: bool = False
    cadence: str = ""
    origin: str = ""  # upstream data source; beacons sharing one are not independent


# --- helpers -----------------------------------------------------------------

def parse_dt(value) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip().replace("Z", "+00:00").replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def age_days(dt: datetime | None, now: datetime | None = None) -> float | None:
    if dt is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86400)


def iso_date(dt: datetime | None) -> str | None:
    return dt.date().isoformat() if dt else None


def _ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version


class BeaconError(Exception):
    failure = "error"


class RateLimited(BeaconError):
    failure = "rate_limited"


class BadKey(BeaconError):
    failure = "bad_key"


def _expect_ok(status: int, data, what: str) -> None:
    if status == 429:
        raise RateLimited(f"{what} is rate limiting or overloaded (HTTP 429); try again later "
                          "or add an API key")
    if status in (401, 403):
        raise BadKey(f"{what} rejected the API key (HTTP {status})")
    if status >= 400 or data is None:
        raise BeaconError(f"{what} returned HTTP {status}")


# --- fast tier ---------------------------------------------------------------

OTX_HALF_LIFE_DAYS = 30.0
# Tunable OTX settings (see paradox/calibrate.py). Calibration on 2026-10-27
# showed benign infrastructure (DNS resolvers, GitHub, CDNs) appearing in huge
# sandbox-dump pulses, while malicious IPs appear in small targeted feeds.
OTX_AUTOMATED_FACTOR = 0.6
OTX_SPECIFIC_INDICATORS = 1000   # pulses up to this size count fully
OTX_SPECIFICITY_POWER = 0.75     # 3,000 indicators -> 0.44, 20,000 -> 0.11
OTX_WHITELIST_FACTOR = 0.2
JUNK_PULSE_NAME = re.compile(r"^\s*(test\w*|\d+|.{0,3}|.*clone.*)\s*$", re.IGNORECASE)


def pulse_quality(p: dict) -> tuple[float, list[str]]:
    """How much one pulse should count as evidence, 0-1, plus the reasons it was
    discounted. Anyone can publish an OTX pulse, so test pulses, clones and
    pulses nobody follows count for less than curated research."""
    q, why = 1.0, []
    if p.get("pulse_source") == "api" and OTX_AUTOMATED_FACTOR < 1:
        q *= OTX_AUTOMATED_FACTOR
        why.append("automated")
    size = p.get("indicator_count") or 0
    if size > OTX_SPECIFIC_INDICATORS:
        # A sandbox report listing every IP a sample touched also lists the
        # DNS resolvers and CDNs it used, so huge pulses say little per IP.
        q *= (OTX_SPECIFIC_INDICATORS / size) ** OTX_SPECIFICITY_POWER
        why.append(f"bulk: {size:,} indicators")
    if p.get("cloned_from"):
        q *= 0.3
        why.append("clone")
    if JUNK_PULSE_NAME.match(p.get("name") or ""):
        q *= 0.3
        why.append("test/junk")
    subs = p.get("subscriber_count") or 0
    q *= 0.5 + 0.5 * min(1.0, math.log10(subs + 1) / 3)  # 1000+ subscribers = full credit
    return q, why


def score_otx(data: dict, now: datetime | None = None) -> dict:
    """Score OTX pulses by recency, quality and independence.

    * Recency: a pulse touched today counts fully, one a month old counts half.
    * Quality: see pulse_quality().
    * Independence: each author counts once (their best pulse), so one account
      flooding pulses about an IP cannot inflate - or smear - its score.
    """
    pulses = (data.get("pulse_info") or {}).get("pulses") or []
    total = (data.get("pulse_info") or {}).get("count", len(pulses))
    dated = []
    for p in pulses:
        dt = parse_dt(p.get("modified") or p.get("created"))
        dated.append((dt, p))
    dated.sort(key=lambda x: x[0] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

    by_author: dict[str, float] = {}
    pulse_counts: dict[str, int] = {}
    recent_30 = 0
    discounted = 0
    families: set[str] = set()
    for dt, p in dated:
        author = ((p.get("author") or {}).get("username") or "?").lower()
        pulse_counts[author] = pulse_counts.get(author, 0) + 1
        age = age_days(dt, now)
        if age is None:
            continue
        q, why = pulse_quality(p)
        discounted += bool(why)
        by_author[author] = max(by_author.get(author, 0.0), q * 0.5 ** (age / OTX_HALF_LIFE_DAYS))
        if age <= 30:
            recent_30 += 1
            for fam in p.get("malware_families") or []:
                families.add(fam.get("display_name") if isinstance(fam, dict) else str(fam))
            if p.get("adversary"):
                families.add(f"adversary: {p['adversary']}")

    mass = sum(by_author.values())
    threat = 1 - math.exp(-mass / 1.5)
    validation = data.get("validation") or []
    whitelisted = [v.get("name") or v.get("source") for v in validation if isinstance(v, dict)]
    if whitelisted:
        # OTX vouching for an IP mostly means its own pulses about it are noise
        # (malware contacting a DNS resolver). The label is still recorded, so
        # the veneer check fires if an *independent* beacon disagrees.
        threat *= OTX_WHITELIST_FACTOR
    authors = len(pulse_counts)
    flooders = sorted(((n, a) for a, n in pulse_counts.items() if n >= 3), reverse=True)
    newest = dated[0][0] if dated else None
    return {
        "threat": round(threat, 3),
        "confidence": round(min(1.0, 0.45 + 0.1 * authors), 3) if pulses else 0.5,
        "total": total,
        "authors": authors,
        "recent_30": recent_30,
        "discounted": discounted,
        "flooders": [(a, n) for n, a in flooders],
        "newest": newest,
        "families": sorted(f for f in families if f),
        "whitelisted": whitelisted,
        "top": [(iso_date(dt), p.get("name", ""), pulse_quality(p)[1]) for dt, p in dated[:5]],
    }


def fetch_otx(ip: str) -> dict:
    kind = "IPv6" if _ip_version(ip) == 6 else "IPv4"
    headers = {"X-OTX-API-KEY": k} if (k := config.key("OTX_API_KEY")) else None
    status, data = fetch_json(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/general",
                              headers=headers, timeout=max(config.HTTP_TIMEOUT, 25))
    _expect_ok(status, data, "OTX")
    return data


def check_otx(ip: str, sig: Signal) -> None:
    apply_otx(ip, sig, fetch_otx(ip))


# --- scanning vs. attacking ---------------------------------------------------
# A known research scanner (Shodan, Censys) gets reported everywhere for doing
# exactly what it says it does. Each beacon reports what share of its evidence
# is plain scanning, so scoring can tell "a scanner scanning" (expected) from
# "a scanner label on an IP that brute-forces and drops malware" (veneer).

ABUSE_SCAN_CATEGORIES = {14, 15}       # AbuseIPDB: Port Scan, Hacking (generic)
SCAN_TERMS = re.compile(r"scan|recon|masscan|zmap|crawler|probe|sensor-tagged", re.I)
ATTACK_TERMS = re.compile(r"brute|malware|botnet|\bc2\b|c&c|command.and.control|exploit|cve-|payload|"
                          r"loader|ransom|phish|ddos|miner|webshell|web-attack|intrusion|stealer|\brat\b", re.I)


def abuse_scan_share(reports: list[dict]) -> float | None:
    """Share of AbuseIPDB reports that are only port scans/generic hacking."""
    cats = [set(r.get("categories") or []) for r in reports]
    cats = [c for c in cats if c]
    if not cats:
        return None
    return round(sum(c <= ABUSE_SCAN_CATEGORIES for c in cats) / len(cats), 3)


def otx_scan_share(data: dict) -> float | None:
    """Share of OTX pulses (with a clear theme) that are about scanning rather
    than attacks. Tags describe the whole pulse, not this IP, and honeypot feeds
    tag everything "bruteforce" - so pulses that mention both, or neither, don't vote."""
    scan = attack = 0
    for p in (data.get("pulse_info") or {}).get("pulses") or []:
        text = " ".join([p.get("name") or ""] + [str(t) for t in p.get("tags") or []])
        is_attack, is_scan = bool(ATTACK_TERMS.search(text)), bool(SCAN_TERMS.search(text))
        if is_attack and not is_scan:
            attack += 1
        elif is_scan and not is_attack:
            scan += 1
    return round(scan / (scan + attack), 3) if scan + attack else None


def apply_otx(ip: str, sig: Signal, data: dict) -> None:
    """Fill an OTX signal from a raw response (separate so calibration can
    re-score saved responses offline)."""
    s = score_otx(data)
    sig.threat, sig.confidence = s["threat"], s["confidence"]
    sig.last_seen = iso_date(s["newest"])
    sig.link = f"https://otx.alienvault.com/indicator/ip/{ip}"
    sig.summary = (f"{s['total']} pulses from {s['authors']} authors, "
                   f"{s['recent_30']} touched in the last 30 days"
                   if s["total"] else "Not referenced in any OTX pulse")
    sig.evidence = [f"{d}  {name}" + (f"  [{', '.join(why)}]" if why else "")
                    for d, name, why in s["top"]]
    if s["families"]:
        sig.evidence.append("Recent families: " + ", ".join(s["families"][:8]))
    if s["flooders"]:
        sig.evidence.append("Counted once per author: " + ", ".join(f"{a} ({n} pulses)" for a, n in s["flooders"][:3]))
    if s["discounted"]:
        sig.evidence.append(f"{s['discounted']} pulses discounted (automated, bulk, cloned, test or unfollowed)")
    sig.facts = {"asn": data.get("asn"), "country": data.get("country_name"),
                 "authors": s["authors"], "flooders": s["flooders"],
                 "scan_share": otx_scan_share(data)}
    if s["whitelisted"]:
        sig.facts["benign_label"] = "OTX validation: " + ", ".join(map(str, s["whitelisted"]))


def check_greynoise(ip: str, sig: Signal) -> None:
    headers = {"key": k} if (k := config.key("GREYNOISE_API_KEY")) else None
    status, data = fetch_json(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    sig.link = f"https://viz.greynoise.io/ip/{ip}"
    if status == 404:
        sig.threat, sig.confidence = 0.0, 0.2
        sig.summary = "Not observed scanning the internet"
        return
    _expect_ok(status, data, "GreyNoise")
    cls = data.get("classification", "unknown")
    sig.last_seen = data.get("last_seen")
    # Benign labels say who owns or operates the IP, not what it is doing now.
    # Attackers rent cloud space and pose as "research scanners", so these get
    # moderate confidence and are flagged for the veneer check in scoring.
    if data.get("riot"):
        sig.threat, sig.confidence = 0.0, 0.6
        sig.summary = f"Known benign business service ({data.get('name') or 'RIOT'})"
        sig.facts["benign_label"] = f"GreyNoise RIOT: {data.get('name') or 'business service'}"
    elif cls == "malicious":
        sig.threat, sig.confidence = 0.9, 0.8
        sig.summary = "Actively scanning/attacking GreyNoise sensors (malicious)"
    elif cls == "benign":
        sig.threat, sig.confidence = 0.05, 0.6
        sig.summary = f"Benign scanner ({data.get('name') or 'known actor'})"
        sig.facts["benign_label"] = f"GreyNoise benign: {data.get('name') or 'known actor'}"
        sig.facts["label_kind"] = "scanner"     # explains scanning reports, nothing more
    else:
        sig.threat, sig.confidence = (0.35, 0.4) if data.get("noise") else (0.1, 0.3)
        sig.summary = "Internet noise, intent unknown" if data.get("noise") else "Seen, intent unknown"
    if data.get("name"):
        sig.evidence.append(f"Actor: {data['name']}")


def _feodo_index() -> dict:
    def load():
        status, rows = fetch_json("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=20)
        _expect_ok(status, rows, "Feodo Tracker")
        return {r["ip_address"]: r for r in rows if r.get("ip_address")}
    return cached("feodo_ipblocklist", 3600, load)


def check_feodo(ip: str, sig: Signal) -> None:
    hit = _feodo_index().get(ip)
    sig.link = f"https://feodotracker.abuse.ch/browse/host/{ip}/"
    if not hit:
        sig.threat, sig.confidence = 0.0, 0.2
        sig.summary = "Not a known botnet C2 server"
        sig.link = None
        return
    online = hit.get("status") == "online"
    sig.threat, sig.confidence = (0.95, 0.9) if online else (0.6, 0.7)
    # "online" is Feodo's live status; its last_online date can lag behind it.
    sig.facts["current"] = online
    sig.last_seen = hit.get("last_online")
    sig.summary = f"{hit.get('malware')} botnet C2 ({hit.get('status')})"
    sig.evidence = [f"First seen {hit.get('first_seen')}, port {hit.get('port')}, AS{hit.get('as_number')} {hit.get('as_name')}"]


def check_abuseipdb(ip: str, sig: Signal) -> None:
    # verbose adds the latest reports (up to 100) with their attack categories
    q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
    status, body = fetch_json(f"https://api.abuseipdb.com/api/v2/check?{q}",
                              headers={"Key": config.key("ABUSEIPDB_API_KEY") or ""})
    _expect_ok(status, body, "AbuseIPDB")
    d = body.get("data") or {}
    score = d.get("abuseConfidenceScore") or 0
    reporters = d.get("numDistinctUsers") or 0
    sig.threat = score / 100
    sig.confidence = round(min(1.0, 0.4 + reporters / 20), 3)
    sig.last_seen = iso_date(parse_dt(d.get("lastReportedAt")))
    sig.link = f"https://www.abuseipdb.com/check/{ip}"
    sig.summary = f"Abuse confidence {score}% from {d.get('totalReports', 0)} reports by {reporters} users (90d)"
    if d.get("usageType"):
        sig.evidence.append(f"{d.get('usageType')} - {d.get('isp')}")
        sig.facts["usage_type"] = d["usageType"]
    share = abuse_scan_share(d.get("reports") or [])
    sig.facts["scan_share"] = share
    if share is not None:
        sig.evidence.append(f"{share:.0%} of recent reports are port scans only")
    if d.get("isWhitelisted"):
        sig.threat = min(score / 100, 0.1)
        sig.facts["benign_label"] = "AbuseIPDB whitelisted"


def check_threatfox(ip: str, sig: Signal) -> None:
    status, body = fetch_json("https://threatfox-api.abuse.ch/api/v1/",
                              headers={"Auth-Key": config.key("THREATFOX_API_KEY") or ""},
                              body={"query": "search_ioc", "search_term": ip})
    _expect_ok(status, body, "ThreatFox")
    if body.get("query_status") != "ok":
        sig.threat, sig.confidence = 0.0, 0.25
        sig.summary = "No matching IOCs"
        return
    iocs = body.get("data") or []
    newest = max((parse_dt(i.get("last_seen") or i.get("first_seen")) for i in iocs),
                 default=None, key=lambda d: d or datetime.min.replace(tzinfo=timezone.utc))
    best = max((i.get("confidence_level") or 50) for i in iocs)
    age = age_days(newest)
    recency = 0.5 ** ((age or 0) / 60)
    sig.threat = round(min(1.0, best / 100) * (0.4 + 0.6 * recency), 3)
    sig.confidence = 0.8
    sig.last_seen = iso_date(newest)
    sig.summary = f"{len(iocs)} IOC(s): " + ", ".join(sorted({i.get('malware_printable', '?') for i in iocs}))
    sig.evidence = [f"{i.get('ioc')} - {i.get('threat_type_desc') or i.get('threat_type')}" for i in iocs[:5]]


# --- slow tier ---------------------------------------------------------------

def _drop_networks() -> list[list[str]]:
    def load():
        out = []
        for url in ("https://www.spamhaus.org/drop/drop_v4.json",
                    "https://www.spamhaus.org/drop/drop_v6.json"):
            status, raw = fetch(url, timeout=20)
            if status >= 400:
                raise BeaconError(f"Spamhaus DROP returned HTTP {status}")
            for line in raw.decode().splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("cidr"):
                    out.append([row["cidr"], row.get("sblid", "")])
        return out
    return cached("spamhaus_drop", 12 * 3600, load)


def check_spamhaus(ip: str, sig: Signal) -> None:
    addr = ipaddress.ip_address(ip)
    for cidr, sbl in _drop_networks():
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version == addr.version and addr in net:
            sig.threat, sig.confidence = 1.0, 0.95
            sig.summary = f"Inside hijacked/criminal netblock {cidr}"
            sig.evidence = [f"Spamhaus {sbl}"]
            sig.link = f"https://check.spamhaus.org/results/?query={ip}"
            return
    sig.threat, sig.confidence = 0.0, 0.5
    sig.summary = "Not in a Spamhaus DROP netblock"


def _kev_set() -> list[str]:
    def load():
        status, data = fetch_json(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=30)
        _expect_ok(status, data, "CISA KEV")
        return [v["cveID"] for v in data.get("vulnerabilities", [])]
    return cached("cisa_kev", 12 * 3600, load)


def _epss(cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    status, data = fetch_json("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[:50]))
    if status >= 400 or not data:
        return {}
    return {row["cve"]: float(row["epss"]) for row in data.get("data", [])}


HOSTILE_TAGS = {"c2", "malware", "compromised", "botnet"}


def check_internetdb(ip: str, sig: Signal) -> None:
    status, data = fetch_json(f"https://internetdb.shodan.io/{ip}")
    sig.link = f"https://www.shodan.io/host/{ip}"
    if status == 404:
        sig.threat, sig.confidence = 0.0, 0.3
        sig.summary = "No open services in Shodan's scan data"
        return
    _expect_ok(status, data, "Shodan InternetDB")
    ports, vulns, tags = data.get("ports", []), data.get("vulns", []), data.get("tags", [])
    kev = set(_kev_set()) & set(vulns) if vulns else set()
    epss = _epss(vulns)
    top_epss = max(epss.values(), default=0.0)

    hostile = HOSTILE_TAGS & set(tags)
    if hostile:
        threat = 0.85
    else:
        # Exposure is not maliciousness, so it is capped: a vulnerable host is a
        # likely future threat, not a confirmed one.
        threat = 0.05 if ports else 0.0
        if vulns:
            threat = max(threat, 0.15 + 0.35 * top_epss)
        if kev:
            threat = max(threat, 0.5)
        threat = min(threat, 0.6)
    sig.threat, sig.confidence = round(threat, 3), 0.6
    sig.summary = (f"{len(ports)} open ports, {len(vulns)} CVEs"
                   + (f", {len(kev)} in CISA KEV" if kev else ""))
    if tags:
        sig.evidence.append("Tags: " + ", ".join(tags))
    if ports:
        sig.evidence.append("Ports: " + ", ".join(map(str, ports[:20])))
    ranked = sorted(vulns, key=lambda c: (c in kev, epss.get(c, 0)), reverse=True)
    for cve in ranked[:6]:
        flags = []
        if cve in kev:
            flags.append("KEV")
        if cve in epss:
            flags.append(f"EPSS {epss[cve]:.2f}")
        sig.evidence.append(f"{cve}" + (f" ({', '.join(flags)})" if flags else ""))
    sig.facts = {"hostnames": data.get("hostnames", []), "cves": vulns, "kev": sorted(kev)}


ECHO_ENGINES = re.compile(r"alienvault|abuse\.?ch|feodo|threatfox|urlhaus|spamhaus|greynoise|abuseipdb",
                          re.IGNORECASE)


def check_virustotal(ip: str, sig: Signal) -> None:
    status, body = fetch_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                              headers={"x-apikey": config.key("VIRUSTOTAL_API_KEY") or ""})
    _expect_ok(status, body, "VirusTotal")
    attrs = (body.get("data") or {}).get("attributes") or {}
    results = attrs.get("last_analysis_results") or {}
    # VirusTotal's vendor list includes feeds this app already queries directly
    # (AlienVault, abuse.ch, Spamhaus, ...). Counting them again would let one
    # observation vote twice, so only independent vendors are scored.
    independent = {name: r for name, r in results.items() if not ECHO_ENGINES.search(name)}
    echoed = sorted(name for name, r in results.items()
                    if name not in independent and r.get("category") in ("malicious", "suspicious"))
    if results:
        cats = [r.get("category") for r in independent.values()]
        mal, sus, engines = cats.count("malicious"), cats.count("suspicious"), len(independent)
    else:
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus, engines = stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values())
    sig.threat = round(min(1.0, (mal + 0.5 * sus) / 5), 3)
    sig.confidence = 0.8
    sig.last_seen = iso_date(parse_dt(attrs.get("last_analysis_date")))
    sig.link = f"https://www.virustotal.com/gui/ip-address/{ip}"
    sig.summary = f"{mal} malicious / {sus} suspicious of {engines} independent vendors"
    if echoed:
        sig.evidence.append("Not double-counted (queried directly): " + ", ".join(echoed))
    if attrs.get("as_owner"):
        sig.evidence.append(f"AS owner: {attrs['as_owner']}")


# --- network -----------------------------------------------------------------

NEIGHBOR_LISTS = [
    ("blocklist.de", "https://lists.blocklist.de/lists/all.txt"),
    ("CINS Army", "https://cinsscore.com/list/ci-badguys.txt"),
    ("ET compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
]
NEIGHBOR_NOISE = 2
HOSTING_NAMES = re.compile(
    r"amazon|aws|google|microsoft|azure|digitalocean|linode|akamai|ovh|hetzner|vultr|choopa|"
    r"oracle|alibaba|tencent|cloud|hosting|host|server|datacenter|data center|colo|vps|"
    r"contabo|leaseweb|scaleway", re.IGNORECASE)


def _ip_list(name: str, url: str) -> list[str]:
    def load():
        status, raw = fetch(url, timeout=30)
        if status >= 400:
            raise BeaconError(f"{name} returned HTTP {status}")
        return [line.strip() for line in raw.decode(errors="replace").splitlines()
                if line.strip() and not line.startswith("#")]
    return cached("list_" + re.sub(r"\W+", "_", name.lower()), 3600, load)


def neighborhood_of(ip: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(f"{ip}/{24 if _ip_version(ip) == 4 else 64}", strict=False)


def check_neighborhood(ip: str, sig: Signal) -> None:
    """Count blocklisted neighbors in the IP's /24 (IPv6: /64). Attackers rotate
    through adjacent addresses, so a clean IP in a dirty block is suspicious."""
    net = neighborhood_of(ip)
    lists = [(name, _ip_list(name, url)) for name, url in NEIGHBOR_LISTS]
    lists.append(("Feodo C2", list(_feodo_index())))
    listed: dict[str, set[str]] = {}
    self_listed = []
    for name, ips in lists:
        for entry in ips:
            try:
                addr = ipaddress.ip_address(entry)
            except ValueError:
                continue
            if addr.version != net.version or addr not in net:
                continue
            if str(addr) == ip:
                self_listed.append(name)
            else:
                listed.setdefault(str(addr), set()).add(name)
    drop_overlap = [cidr for cidr, _ in _drop_networks()
                    if (n := ipaddress.ip_network(cidr, strict=False)).version == net.version
                    and n.overlaps(net) and ipaddress.ip_address(ip) not in n]

    count = len(listed)
    # One or two listed neighbors is background noise (97% of dirty /24s have
    # fewer than 5); the curve starts after that: 5 -> 0.31, 10 -> 0.63, 20 -> 0.9.
    threat = 1 - math.exp(-max(0, count - NEIGHBOR_NOISE) / 8)
    if drop_overlap:
        threat = max(threat, 0.7)
    sig.threat, sig.confidence = round(threat, 3), 0.6
    sig.summary = f"{count} blocklisted neighbor{'s' if count != 1 else ''} in {net}"
    per_list: dict[str, int] = {}
    for names in listed.values():
        for name in names:
            per_list[name] = per_list.get(name, 0) + 1
    if per_list:
        sig.evidence.append("By list: " + ", ".join(f"{n} {k}" for k, n in sorted(per_list.items(), key=lambda x: -x[1])))
        sig.evidence.append("Examples: " + ", ".join(sorted(listed, key=ipaddress.ip_address)[:6]))
    if drop_overlap:
        sig.evidence.append("Spamhaus DROP covers part of this block: " + ", ".join(drop_overlap))
    if self_listed:
        sig.evidence.append("This IP itself is on: " + ", ".join(self_listed))
    sig.facts = {"prefix": str(net), "listed_neighbors": count, "drop_overlap": drop_overlap,
                 "self_listed": self_listed}


def _asn_drop() -> dict:
    def load():
        status, raw = fetch("https://www.spamhaus.org/drop/asndrop.json", timeout=20)
        if status >= 400:
            raise BeaconError(f"Spamhaus ASN-DROP returned HTTP {status}")
        out = {}
        for line in raw.decode().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("asn"):
                out[str(row["asn"])] = row.get("asname", "")
        return out
    return cached("spamhaus_asndrop", 12 * 3600, load)


def check_network(ip: str, sig: Signal) -> None:
    """Who announces this IP, and is that network itself run by criminals?"""
    status, info = fetch_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",
                              timeout=max(config.HTTP_TIMEOUT, 20))
    _expect_ok(status, info, "RIPEstat")
    data = info.get("data") or {}
    asns, prefix = data.get("asns") or [], data.get("prefix")
    if not asns:
        sig.threat, sig.confidence = 0.0, 0.3
        sig.summary = "IP is not announced in global routing"
        return
    asn = str(asns[0])
    status, ov = fetch_json(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}",
                            timeout=max(config.HTTP_TIMEOUT, 20))
    holder = ((ov or {}).get("data") or {}).get("holder") or "" if status < 400 else ""
    hosting = bool(HOSTING_NAMES.search(holder))
    drop = _asn_drop()
    c2s = sum(1 for r in _feodo_index().values() if str(r.get("as_number")) == asn)

    sig.link = f"https://stat.ripe.net/AS{asn}"
    sig.summary = f"AS{asn} {holder}".strip() + (f", prefix {prefix}" if prefix else "")
    if asn in drop:
        sig.threat, sig.confidence = 1.0, 0.9
        sig.evidence.append(f"Spamhaus ASN-DROP: the whole network ({drop[asn] or 'AS' + asn}) is criminal-run")
    else:
        sig.threat, sig.confidence = 0.0, 0.5
    if hosting and asn not in drop:
        sig.evidence.append("Looks like a cloud/hosting network (by name): neighbors are unrelated tenants and IPs change hands often")
    if c2s:
        sig.evidence.append(f"{c2s} Feodo botnet C2 server{'s' if c2s != 1 else ''} currently in this ASN")
    # A criminal-run network is bulletproof hosting, not a shared cloud: its
    # neighbors are not innocent bystanders, so the hosting discount is off.
    sig.facts = {"asn": asn, "holder": holder, "prefix": prefix, "hosting": hosting and asn not in drop,
                 "asn_drop": asn in drop, "feodo_c2_in_asn": c2s}


# --- context -----------------------------------------------------------------

def check_rdap(ip: str, sig: Signal) -> None:
    status, data = fetch_json(f"https://rdap.org/ip/{ip}")
    _expect_ok(status, data, "RDAP")
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    names = []
    for ent in data.get("entities", []):
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                names.append(item[3])
    sig.summary = f"{data.get('name', '?')} ({data.get('country') or 'country n/a'})"
    sig.evidence = [f"Range {data.get('startAddress')} - {data.get('endAddress')}"]
    if names:
        sig.evidence.append("Entities: " + ", ".join(dict.fromkeys(names)))
    if events.get("registration"):
        sig.evidence.append(f"Registered {events['registration'][:10]}")
    if events.get("last changed"):
        sig.evidence.append(f"Last changed {events['last changed'][:10]}")
    sig.facts = {"network": data.get("name"), "country": data.get("country")}


def check_tor(ip: str, sig: Signal) -> None:
    def load():
        status, raw = fetch("https://check.torproject.org/torbulkexitlist", timeout=20)
        if status >= 400:
            raise BeaconError(f"Tor exit list returned HTTP {status}")
        return [line.strip() for line in raw.decode().splitlines() if line.strip()]
    exits = set(cached("tor_exits", 3600, load))
    is_exit = ip in exits
    sig.summary = "Tor exit node - traffic may come from many users" if is_exit else "Not a Tor exit node"
    sig.facts = {"tor_exit": is_exit}


# Operators whose reverse DNS names identify them. Anyone can set an IP's PTR
# record to any name, but only the operator can make that name resolve back, so
# a claim counts only when it is forward-confirmed (PTR -> name -> same IP).
IDENTITY_DOMAINS = {
    "shodan.io": ("Shodan", "scanner"),
    "censys-scanner.com": ("Censys", "scanner"),
    "shadowserver.org": ("Shadowserver", "scanner"),
    "binaryedge.ninja": ("BinaryEdge", "scanner"),
    "onyphe.net": ("ONYPHE", "scanner"),
    "googlebot.com": ("Googlebot", "crawler"),
    "search.msn.com": ("Bingbot", "crawler"),
    "applebot.apple.com": ("Applebot", "crawler"),
}
DNS_TIMEOUT = 5.0


def _resolve(fn, *args):
    """Run a blocking resolver call with a deadline (the stdlib resolver has none)."""
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return pool.submit(fn, *args).result(timeout=DNS_TIMEOUT)
    finally:
        pool.shutdown(wait=False)


def claimed_identity(name: str) -> tuple[str, str] | None:
    name = name.lower().rstrip(".")
    return next((v for d, v in IDENTITY_DOMAINS.items() if name == d or name.endswith("." + d)), None)


def check_rdns(ip: str, sig: Signal) -> None:
    try:
        name = _resolve(socket.gethostbyaddr, ip)[0]
    except (socket.herror, socket.gaierror):
        sig.summary = "No reverse DNS"
        return
    except FuturesTimeout:
        raise BeaconError("reverse DNS lookup timed out") from None
    try:
        forward = {ipaddress.ip_address(a[4][0].split("%")[0]) for a in _resolve(socket.getaddrinfo, name, None)}
    except (socket.herror, socket.gaierror, FuturesTimeout):
        forward = set()
    confirmed = ipaddress.ip_address(ip) in forward
    sig.facts = {"ptr": name, "confirmed": confirmed}
    claim = claimed_identity(name)
    if not claim:
        sig.summary = f"{name} ({'forward-confirmed' if confirmed else 'does not resolve back'})"
        return
    operator, kind = claim
    sig.facts["claim"] = operator
    if confirmed:
        sig.summary = f"{operator} {kind} ({name}, forward-confirmed)"
        sig.facts["benign_label"] = f"rDNS: {operator} {kind}, forward-confirmed"
        sig.facts["label_kind"] = kind        # a confirmed scanner explains scanning, as GreyNoise's label does
    else:
        sig.summary = f"Claims to be {operator} ({name}) but the name does not resolve back to this IP"
        sig.facts["spoofed_identity"] = (f"reverse DNS claims {operator} ({name}), but {name} "
                                         "does not resolve back to this IP")


# Operators that publish the address ranges their scanners and crawlers use.
# Membership is a label the operator vouches for; like every label it can
# explain matching evidence but never discount a contradiction. Palo Alto
# Xpanse and Shodan publish no public list (Shodan is covered by reverse DNS).
PUBLISHED_RANGES = [
    ("Googlebot", "crawler", "json", "https://developers.google.com/static/search/apis/ipranges/googlebot.json"),
    ("Bingbot", "crawler", "json", "https://www.bing.com/toolbox/bingbot.json"),
    ("Applebot", "crawler", "json", "https://search.developer.apple.com/applebot.json"),
    ("GPTBot", "crawler", "json", "https://openai.com/gptbot.json"),
    # Censys lists its ranges on a documentation page, not in a feed.
    ("Censys", "scanner", "html", "https://docs.censys.com/docs/opt-out-of-data-collection"),
]
CIDR_IN_TEXT = re.compile(r"(?<![\w.:/])(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})/\d{1,3}(?![\w/])")
MIN_HTML_RANGES = 5   # a page that yields fewer has probably changed shape; don't trust a partial parse


def parse_ranges(fmt: str, raw: bytes) -> list[str]:
    if fmt == "json":
        prefixes = json.loads(raw).get("prefixes") or []
        found = [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in prefixes]
    else:
        found = CIDR_IN_TEXT.findall(raw.decode("utf-8", errors="replace"))
    nets = []
    for c in found:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except (TypeError, ValueError):
            continue
        if net.is_global and net.prefixlen >= (16 if net.version == 4 else 32):  # nobody owns a /8
            nets.append(str(net))
    nets = sorted(set(nets))
    if fmt == "html" and len(nets) < MIN_HTML_RANGES:
        raise BeaconError(f"found only {len(nets)} ranges; the page format may have changed")
    return nets


def _published(operator: str, fmt: str, url: str) -> list[str]:
    def load():
        status, raw = fetch(url, timeout=20)
        if status >= 400:
            raise BeaconError(f"{operator} list returned HTTP {status}")
        return parse_ranges(fmt, raw)
    return cached(f"published_{operator.lower()}", 86400, load)


def check_published(ip: str, sig: Signal) -> None:
    addr = ipaddress.ip_address(ip)
    failed = []
    for operator, kind, fmt, url in PUBLISHED_RANGES:
        try:
            ranges = _published(operator, fmt, url)
        except Exception:
            failed.append(operator)
            continue
        hit = next((r for r in ranges if addr in ipaddress.ip_network(r)), None)
        if hit:
            sig.summary = f"In {operator}'s published {kind} range {hit}"
            sig.facts = {"operator": operator, "range": hit, "label_kind": kind,
                         "benign_label": f"Published by {operator}: {kind} range {hit}"}
            sig.link = url
            return
    if len(failed) == len(PUBLISHED_RANGES):
        raise BeaconError("no operator range list could be loaded")
    sig.summary = "Not in any operator-published scanner or crawler range"
    if failed:
        sig.summary += f" (unavailable: {', '.join(failed)})"


BEACONS: list[Beacon] = [
    Beacon("otx", "AlienVault OTX pulses", "fast", 1.0, check_otx, "OTX_API_KEY", False, "minutes-hours"),
    Beacon("greynoise", "GreyNoise sensors", "fast", 0.8, check_greynoise, "GREYNOISE_API_KEY", False, "hours"),
    Beacon("feodo", "abuse.ch Feodo Tracker", "fast", 1.0, check_feodo, None, False, "every 5 minutes", "abuse.ch"),
    Beacon("abuseipdb", "AbuseIPDB reports", "fast", 1.0, check_abuseipdb, "ABUSEIPDB_API_KEY", True, "minutes"),
    Beacon("threatfox", "abuse.ch ThreatFox IOCs", "fast", 0.9, check_threatfox, "THREATFOX_API_KEY", True, "minutes", "abuse.ch"),
    Beacon("spamhaus", "Spamhaus DROP", "slow", 1.0, check_spamhaus, None, False, "curated, days-weeks"),
    Beacon("virustotal", "VirusTotal vendor consensus", "slow", 1.0, check_virustotal, "VIRUSTOTAL_API_KEY", True, "vendor lists, days"),
    Beacon("internetdb", "Shodan InternetDB + CVE/KEV/EPSS", "slow", 0.5, check_internetdb, None, False, "weekly crawl"),
    Beacon("neighborhood", "Neighborhood (/24) blocklists", "network", 0.0, check_neighborhood, None, False, "hourly lists"),
    Beacon("network", "Network (ASN) reputation", "network", 0.0, check_network, None, False, "routing + ASN-DROP"),
    Beacon("rdap", "RDAP registration", "context", 0.0, check_rdap, None, False, "registry"),
    Beacon("tor", "Tor exit list", "context", 0.0, check_tor, None, False, "hourly"),
    Beacon("rdns", "Reverse DNS identity", "context", 0.0, check_rdns, None, False, "live DNS", "dns"),
    Beacon("published", "Operator-published ranges", "context", 0.0, check_published, None, False,
           "operator lists, daily"),
]


# What a report loses when a beacon doesn't answer.
BEACON_COST = {
    "otx": "No fresh pulse evidence, so the fast tier is thinner.",
    "greynoise": "No sensor reading and no GreyNoise label. Scanner identity falls back to reverse DNS and published ranges.",
    "feodo": "No live botnet C2 check. ThreatFox still covers abuse.ch data if it answered.",
    "abuseipdb": "No abuse reports, no scan share for the scanner rule, and no usage type for the CDN rule.",
    "threatfox": "No ThreatFox IOC check. Feodo Tracker still covers abuse.ch C2s.",
    "spamhaus": "No check against hijacked and criminal netblocks.",
    "virustotal": "No vendor consensus, so the slow tier is thinner.",
    "internetdb": "No open-port or CVE evidence, so the slow tier is thinner.",
    "neighborhood": "No /24 neighbor risk, so a clean IP in a dirty block won't show.",
    "network": "No ASN, hosting or ASN-DROP facts.",
    "rdap": "No registration owner. Not scored.",
    "tor": "No Tor exit check. Not scored.",
    "rdns": "Reverse DNS claims can't be tested, so a forged identity won't be caught.",
    "published": "No operator range check, so a listed scanner or crawler loses that label.",
}


def origin_of(source_id: str) -> str:
    return next((b.origin or b.id for b in BEACONS if b.id == source_id), source_id)


def run_beacon(beacon: Beacon, ip: str) -> Signal:
    sig = Signal(source=beacon.id, name=beacon.name, tier=beacon.tier)
    if beacon.key_required and not config.key(beacon.key_env or ""):
        sig.status, sig.failure = "skipped", "no_key"
        sig.summary = f"Set {beacon.key_env} to enable"
        return sig
    start = time.monotonic()
    try:
        beacon.check(ip, sig)
    except Exception as exc:  # one failing beacon must never sink the scan
        sig.status, sig.threat, sig.confidence = "error", None, 0.0
        sig.failure = getattr(exc, "failure", "error")
        sig.summary = str(exc) if isinstance(exc, BeaconError) else f"{type(exc).__name__}: {exc}"
    sig.last_seen = iso_date(parse_dt(sig.last_seen))  # feeds supply this text; pass on only a real date
    sig.latency_ms = int((time.monotonic() - start) * 1000)
    return sig
