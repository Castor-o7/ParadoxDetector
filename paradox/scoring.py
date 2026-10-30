"""Turn beacon signals into tier scores, a consensus threat and a paradox score.

Paradox score (0-100), in plain terms:

1. Each tier (fast, slow) gets a threat score: half the confidence-weighted
   mean of its beacons, half its strongest confident detection. One confident
   hit matters; silence from a narrow list (e.g. a botnet-only tracker) only
   partly dilutes it.
2. gap = fast - slow.
   * gap > 0  "emerging threat": fast beacons see something slow ones haven't
     caught up with. This is the paradox we care about most and counts fully.
   * gap < 0  "stale reputation": slow lists still flag the IP but there is no
     fresh activity (remediated, reassigned). Counts at half strength.
3. dispersion: weighted spread of every beacon's reading, regardless of tier.
4. Reputation veneer: a beacon vouches for the IP (GreyNoise RIOT/benign, OTX
   or AbuseIPDB whitelist) while a *different* beacon reports fresh, confident
   threat activity. Legitimacy is exactly what attackers borrow, so a
   contradicted benign label loses half its weight and adds to the paradox.
   Exception: a scanner label (GreyNoise "benign": Shodan, Censys) *explains*
   reports that are mostly port scans. That evidence is discounted by its scan
   share and is not a contradiction. Brute force, malware or C2 evidence still is.
   Shared infrastructure (AbuseIPDB usage type CDN): OTX
   mentions of these IPs usually come from reports listing every address the
   malware contacted (GitHub, Microsoft, CDNs), so OTX counts at half weight.
   Direct attack evidence (abuse reports, sensor hits) is unaffected.
   Forged identity: an IP whose reverse DNS names a known operator (Shodan,
   Googlebot...) that does not resolve back is wearing a costume anyone can
   sew. It counts as a veneer, and sets a "Suspicious" threat floor.
5. Neighborhood cover: the IP's own evidence looks clean but its /24 or its
   network (ASN) is dirty. Attackers rotate through adjacent addresses and
   rent from bulletproof hosts, so the gap between surroundings and the IP
   itself adds to the paradox. On cloud/hosting networks the neighbors are
   unrelated tenants, so neighborhood risk counts at half strength there.
6. raw = 0.8 * directional gap + 0.2 * dispersion + 0.25 * veneer strength
         + 0.2 * neighborhood cover
7. Scaled by coverage: a paradox needs both tiers to have actually answered.

Independence: beacons that share an upstream origin (Feodo Tracker and
ThreatFox are both abuse.ch) are collapsed into one vote before any of the
above, so two copies of the same observation never look like corroboration.
"""

from __future__ import annotations

import math
from dataclasses import replace
from datetime import datetime, timezone

from .sources import BEACON_COST, BEACONS, Signal, age_days, origin_of, parse_dt

WEIGHTS = {b.id: b.weight for b in BEACONS}
PEAK_MIN_CONFIDENCE = 0.5
COVERAGE_TARGET = 0.8      # summed weight*confidence that counts as full coverage
STALE_FACTOR = 0.5
VENEER_MIN_THREAT = 0.4
VENEER_MIN_CONFIDENCE = 0.5
VENEER_FRESH_DAYS = 30
VENEER_WEIGHT = 0.25
NETWORK_WEIGHT = 0.2
SCAN_EXPLAINED_SHARE = 0.6     # evidence this scan-dominated is what a scanner label predicts
SHARED_INFRA_OTX_FACTOR = 0.5  # OTX on CDN addresses: mostly "malware contacted this"
SPOOF_STRENGTH = 0.6           # veneer strength of a forged reverse-DNS identity
SPOOF_THREAT_FLOOR = 0.3       # forging an identity is suspicious on its own, but not proof
HOSTING_DISCOUNT = 0.5
NETWORK_THREAT_FACTOR = 0.5   # guilt by association lifts threat, but only so far


def _scored(signals: list[Signal], tier: str | None = None) -> list[tuple[Signal, float]]:
    out = []
    for s in signals:
        if s.status != "ok" or s.threat is None or s.tier not in ("fast", "slow"):
            continue
        if tier and s.tier != tier:
            continue
        w = WEIGHTS.get(s.source, 1.0) * s.confidence
        if w > 0:
            out.append((s, w))
    return out


def _groups(signals: list[Signal], tier: str | None = None) -> list[tuple[float, float, list[Signal]]]:
    """Collapse beacons sharing an upstream origin into one vote: (threat,
    weight, members). The group reading is the members' weighted mean and its
    weight is its strongest member's, so agreement between two copies of the
    same data adds no weight."""
    by_origin: dict[tuple[str, str], list[tuple[Signal, float]]] = {}
    for s, w in _scored(signals, tier):
        by_origin.setdefault((s.tier, origin_of(s.source)), []).append((s, w))
    out = []
    for rows in by_origin.values():
        total = sum(w for _, w in rows)
        out.append((sum(s.threat * w for s, w in rows) / total, max(w for _, w in rows),
                    [s for s, _ in rows]))
    return out


def tier_score(signals: list[Signal], tier: str) -> dict:
    groups = _groups(signals, tier)
    weight = sum(w for _, w, _ in groups)
    if not groups:
        return {"score": None, "weight": 0.0, "beacons": 0, "independent": 0}
    mean = sum(t * w for t, w, _ in groups) / weight
    peak = max((s.threat for _, _, members in groups for s in members
                if s.confidence >= PEAK_MIN_CONFIDENCE), default=mean)
    return {"score": round(0.5 * mean + 0.5 * max(peak, mean), 4),
            "mean": round(mean, 4), "peak": round(peak, 4), "weight": round(weight, 4),
            "beacons": sum(len(m) for _, _, m in groups), "independent": len(groups)}


def dispersion(signals: list[Signal]) -> float:
    """Weighted standard deviation of all independent readings, normalized so
    1.0 is the maximum possible spread (half the votes at 0, half at 1)."""
    groups = _groups(signals)
    total = sum(w for _, w, _ in groups)
    if len(groups) < 2 or total == 0:
        return 0.0
    mean = sum(t * w for t, w, _ in groups) / total
    var = sum(w * (t - mean) ** 2 for t, w, _ in groups) / total
    return min(1.0, math.sqrt(var) / 0.5)


def label(paradox: float) -> str:
    if paradox < 15:
        return "Coherent"
    if paradox < 35:
        return "Mild tension"
    if paradox < 60:
        return "Paradox"
    return "Severe paradox"


def threat_label(threat: float) -> str:
    if threat < 0.15:
        return "Likely benign"
    if threat < 0.4:
        return "Suspicious"
    if threat < 0.7:
        return "Likely malicious"
    return "Malicious"


def explain_scanning(signals: list[Signal]) -> tuple[list[Signal], dict]:
    """A known scanner being reported for scanning is expected, not a paradox.
    Discount each beacon's threat by the share of its evidence that is plain
    scanning, when a scanner label from a different origin explains it."""
    labels = [s for s in signals if s.status == "ok" and s.facts.get("label_kind") == "scanner"]
    info = {"label": labels[0].facts["benign_label"] if labels else None, "explained": []}
    if not labels:
        return signals, info
    out = []
    for s in signals:
        share = s.facts.get("scan_share")
        if (s.status == "ok" and s.tier in ("fast", "slow") and s.threat and share is not None
                and share >= SCAN_EXPLAINED_SHARE
                and any(origin_of(lab.source) != origin_of(s.source) for lab in labels)):
            info["explained"].append(f"{s.name} ({share:.0%} scanning)")
            s = replace(s, threat=round(s.threat * (1 - share), 3),
                        facts={**s.facts, "explained_by_label": True})
        out.append(s)
    return out, info


def shared_infrastructure(signals: list[Signal]) -> tuple[list[Signal], str | None]:
    """CDN IPs are shared by many sites and contacted by everything, malware
    included, so OTX's contextual mentions say little about them."""
    # Deliberately not GreyNoise RIOT or any other benign *label*: a label that
    # discounted the evidence against it would make the veneer self-protecting.
    # Usage type is a fact about the network, not a vouch for the IP.
    why = next((f"{s.name}: Content Delivery Network" for s in signals
                if s.status == "ok" and s.facts.get("usage_type") == "Content Delivery Network"), None)
    if not why:
        return signals, None
    return [replace(s, threat=round(s.threat * SHARED_INFRA_OTX_FACTOR, 3))
            if s.source == "otx" and s.status == "ok" and s.threat else s for s in signals], why


def detect_veneer(signals: list[Signal], now: datetime) -> dict:
    """Find benign labels that another beacon contradicts with fresh evidence."""
    labels = [s for s in signals if s.status == "ok" and s.facts.get("benign_label")]
    out = {"active": False, "strength": 0.0,
           "labels": [s.facts["benign_label"] for s in labels], "contradicted_by": []}
    if not labels:
        return out
    hits = []
    for s in signals:
        if (s.status != "ok" or s.threat is None or s.tier not in ("fast", "slow")
                or s.facts.get("explained_by_label") or s.threat < VENEER_MIN_THREAT or s.confidence < VENEER_MIN_CONFIDENCE):
            continue
        if not any(origin_of(lab.source) != origin_of(s.source) for lab in labels):
            continue  # contradicting a label from the same origin is not independent
        age = age_days(parse_dt(s.last_seen), now)
        if not s.facts.get("current") and age is not None and age > VENEER_FRESH_DAYS:
            continue  # undated hits and live list status count as fresh
        hits.append(s)
    if hits:
        out.update(active=True, strength=round(max(s.threat for s in hits), 3),
                   contradicted_by=[f"{s.name} ({s.summary})" for s in hits])
    return out


def network_risk(signals: list[Signal]) -> dict:
    """Risk from the IP's surroundings: its /24 neighbors and its ASN."""
    by_id = {s.source: s for s in signals if s.status == "ok" and s.threat is not None}
    nb, asn = by_id.get("neighborhood"), by_id.get("network")
    hosting = bool(asn and asn.facts.get("hosting"))
    nb_risk = (nb.threat if nb else 0.0) * (HOSTING_DISCOUNT if hosting else 1.0)
    asn_risk = asn.threat if asn else 0.0
    return {"risk": round(max(nb_risk, asn_risk), 3), "neighborhood": round(nb_risk, 3),
            "asn": round(asn_risk, 3), "hosting": hosting,
            "asn_drop": bool(asn and asn.facts.get("asn_drop")),
            "listed_neighbors": nb.facts.get("listed_neighbors") if nb else None,
            "prefix": nb.facts.get("prefix") if nb else None,
            "holder": asn.facts.get("holder") if asn else None}


def _rows(*rows: tuple[str, float]) -> list[dict]:
    return [{"label": text, "points": round(points, 2)} for text, points in rows if abs(points) >= 0.005]


def adjustments(before: list[Signal], after: list[Signal], scanner: dict, shared: str | None) -> list[dict]:
    """What the rules changed about a scored beacon before it voted."""
    out = []
    for old, new in zip(before, after):
        if old.status != "ok" or old.threat is None or old.tier not in ("fast", "slow"):
            continue
        if new.threat != old.threat:
            why = []
            if new.facts.get("explained_by_label"):
                why.append(f"{scanner['label']} explains the {old.facts['scan_share']:.0%} that is scanning")
            if shared and new.source == "otx":
                why.append("CDN address, where OTX mentions are mostly malware contacting it")
            out.append({"beacon": old.name, "field": "threat", "from": old.threat, "to": new.threat,
                        "why": "; ".join(why)})
        if new.confidence != old.confidence:
            out.append({"beacon": old.name, "field": "confidence", "from": round(old.confidence, 3),
                        "to": round(new.confidence, 3), "why": "its benign label is contradicted, so it counts at half weight"})
    return out


def missing_beacons(signals: list[Signal]) -> list[dict]:
    """Beacons that gave no reading, failures before unconfigured ones, and what that costs."""
    gone = sorted((s for s in signals if s.status != "ok"), key=lambda s: s.status == "skipped")
    return [{"beacon": s.name, "tier": s.tier, "status": s.status, "failure": s.failure,
             "summary": s.summary, "cost": BEACON_COST.get(s.source, "")} for s in gone]


def compute(signals: list[Signal], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    original = signals
    signals, scanner = explain_scanning(signals)
    signals, shared = shared_infrastructure(signals)
    veneer = detect_veneer(signals, now)
    spoofed = [s.facts["spoofed_identity"] for s in signals
               if s.status == "ok" and s.facts.get("spoofed_identity")]
    if spoofed:
        veneer.update(active=True, strength=max(veneer["strength"], SPOOF_STRENGTH),
                      contradicted_by=veneer["contradicted_by"] + spoofed)
    veneer["spoofed"] = spoofed
    if veneer["active"]:
        signals = [replace(s, confidence=s.confidence * 0.5)
                   if s.facts.get("benign_label") and (s.threat or 0) < 0.2 else s
                   for s in signals]
    fast, slow = tier_score(signals, "fast"), tier_score(signals, "slow")
    disp = dispersion(signals)
    cov_fast = min(1.0, fast["weight"] / COVERAGE_TARGET)
    cov_slow = min(1.0, slow["weight"] / COVERAGE_TARGET)
    coverage = math.sqrt(cov_fast * cov_slow)

    f = fast["score"] if fast["score"] is not None else 0.0
    s = slow["score"] if slow["score"] is not None else 0.0
    gap = f - s
    directional = max(gap, 0.0) + STALE_FACTOR * max(-gap, 0.0)

    groups = _groups(signals)
    total = sum(w for _, w, _ in groups)
    consensus = sum(t * w for t, w, _ in groups) / total if total else 0.0
    rows = _scored(signals)
    # Blend in the fast tier's view so a fresh, confident detection is not
    # averaged away by many quiet slow sources.
    threat = max(consensus, 0.6 * f + 0.4 * s) if fast["score"] is not None else consensus
    blended = threat
    # A single high-confidence detection (live C2, DROP netblock) sets a floor.
    strong = [x.threat for x, _ in rows if x.confidence >= 0.8]
    threat = max(threat, 0.85 * max(strong, default=0.0))
    floored = threat

    network = network_risk(signals)
    network["cover"] = round(max(0.0, network["risk"] - threat), 3)
    terms = (0.8 * directional, 0.2 * disp, VENEER_WEIGHT * veneer["strength"], NETWORK_WEIGHT * network["cover"])
    raw = min(1.0, sum(terms))
    paradox = round(100 * raw * (0.4 + 0.6 * coverage), 1)
    threat = max(threat, NETWORK_THREAT_FACTOR * network["risk"])
    networked = threat
    if spoofed:
        threat = max(threat, SPOOF_THREAT_FLOOR)

    # The ledger explains the numbers above and feeds nothing back into them:
    # each list adds up to its score, whichever rule decided it.
    ledger = {
        "paradox": _rows(
            ("Fast beacons ahead of slow" if gap >= 0 else "Slow beacons ahead of fast (counts at half)", 100 * terms[0]),
            ("Beacons disagree with each other", 100 * terms[1]),
            ("Veneer: " + "; ".join((veneer["labels"] if len(veneer["contradicted_by"]) > len(spoofed) else [])
                                     + (["forged identity"] if spoofed else [])) + " contradicted", 100 * terms[2]),
            ("Clean IP in dirty surroundings", 100 * terms[3]),
            ("Capped at 100", 100 * (raw - sum(terms))),
            (f"Coverage {coverage:.0%}: not every tier answered", 100 * raw * 0.6 * (coverage - 1))),
        "threat": _rows(
            *((" + ".join(x.name for x in members) + " (independent vote)", 100 * t * w / total)
              for t, w, members in groups),
            ("Tier blend (60% fast, 40% slow) is above the average", 100 * (blended - consensus)),
            ("High-confidence detection sets a floor", 100 * (floored - blended)),
            ("Dirty surroundings set a floor", 100 * (networked - floored)),
            ("Forged identity sets a floor", 100 * (threat - networked))),
        "adjustments": adjustments(original, signals, scanner, shared),
    }

    if gap > 0.1:
        direction = "emerging"
        explanation = ("Fast-updating beacons report threat activity that the slower, "
                       "curated sources have not reflected yet.")
    elif gap < -0.1:
        direction = "stale"
        explanation = ("Slow-updating sources still flag this IP, but the fast beacons see no "
                       "fresh activity - it may have been cleaned up or reassigned.")
    else:
        direction = "aligned"
        explanation = "Fast and slow beacons broadly agree."
    if spoofed:
        explanation += " Its reverse DNS claims an identity that does not check out: a forged label."
    elif veneer["active"]:
        explanation += " A trusted reputation label may be providing cover."
    elif scanner["explained"]:
        explanation += (f" {scanner['label']} identifies a known scanner; reports that are mostly "
                        "scanning are expected for it and were discounted.")
    if network["asn_drop"]:
        explanation += " The network itself is on Spamhaus ASN-DROP (criminal-run hosting)."
        if direction == "stale":
            explanation = explanation.replace(" - it may have been cleaned up or reassigned.", ".")
            explanation += " On a network like this, a quiet spell is more likely dormancy than cleanup."
    elif network["cover"] >= 0.3:
        explanation += (" The IP itself looks cleaner than its surroundings: its neighbors are "
                        "heavily blocklisted, a pattern seen when attackers rotate addresses.")
    if direction == "stale" and network["hosting"]:
        explanation += (" It sits on a cloud/hosting network where IPs change hands often, so "
                        "the old reputation may belong to a previous tenant.")
    if shared and direction != "aligned":
        explanation += (" It is shared infrastructure, so OTX mentions (often malware contacting it) "
                        "were counted at half weight.")
    if coverage < 0.5:
        explanation += " Coverage is thin, so treat the paradox score with caution."

    fresh = [0.0 if x.facts.get("current") else age_days(parse_dt(x.last_seen), now)
             for x, _ in _scored(signals, "fast") if x.threat >= 0.3 and x.last_seen]
    fresh = [a for a in fresh if a is not None]

    return {
        "paradox": paradox,
        "paradox_label": label(paradox),
        "direction": direction,
        "explanation": explanation,
        "threat": round(threat, 3),
        "threat_label": threat_label(threat),
        "ledger": ledger,
        "missing": missing_beacons(original),
        "fast": fast,
        "slow": slow,
        "gap": round(gap, 3),
        "dispersion": round(disp, 3),
        "coverage": round(coverage, 3),
        "veneer": veneer,
        "scanner": scanner,
        "shared_infrastructure": shared,
        "network": network,
        "independence": {
            "beacons": sum(len(m) for _, _, m in groups),
            "independent": len(groups),
            "shared": [[s.name for s in m] for _, _, m in groups if len(m) > 1],
        },
        "freshest_fast_evidence_days": round(min(fresh), 1) if fresh else None,
    }
