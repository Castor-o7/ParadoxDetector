import unittest
from datetime import datetime, timedelta, timezone

from paradox.scoring import compute
from paradox.sources import Signal, abuse_scan_share, otx_scan_share, pulse_role, score_otx

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def sig(source, tier, threat, confidence, status="ok", last_seen=None, benign_label=None):
    return Signal(source=source, name=source, tier=tier, status=status, threat=threat,
                  confidence=confidence, last_seen=last_seen,
                  facts={"benign_label": benign_label} if benign_label else {})


class ParadoxScoreTests(unittest.TestCase):
    def test_emerging_threat_scores_high(self):
        r = compute([
            sig("otx", "fast", 0.9, 0.9), sig("feodo", "fast", 0.95, 0.9),
            sig("spamhaus", "slow", 0.0, 0.5), sig("virustotal", "slow", 0.0, 0.8),
        ], now=NOW)
        self.assertEqual(r["direction"], "emerging")
        self.assertGreaterEqual(r["paradox"], 60)

    def test_consensus_malicious_is_not_a_paradox(self):
        r = compute([
            sig("otx", "fast", 0.9, 0.9), sig("feodo", "fast", 0.95, 0.9),
            sig("spamhaus", "slow", 1.0, 0.95), sig("virustotal", "slow", 0.9, 0.8),
        ], now=NOW)
        self.assertLess(r["paradox"], 15)
        self.assertEqual(r["threat_label"], "Malicious")

    def test_consensus_benign_is_coherent(self):
        r = compute([
            sig("otx", "fast", 0.0, 0.5), sig("greynoise", "fast", 0.0, 0.9),
            sig("spamhaus", "slow", 0.0, 0.5), sig("internetdb", "slow", 0.05, 0.6),
        ], now=NOW)
        self.assertEqual(r["paradox_label"], "Coherent")
        self.assertEqual(r["threat_label"], "Likely benign")

    def test_stale_reputation_counts_less_than_emerging(self):
        emerging = compute([sig("otx", "fast", 0.9, 0.9), sig("spamhaus", "slow", 0.0, 0.9)], now=NOW)
        stale = compute([sig("otx", "fast", 0.0, 0.9), sig("spamhaus", "slow", 0.9, 0.9)], now=NOW)
        self.assertEqual(stale["direction"], "stale")
        self.assertLess(stale["paradox"], emerging["paradox"])

    def test_missing_slow_tier_dampens_paradox(self):
        full = compute([sig("otx", "fast", 0.9, 0.9), sig("spamhaus", "slow", 0.0, 0.9)], now=NOW)
        thin = compute([sig("otx", "fast", 0.9, 0.9),
                        sig("spamhaus", "slow", None, 0.0, status="error")], now=NOW)
        self.assertLess(thin["paradox"], full["paradox"])
        self.assertIn("caution", thin["explanation"])

    def test_skipped_and_context_beacons_are_ignored(self):
        base = [sig("otx", "fast", 0.5, 0.8), sig("spamhaus", "slow", 0.0, 0.5)]
        extra = base + [sig("abuseipdb", "fast", None, 0.0, status="skipped"),
                        sig("rdap", "context", None, 0.0)]
        self.assertEqual(compute(base, now=NOW)["paradox"], compute(extra, now=NOW)["paradox"])


class IndependenceTests(unittest.TestCase):
    def test_shared_origin_beacons_count_as_one_vote(self):
        quiet = [sig("otx", "fast", 0.0, 0.5), sig("greynoise", "fast", 0.0, 0.6),
                 sig("spamhaus", "slow", 0.0, 0.5)]
        one = compute(quiet + [sig("feodo", "fast", 0.9, 0.9)], now=NOW)
        echoed = compute(quiet + [sig("feodo", "fast", 0.9, 0.9), sig("threatfox", "fast", 0.9, 0.9)], now=NOW)
        self.assertEqual(one["fast"]["score"], echoed["fast"]["score"])
        self.assertEqual(echoed["independence"]["independent"], 4)
        self.assertEqual(echoed["independence"]["shared"], [["feodo", "threatfox"]])

    def test_independent_beacons_do_corroborate(self):
        quiet = [sig("greynoise", "fast", 0.0, 0.6), sig("spamhaus", "slow", 0.0, 0.5)]
        one = compute(quiet + [sig("feodo", "fast", 0.9, 0.9)], now=NOW)
        two = compute(quiet + [sig("feodo", "fast", 0.9, 0.9), sig("abuseipdb", "fast", 0.9, 0.9)], now=NOW)
        self.assertGreater(two["fast"]["score"], one["fast"]["score"])

    def test_virustotal_ignores_engines_already_queried(self):
        from paradox.sources import ECHO_ENGINES
        for engine in ("AlienVault", "abusix", "Feodo Tracker", "ThreatFox", "Spamhaus", "GreyNoise"):
            self.assertEqual(bool(ECHO_ENGINES.search(engine)), engine != "abusix", engine)


    def test_virustotal_ignores_calibration_label_sources(self):
        from unittest import mock
        from paradox import sources
        results = {"CINS Army": {"category": "malicious"}, "EmergingThreats": {"category": "malicious"},
                   "IPsum": {"category": "malicious"}, "VendorA": {"category": "malicious"},
                   "VendorB": {"category": "harmless"}}
        s = Signal(source="virustotal", name="vt", tier="slow")
        with mock.patch.object(sources, "fetch_json", return_value=(200, {"data": {"attributes": {"last_analysis_results": results}}})):
            sources.check_virustotal("203.0.113.9", s)
        self.assertEqual(s.summary, "1 malicious / 0 suspicious of 2 independent vendors")
        self.assertIn("CINS Army, EmergingThreats, IPsum", s.evidence[0])

    def vt(self, *flags):
        from unittest import mock
        from paradox import sources
        results = {f"Vendor{i}": {"category": c} for i, c in enumerate(flags)} | {"Clean": {"category": "harmless"}}
        s = Signal(source="virustotal", name="vt", tier="slow")
        with mock.patch.object(sources, "fetch_json", return_value=(200, {"data": {"attributes": {"last_analysis_results": results}}})):
            sources.check_virustotal("203.0.113.9", s)
        return s

    def test_one_vendor_alone_cannot_rate_an_ip_suspicious(self):
        quiet = [sig("otx", "fast", 0.0, 0.5), sig("abuseipdb", "fast", 0.0, 0.8), sig("spamhaus", "slow", 0.0, 0.5)]
        for flag in ("malicious", "suspicious"):
            r = compute(quiet + [self.vt(flag)], now=NOW)
            self.assertEqual(r["threat_label"], "Likely benign", flag)

    def test_one_vendor_cannot_contradict_a_label(self):
        gn = sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X")
        one = self.vt(*["malicious"] * 1)
        one.threat = 0.6     # even with a high reading, one vendor isn't a contradiction
        self.assertFalse(compute([gn, one], now=NOW)["veneer"]["active"])

    def test_two_vendors_and_clean_answers_keep_full_confidence(self):
        self.assertEqual(self.vt("malicious", "malicious").confidence, 0.8)
        self.assertEqual(self.vt("malicious", "suspicious").confidence, 0.8)
        self.assertEqual(self.vt().confidence, 0.8)
        self.assertEqual(self.vt("malicious").confidence, 0.4)

    def test_saved_scans_are_rescored_under_the_vendor_rule(self):
        from paradox import calibrate
        saved = {"otx_raw": None, "signals": [{"source": "virustotal", "name": "v", "tier": "slow", "threat": 0.2,
                                                "confidence": 0.8, "summary": "1 malicious / 0 suspicious of 86 independent vendors"}]}
        vt = next(s for s in calibrate.build_signals("45.1.1.1", saved) if s.source == "virustotal")
        self.assertEqual(vt.confidence, 0.4)

    def test_virustotal_without_per_vendor_results_gives_no_reading(self):
        from unittest import mock
        from paradox import sources
        beacon = next(b for b in sources.BEACONS if b.id == "virustotal")
        for attrs in ({"last_analysis_stats": {"malicious": 5, "harmless": 80}}, {},
                      {"last_analysis_results": {"IPsum": {"category": "malicious"}}}):
            with mock.patch.object(sources, "fetch_json", return_value=(200, {"data": {"attributes": attrs}})), \
                 mock.patch.object(sources.config, "key", return_value="set"):
                s = sources.run_beacon(beacon, "203.0.113.9")
            self.assertEqual((s.status, s.threat), ("error", None), attrs)

    def test_virustotal_scores_only_independent_vendors(self):
        from unittest import mock
        from paradox import sources
        results = {"AlienVault": {"category": "malicious"}, "Feodo Tracker": {"category": "malicious"},
                   "Spamhaus": {"category": "malicious"}, "VendorA": {"category": "malicious"},
                   "VendorB": {"category": "harmless"}}
        body = {"data": {"attributes": {"last_analysis_results": results}}}
        s = Signal(source="virustotal", name="vt", tier="slow")
        with mock.patch.object(sources, "fetch_json", return_value=(200, body)):
            sources.check_virustotal("203.0.113.9", s)
        self.assertEqual(s.summary, "1 malicious / 0 suspicious of 2 independent vendors")
        self.assertIn("AlienVault, Feodo Tracker, Spamhaus", s.evidence[0])


def net(threat, hosting=False, asn_drop=False):
    nb = sig("neighborhood", "network", threat, 0.6)
    nb.facts.update(listed_neighbors=20, prefix="203.0.113.0/24")
    asn = sig("network", "network", 1.0 if asn_drop else 0.0, 0.9 if asn_drop else 0.5)
    asn.facts.update(hosting=hosting, asn_drop=asn_drop, holder="EXAMPLE-AS")
    return [nb, asn]


class NetworkTests(unittest.TestCase):
    CLEAN = [sig("otx", "fast", 0.0, 0.5), sig("greynoise", "fast", 0.0, 0.2),
             sig("spamhaus", "slow", 0.0, 0.5), sig("internetdb", "slow", 0.0, 0.3)]

    def test_clean_ip_in_dirty_neighborhood_raises_paradox(self):
        base = compute(self.CLEAN, now=NOW)
        dirty = compute(self.CLEAN + net(0.9), now=NOW)
        self.assertGreater(dirty["paradox"], base["paradox"])
        self.assertIn("rotate addresses", dirty["explanation"])
        self.assertEqual(dirty["fast"], base["fast"])   # surroundings never leak into the tiers
        self.assertEqual(dirty["slow"], base["slow"])
        self.assertAlmostEqual(dirty["threat"], 0.45)

    def test_hosting_network_halves_neighborhood_risk(self):
        r = compute(self.CLEAN + net(0.9, hosting=True), now=NOW)
        self.assertAlmostEqual(r["network"]["neighborhood"], 0.45)
        self.assertLess(r["paradox"], compute(self.CLEAN + net(0.9), now=NOW)["paradox"])

    def test_asn_drop_sets_threat_floor(self):
        r = compute(self.CLEAN + net(0.0, asn_drop=True), now=NOW)
        self.assertEqual(r["threat_label"], "Likely malicious")
        self.assertIn("ASN-DROP", r["explanation"])

    def test_stale_on_criminal_network_reads_as_dormant_not_cleaned(self):
        r = compute([sig("otx", "fast", 0.0, 0.9), sig("spamhaus", "slow", 1.0, 0.95)]
                    + net(0.0, asn_drop=True), now=NOW)
        self.assertEqual(r["direction"], "stale")
        self.assertIn("dormancy", r["explanation"])
        self.assertNotIn("cleaned up", r["explanation"])

    def test_no_cover_when_ip_is_already_malicious(self):
        bad = [sig("feodo", "fast", 0.95, 0.9), sig("spamhaus", "slow", 1.0, 0.95)]
        self.assertEqual(compute(bad + net(0.9), now=NOW)["network"]["cover"], 0.0)

    def test_network_signals_do_not_contradict_benign_labels(self):
        r = compute([sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X")] + net(0.9), now=NOW)
        self.assertFalse(r["veneer"]["active"])

    def test_stale_reputation_on_cloud_mentions_previous_tenant(self):
        r = compute([sig("otx", "fast", 0.0, 0.9), sig("spamhaus", "slow", 0.9, 0.9)]
                    + net(0.0, hosting=True), now=NOW)
        self.assertIn("previous tenant", r["explanation"])


class VeneerTests(unittest.TestCase):
    RIOT = dict(benign_label="GreyNoise RIOT: Example Cloud")

    def test_benign_label_contradicted_by_fresh_threat_raises_paradox(self):
        plain = [sig("otx", "fast", 0.8, 0.9, last_seen="2026-10-25"),
                 sig("greynoise", "fast", 0.0, 0.6),
                 sig("spamhaus", "slow", 0.0, 0.5), sig("internetdb", "slow", 0.0, 0.6)]
        veneered = [plain[0], sig("greynoise", "fast", 0.0, 0.6, **self.RIOT), *plain[2:]]
        r = compute(veneered, now=NOW)
        self.assertTrue(r["veneer"]["active"])
        self.assertIn("providing cover", r["explanation"])
        self.assertGreater(r["paradox"], compute(plain, now=NOW)["paradox"])

    def test_uncontradicted_benign_label_stays_coherent(self):
        r = compute([sig("otx", "fast", 0.0, 0.5), sig("greynoise", "fast", 0.0, 0.6, **self.RIOT),
                     sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertFalse(r["veneer"]["active"])
        self.assertEqual(r["veneer"]["labels"], ["GreyNoise RIOT: Example Cloud"])
        self.assertEqual(r["paradox_label"], "Coherent")

    def test_stale_threat_does_not_trigger_veneer(self):
        r = compute([sig("otx", "fast", 0.8, 0.9, last_seen="2025-01-01"),
                     sig("greynoise", "fast", 0.0, 0.6, **self.RIOT)], now=NOW)
        self.assertFalse(r["veneer"]["active"])

    def test_live_list_status_counts_as_fresh(self):
        c2 = sig("feodo", "fast", 0.95, 0.9, last_seen="2026-03-12")
        c2.facts["current"] = True
        r = compute([c2, sig("otx", "fast", 0.3, 0.7, benign_label="OTX validation: Cloud Provider IP range"),
                     sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertTrue(r["veneer"]["active"])

    def test_beacon_cannot_contradict_its_own_label(self):
        r = compute([sig("otx", "fast", 0.6, 0.9, last_seen="2026-10-25",
                         benign_label="OTX validation: Whitelisted IP"),
                     sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertFalse(r["veneer"]["active"])


def pulse(age, author="alice", name=None, **extra):
    return {"name": name or f"Campaign seen {age}d ago", "author": {"username": author},
            "modified": (NOW - timedelta(days=age)).isoformat(), "pulse_source": "web",
            "subscriber_count": 1000, **extra}


class ScannerLabelTests(unittest.TestCase):
    """A scanner label explains scanning reports, but not attacks."""

    def scan(self, abuse_share, otx_share):
        gn = sig("greynoise", "fast", 0.05, 0.6, last_seen="2026-10-26", benign_label="GreyNoise benign: Shodan.io")
        gn.facts["label_kind"] = "scanner"
        abuse = sig("abuseipdb", "fast", 1.0, 1.0, last_seen="2026-10-26")
        abuse.facts["scan_share"] = abuse_share
        otx = sig("otx", "fast", 0.85, 1.0, last_seen="2026-10-26")
        otx.facts["scan_share"] = otx_share
        return compute([gn, abuse, otx, sig("spamhaus", "slow", 0.0, 0.5),
                        sig("internetdb", "slow", 0.05, 0.6)], now=NOW)

    def test_scanner_scanning_is_expected(self):
        r = self.scan(0.77, 0.74)      # Shodan's scanner, measured 2026-10-28
        self.assertFalse(r["veneer"]["active"])
        self.assertEqual(len(r["scanner"]["explained"]), 2)
        self.assertLess(r["paradox"], 35)
        self.assertIn("known scanner", r["explanation"])

    def test_scanner_label_on_an_attacker_is_a_veneer(self):
        r = self.scan(0.17, 0.14)      # brute-forcer and malware loader, measured 2026-10-28
        self.assertTrue(r["veneer"]["active"])
        self.assertEqual(r["scanner"]["explained"], [])
        self.assertGreaterEqual(r["paradox"], 60)

    def test_business_label_explains_nothing(self):
        gn = sig("greynoise", "fast", 0.0, 0.6, last_seen="2026-10-26", benign_label="GreyNoise RIOT: Google")
        abuse = sig("abuseipdb", "fast", 1.0, 1.0, last_seen="2026-10-26")
        abuse.facts["scan_share"] = 0.9
        r = compute([gn, abuse, sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertTrue(r["veneer"]["active"])     # a Google IP port-scanning the internet is odd

    def test_abuse_scan_share(self):
        reports = [{"categories": [14]}, {"categories": [14, 15]}, {"categories": [18, 22]}, {"categories": []}]
        self.assertAlmostEqual(abuse_scan_share(reports), 0.667, places=3)
        self.assertIsNone(abuse_scan_share([]))

    def test_otx_mixed_pulses_do_not_vote(self):
        pulses = [{"name": "Webscanners", "tags": ["portscan"]},              # scan
                  {"name": "SSH honeypot", "tags": ["scanner", "bruteforce"]},  # mixed: no vote
                  {"name": "Honeypot feed", "tags": ["honeypot"]},             # neither: no vote
                  {"name": "Mirai loader", "tags": ["botnet"]}]                 # attack
        self.assertEqual(otx_scan_share({"pulse_info": {"pulses": pulses}}), 0.5)


class SharedInfrastructureTests(unittest.TestCase):
    def test_cdn_halves_otx_but_not_abuse_reports(self):
        abuse = sig("abuseipdb", "fast", 0.0, 0.8)
        abuse.facts["usage_type"] = "Content Delivery Network"
        base = [sig("spamhaus", "slow", 0.0, 0.5), sig("internetdb", "slow", 0.05, 0.6)]
        cdn = compute([sig("otx", "fast", 0.43, 1.0), abuse] + base, now=NOW)
        plain = compute([sig("otx", "fast", 0.43, 1.0), sig("abuseipdb", "fast", 0.0, 0.8)] + base, now=NOW)
        self.assertLess(cdn["paradox"], plain["paradox"])
        self.assertIn("Content Delivery Network", cdn["shared_infrastructure"])

        attacked = sig("abuseipdb", "fast", 0.9, 1.0, last_seen="2026-10-26")
        attacked.facts["usage_type"] = "Content Delivery Network"
        r = compute([sig("otx", "fast", 0.0, 0.5), attacked] + base, now=NOW)
        self.assertEqual(r["threat_label"], "Malicious")   # direct reports keep full weight

    def test_benign_label_does_not_discount_its_contradiction(self):
        gn = sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: Example")
        r = compute([sig("otx", "fast", 0.8, 0.9, last_seen="2026-10-25"), gn,
                     sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertIsNone(r["shared_infrastructure"])
        self.assertTrue(r["veneer"]["active"])


class ForgedIdentityTests(unittest.TestCase):
    def rdns(self, **facts):
        s = sig("rdns", "context", None, 0.0)
        s.facts.update(facts)
        return s

    def test_forged_identity_is_a_veneer_with_a_threat_floor(self):
        r = compute([self.rdns(spoofed_identity="reverse DNS claims Shodan (x.shodan.io), but ..."),
                     sig("otx", "fast", 0.0, 0.5), sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertTrue(r["veneer"]["active"])
        self.assertEqual(r["threat_label"], "Suspicious")
        self.assertIn("forged label", r["explanation"])

    def test_confirmed_scanner_rdns_explains_scanning_without_greynoise(self):
        label = self.rdns(benign_label="rDNS: Shodan scanner, forward-confirmed", label_kind="scanner")
        abuse = sig("abuseipdb", "fast", 1.0, 1.0, last_seen="2026-10-26")
        abuse.facts["scan_share"] = 0.77
        greynoise_down = sig("greynoise", "fast", None, 0.0, status="error")
        r = compute([label, abuse, greynoise_down, sig("spamhaus", "slow", 0.0, 0.5),
                     sig("internetdb", "slow", 0.05, 0.6)], now=NOW)
        self.assertEqual(r["scanner"]["explained"], ["abuseipdb (77% scanning)"])
        self.assertFalse(r["veneer"]["active"])
        self.assertLess(r["paradox"], 35)


class LedgerTests(unittest.TestCase):
    def assertAddsUp(self, r):
        self.assertAlmostEqual(sum(x["points"] for x in r["ledger"]["paradox"]), r["paradox"], delta=0.1)
        self.assertAlmostEqual(sum(x["points"] for x in r["ledger"]["threat"]), r["threat"] * 100, delta=0.1)

    def labels(self, r, key):
        return " | ".join(x["label"] for x in r["ledger"][key])

    def test_every_kind_of_result_adds_up(self):
        scanner = ScannerLabelTests()
        rdns = sig("rdns", "context", None, 0.0)
        rdns.facts["spoofed_identity"] = "reverse DNS claims Shodan, but it does not resolve back"
        for r in (compute([sig("otx", "fast", 0.9, 0.9), sig("feodo", "fast", 0.95, 0.9),
                           sig("spamhaus", "slow", 0.0, 0.5), sig("virustotal", "slow", 0.0, 0.8)], now=NOW),
                  compute([sig("otx", "fast", 0.0, 0.9), sig("spamhaus", "slow", 0.9, 0.9)], now=NOW),
                  compute([sig("otx", "fast", 0.9, 0.9), sig("spamhaus", "slow", None, 0.0, status="error")], now=NOW),
                  compute(NetworkTests.CLEAN + net(0.9), now=NOW),
                  compute([rdns, sig("otx", "fast", 0.0, 0.5), sig("spamhaus", "slow", 0.0, 0.5)], now=NOW),
                  compute([sig("rdap", "context", None, 0.0)], now=NOW),
                  scanner.scan(0.77, 0.74), scanner.scan(0.17, 0.14)):
            self.assertAddsUp(r)

    def test_names_the_claim_that_failed(self):
        r = ScannerLabelTests().scan(0.17, 0.14)
        self.assertIn("Veneer: GreyNoise benign: Shodan.io contradicted", self.labels(r, "paradox"))
        self.assertEqual([a["beacon"] for a in r["ledger"]["adjustments"]], ["greynoise"])
        self.assertEqual(r["ledger"]["adjustments"][0]["field"], "confidence")

    def test_shows_what_the_scanner_label_discounted(self):
        adjusted = ScannerLabelTests().scan(0.77, 0.74)["ledger"]["adjustments"]
        self.assertEqual({a["beacon"]: a["to"] for a in adjusted}, {"abuseipdb": 0.23, "otx": 0.221})
        self.assertIn("explains the 77%", adjusted[0]["why"])

    def test_thin_coverage_is_a_negative_row(self):
        r = compute([sig("otx", "fast", 0.9, 0.9), sig("spamhaus", "slow", None, 0.0, status="error")], now=NOW)
        self.assertLess(r["ledger"]["paradox"][-1]["points"], 0)
        self.assertIn("Coverage", r["ledger"]["paradox"][-1]["label"])

    def test_shared_origin_beacons_share_one_row(self):
        r = compute([sig("feodo", "fast", 0.9, 0.9), sig("threatfox", "fast", 0.9, 0.9),
                     sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)
        self.assertIn("feodo + threatfox", self.labels(r, "threat"))


class ThinReportTests(unittest.TestCase):
    BASE = [sig("otx", "fast", 0.0, 0.5), sig("spamhaus", "slow", 0.0, 0.5), sig("internetdb", "slow", 0.05, 0.6)]

    def abuse(self, threat, reporters, **kw):
        s = sig("abuseipdb", "fast", threat, min(1.0, 0.4 + reporters / 20), **kw)
        s.facts["reporters"] = reporters
        return s

    def test_a_few_reporters_count_for_less(self):
        thin = compute([self.abuse(0.36, 7)] + self.BASE, now=NOW)
        self.assertEqual(thin["threat_label"], "Likely benign")
        self.assertLess(thin["paradox"], 15)
        self.assertEqual(thin["ledger"]["adjustments"][0]["why"], "only 7 distinct reporters, none in the last 3 days")

    def reading(self, **kw):
        r = compute([self.abuse(0.36, 7, **kw)] + self.BASE, now=NOW)
        return next((a["to"] for a in r["ledger"]["adjustments"] if a["field"] == "threat"), 0.36)

    def test_recent_reports_keep_the_full_reading_up_to_the_boundary(self):
        self.assertEqual(self.reading(last_seen="2026-10-26"), 0.36)
        self.assertEqual(self.reading(last_seen="2026-10-24"), 0.36)        # NOW minus exactly 3 days
        self.assertEqual(self.reading(last_seen="2026-10-23T23:59:59+00:00"), 0.21)  # just past it
        self.assertEqual(self.reading(last_seen="2026-10-01"), 0.21)

    def test_unknown_report_date_counts_as_old(self):
        self.assertEqual(self.reading(), 0.21)
        self.assertEqual(self.reading(last_seen="not a date"), 0.21)

    def test_enough_reporters_keep_the_full_reading(self):
        r = compute([self.abuse(0.97, 12)] + self.BASE, now=NOW)
        self.assertEqual(r["ledger"]["adjustments"], [])
        self.assertEqual(r["threat_label"], "Malicious")

    def test_other_beacons_are_not_scaled(self):
        otx = sig("otx", "fast", 0.9, 0.9)
        otx.facts["reporters"] = 1
        self.assertEqual(compute([otx, sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)["ledger"]["adjustments"], [])

    def test_a_benign_label_plays_no_part(self):
        gn = sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X")
        labeled = compute([self.abuse(0.9, 3), gn] + self.BASE[1:], now=NOW)
        plain = compute([self.abuse(0.9, 3), sig("greynoise", "fast", 0.0, 0.6)] + self.BASE[1:], now=NOW)
        self.assertEqual([a["to"] for a in labeled["ledger"]["adjustments"] if a["field"] == "threat"],
                         [a["to"] for a in plain["ledger"]["adjustments"] if a["field"] == "threat"])

    def test_a_missing_reporter_count_means_no_scaling(self):
        from unittest import mock
        from paradox import sources
        s = Signal(source="abuseipdb", name="a", tier="fast")
        body = {"data": {"abuseConfidenceScore": 90, "totalReports": 5}}
        with mock.patch.object(sources, "fetch_json", return_value=(200, body)):
            sources.check_abuseipdb("45.1.1.1", s)
        self.assertNotIn("reporters", s.facts)
        self.assertEqual(compute([s, sig("spamhaus", "slow", 0.0, 0.5)], now=NOW)["ledger"]["adjustments"], [])

    def test_saved_scans_recover_the_reporter_count(self):
        from paradox import calibrate
        saved = {"otx_raw": None, "signals": [{"source": "abuseipdb", "name": "a", "tier": "fast", "threat": 0.36,
                                                "confidence": 0.75, "summary": "Abuse confidence 36% from 8 reports by 7 users (90d)"}]}
        abuse = next(s for s in calibrate.build_signals("45.1.1.1", saved) if s.source == "abuseipdb")
        self.assertEqual(abuse.facts["reporters"], 7)


class ClaimTests(unittest.TestCase):
    def rdns(self, status="ok", **facts):
        s = sig("rdns", "context", None, 0.0, status=status)
        s.facts.update(facts)
        return s

    BASE = [sig("otx", "fast", 0.0, 0.5), sig("spamhaus", "slow", 0.0, 0.5)]

    def claims(self, *extra):
        return compute(list(extra) + self.BASE, now=NOW)["claims"]

    def test_forged_reverse_dns_is_unconfirmed(self):
        c = self.claims(self.rdns(claim="Shodan", spoofed_identity="does not resolve back"))
        self.assertEqual([(x["claim"], x["result"]) for x in c], [("Reverse DNS says Shodan", "unconfirmed")])

    def test_confirmed_identity_can_still_be_contradicted(self):
        good = self.rdns(claim="Shodan", benign_label="rDNS: Shodan scanner, forward-confirmed", label_kind="scanner")
        c = self.claims(good, sig("abuseipdb", "fast", 0.9, 0.9, last_seen="2026-10-26"))[0]
        self.assertEqual(c["result"], "confirmed")
        self.assertTrue(c["contradicted"])

    def test_published_range_is_confirmed(self):
        s = sig("published", "context", None, 0.0, benign_label="Published by Censys: scanner range 1.2.3.0/24")
        s.facts.update(operator="Censys", label_kind="scanner")
        c = self.claims(s)
        self.assertEqual((c[0]["claim"], c[0]["result"]), ("Censys lists this address", "confirmed"))

    def test_vouch_is_never_called_confirmed(self):
        c = self.claims(sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X"))
        self.assertEqual(c[0]["result"], "not_contradicted")
        c = self.claims(sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X"),
                        sig("abuseipdb", "fast", 0.9, 0.9, last_seen="2026-10-26"))
        self.assertEqual(c[0]["result"], "unconfirmed")

    def test_forgery_alone_does_not_condemn_other_labels(self):
        r = compute([self.rdns(claim="Shodan", spoofed_identity="forged"),
                     sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X")] + self.BASE, now=NOW)
        self.assertEqual({c["claim"]: c["result"] for c in r["claims"]},
                         {"Reverse DNS says Shodan": "unconfirmed", "GreyNoise RIOT: X": "not_contradicted"})
        self.assertIn("Veneer: forged identity contradicted", [x["label"] for x in r["ledger"]["paradox"]])

    def test_failed_checks_are_untested_and_ordered_first_after_failures(self):
        c = self.claims(self.rdns(status="error"), sig("greynoise", "fast", 0.0, 0.6, benign_label="GreyNoise RIOT: X"))
        self.assertEqual([x["result"] for x in c], ["untested", "not_contradicted"])

    def test_no_claims_no_rows(self):
        self.assertEqual(self.claims(self.rdns(ptr="host.example.com", confirmed=True)), [])


class OtxQualityTests(unittest.TestCase):
    def otx(self, *pulses):
        return {"pulse_info": {"count": len(pulses), "pulses": list(pulses)}}

    def test_one_author_flooding_counts_once(self):
        flood = score_otx(self.otx(*[pulse(1, "mallory") for _ in range(10)]), now=NOW)
        single = score_otx(self.otx(pulse(1, "mallory")), now=NOW)
        self.assertEqual(flood["threat"], single["threat"])
        self.assertEqual(flood["flooders"], [("mallory", 10)])

    def test_independent_authors_add_up(self):
        one = score_otx(self.otx(pulse(1, "a")), now=NOW)
        three = score_otx(self.otx(pulse(1, "a"), pulse(1, "b"), pulse(1, "c")), now=NOW)
        self.assertGreater(three["threat"], one["threat"])
        self.assertGreater(three["confidence"], one["confidence"])

    def test_junk_clone_and_automated_pulses_are_discounted(self):
        good = score_otx(self.otx(pulse(1)), now=NOW)["threat"]
        for bad in (pulse(1, name="test"), pulse(1, name="20220127clone"),
                    pulse(1, cloned_from="abc"), pulse(1, pulse_source="api"),
                    pulse(1, subscriber_count=0)):
            self.assertLess(score_otx(self.otx(bad), now=NOW)["threat"], good, bad)


class PulseRoleTests(unittest.TestCase):
    def role(self, name="Campaign", tags=(), **counts):
        return pulse_role({"name": name, "tags": list(tags), "indicator_type_counts": counts})

    def test_address_lists_are_actors(self):
        self.assertEqual(self.role(IPv4=95, domain=5), "actor")

    def test_malware_reports_describe_what_was_contacted(self):
        self.assertEqual(self.role(IPv4=10, domain=90), "contacted")
        self.assertEqual(self.role(**{"FileHash-MD5": 40}, IPv4=60), "contacted")

    def test_honeypot_data_is_actor_whatever_else_it_lists(self):
        self.assertEqual(self.role("Honeypot Data - T-Pot", **{"FileHash-MD5": 80}, IPv4=20), "actor")
        self.assertEqual(self.role(tags=["bruteforce"], domain=100), "actor")

    def test_no_indicator_counts_is_unknown(self):
        self.assertEqual(self.role(), "unknown")
        self.assertEqual(self.role(IPv4=40, CVE=60), "unknown")

    def test_contacted_pulses_count_for_less_and_say_why(self):
        actor = pulse(1, indicator_type_counts={"IPv4": 100})
        contacted = pulse(1, indicator_type_counts={"IPv4": 10, "domain": 90})
        data = {"pulse_info": {"count": 1, "pulses": [contacted]}}
        self.assertLess(score_otx(data, now=NOW)["threat"],
                        score_otx({"pulse_info": {"count": 1, "pulses": [actor]}}, now=NOW)["threat"])
        self.assertIn("contacted, not actor", score_otx(data, now=NOW)["top"][0][2])

    def test_an_authors_actor_pulse_still_counts_fully(self):
        actor = pulse(1, indicator_type_counts={"IPv4": 100})
        contacted = pulse(1, indicator_type_counts={"domain": 100})
        both = {"pulse_info": {"count": 2, "pulses": [contacted, actor]}}
        alone = {"pulse_info": {"count": 1, "pulses": [actor]}}
        self.assertEqual(score_otx(both, now=NOW)["threat"], score_otx(alone, now=NOW)["threat"])


class OtxRecencyTests(unittest.TestCase):
    def pulses(self, *ages):
        return {"pulse_info": {"count": len(ages), "pulses": [
            pulse(a, author=f"author{a}") for a in ages]}}

    def test_fresh_pulses_outweigh_old_ones(self):
        fresh = score_otx(self.pulses(1, 2, 3), now=NOW)
        old = score_otx(self.pulses(900, 1000, 1100), now=NOW)
        self.assertGreater(fresh["threat"], 0.7)
        self.assertLess(old["threat"], 0.01)
        self.assertEqual(fresh["recent_30"], 3)

    def test_no_pulses_is_benign(self):
        self.assertEqual(score_otx({"pulse_info": {"count": 0, "pulses": []}}, now=NOW)["threat"], 0)

    def test_otx_whitelist_suppresses_its_own_pulses_but_is_reported(self):
        # Calibration: whitelisted resolvers/CDNs appear in many sandbox pulses,
        # so OTX's own pulses are mostly noise for them. The label is kept so
        # the veneer check can still fire on independent evidence.
        data = self.pulses(1, 2, 3)
        data["validation"] = [{"source": "whitelist", "name": "Known benign"}]
        s = score_otx(data, now=NOW)
        self.assertEqual(s["whitelisted"], ["Known benign"])
        self.assertLess(s["threat"], 0.2)

    def test_bulk_sandbox_pulses_count_less_than_targeted_ones(self):
        targeted = score_otx({"pulse_info": {"count": 1, "pulses": [pulse(1, indicator_count=300)]}}, now=NOW)
        bulk = score_otx({"pulse_info": {"count": 1, "pulses": [pulse(1, indicator_count=20000)]}}, now=NOW)
        self.assertLess(bulk["threat"], targeted["threat"] * 0.3)


if __name__ == "__main__":
    unittest.main()
