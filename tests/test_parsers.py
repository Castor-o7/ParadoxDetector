"""Beacon parsers against real (trimmed) API responses in tests/fixtures.

If a provider changes its response format, these fail before the scores
silently drift.
"""

import json
import socket
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from paradox import calibrate, sources
from paradox.sources import Signal

FIX = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def fixture(name):
    return json.loads((FIX / name).read_text())


def run(check, ip, responses, tier="fast"):
    """Run a beacon check with fetch_json answering from `responses` in order."""
    sig = Signal(source=check.__name__, name=check.__name__, tier=tier)
    with mock.patch.object(sources, "fetch_json", side_effect=responses):
        check(ip, sig)
    return sig


class OtxFixtureTests(unittest.TestCase):
    def test_real_pulse_set_is_scored_by_author_and_quality(self):
        s = sources.score_otx(fixture("otx_45.155.205.233.json"), now=NOW)
        self.assertEqual(s["total"], 28)
        self.assertEqual(s["authors"], 17)
        self.assertEqual(s["flooders"][0], ("kkwonsj99", 7))
        self.assertGreater(s["discounted"], 5)          # clones, test pulses, automated feeds
        self.assertTrue(0.15 < s["threat"] < 0.45)     # two automated pulses from one author last week

    def test_check_otx_builds_evidence(self):
        sig = run(sources.check_otx, "45.155.205.233", [(200, fixture("otx_45.155.205.233.json"))])
        self.assertIn("28 pulses from 17 authors", sig.summary)
        self.assertTrue(any("Counted once per author" in e for e in sig.evidence))
        self.assertEqual(sig.last_seen, "2026-10-20")


class GreyNoiseFixtureTests(unittest.TestCase):
    def test_benign_scanner_is_a_label_not_a_verdict(self):
        sig = run(sources.check_greynoise, "71.6.135.131", [(200, fixture("greynoise_benign.json"))])
        self.assertEqual(sig.threat, 0.05)
        self.assertEqual(sig.facts["benign_label"], "GreyNoise benign: Shodan.io")

    def test_not_observed_is_weak_benign(self):
        sig = run(sources.check_greynoise, "45.155.205.233", [(404, fixture("greynoise_404.json"))])
        self.assertEqual((sig.threat, sig.confidence), (0.0, 0.2))

    def test_rate_limit_raises_beacon_error(self):
        with self.assertRaises(sources.BeaconError):
            run(sources.check_greynoise, "1.2.3.4", [(429, {"message": "rate limited"})])


class InternetDbFixtureTests(unittest.TestCase):
    def test_tor_exit_with_no_cves_is_low_exposure(self):
        with mock.patch.object(sources, "_kev_set", return_value=[]):
            sig = run(sources.check_internetdb, "185.220.101.1",
                      [(200, fixture("internetdb_tor.json"))], tier="slow")
        self.assertEqual(sig.threat, 0.05)
        self.assertEqual(sig.summary, "4 open ports, 0 CVEs")
        self.assertIn("Tags: self-signed, tor", sig.evidence)


class NetworkFixtureTests(unittest.TestCase):
    def test_ripestat_network_lookup(self):
        with mock.patch.object(sources, "_asn_drop", return_value={"403005": "BLATANTHOST"}), \
             mock.patch.object(sources, "_feodo_index", return_value={}):
            sig = run(sources.check_network, "50.16.16.211",
                      [(200, fixture("ripestat_network_info.json")), (200, fixture("ripestat_as_overview.json"))],
                      tier="network")
        self.assertEqual(sig.facts["asn"], "14618")
        self.assertTrue(sig.facts["hosting"])
        self.assertEqual(sig.threat, 0.0)

    def test_asn_drop_network_is_bulletproof_not_hosting(self):
        info = {"data": {"asns": ["403005"], "prefix": "64.89.160.0/24"}}
        overview = {"data": {"holder": "BLATANTHOST - Blatant"}}
        with mock.patch.object(sources, "_asn_drop", return_value={"403005": "BLATANTHOST"}), \
             mock.patch.object(sources, "_feodo_index", return_value={}):
            sig = run(sources.check_network, "64.89.160.10", [(200, info), (200, overview)], tier="network")
        self.assertEqual(sig.threat, 1.0)
        self.assertFalse(sig.facts["hosting"])

    def test_neighborhood_counts_neighbors_not_the_ip_itself(self):
        lists = {"blocklist.de": ["203.0.113.5", "203.0.113.6", "203.0.113.7", "198.51.100.1"],
                 "CINS Army": ["203.0.113.5", "203.0.113.9"], "ET compromised": []}
        with mock.patch.object(sources, "_ip_list", side_effect=lambda name, url: lists[name]), \
             mock.patch.object(sources, "_feodo_index", return_value={"203.0.113.8": {}}), \
             mock.patch.object(sources, "_drop_networks", return_value=[]):
            sig = Signal(source="neighborhood", name="n", tier="network")
            sources.check_neighborhood("203.0.113.5", sig)
        self.assertEqual(sig.facts["listed_neighbors"], 4)       # .6 .7 .9 and the Feodo .8
        self.assertEqual(sig.facts["self_listed"], ["blocklist.de", "CINS Army"])
        self.assertAlmostEqual(sig.threat, 0.221, places=3)    # 4 - 2 noise -> 1 - e^(-2/8)


class CalibrationTests(unittest.TestCase):
    def test_auc(self):
        self.assertEqual(calibrate.auc([0.9, 0.8], [0.1, 0.2]), 1.0)
        self.assertEqual(calibrate.auc([0.1], [0.9]), 0.0)
        self.assertEqual(calibrate.auc([0.5], [0.5]), 0.5)

    def test_scanners_get_their_own_class_but_strict_numbers_stay_headline(self):
        def scan(threat, scanner=False, scan_share=None):
            sigs = [Signal(source="abuseipdb", name="AbuseIPDB", tier="fast", threat=threat, confidence=1.0,
                           last_seen="2026-10-28", facts={"scan_share": scan_share} if scan_share else {}),
                    Signal(source="spamhaus", name="DROP", tier="slow", threat=0.0, confidence=0.5)]
            if scanner:
                sigs.append(Signal(source="rdns", name="Reverse DNS identity", tier="context",
                                   facts={"benign_label": "rDNS: Shodan scanner", "label_kind": "scanner"}))
            return sigs
        labels = {"malicious": ["45.1.1.1", "45.1.1.2"], "benign": ["8.8.8.8"]}
        ev = calibrate.evaluate(labels, {"45.1.1.1": scan(1.0), "45.1.1.2": scan(1.0, True, 0.95),
                                         "8.8.8.8": scan(0.0)})
        self.assertEqual(ev["detection_rate"], 0.5)                 # strict: the scanner is a miss
        self.assertEqual(ev["scanner_aware"]["detection_rate"], 1.0)
        self.assertEqual(ev["scanners"][0]["verdict"], "explained")
        self.assertEqual(ev["scanners"][0]["identified_by"], ["Reverse DNS identity"])

    def test_refresh_adds_beacons_newer_than_the_scan(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "45.1.1.1.json"
            path.write_text(json.dumps({"signals": [{"source": "tor", "name": "Tor", "tier": "context"}],
                                        "otx_raw": None, "otx_error": None}))
            fresh = Signal(source="rdns", name="Reverse DNS identity", tier="context", summary="No reverse DNS")
            with mock.patch.object(calibrate, "SCANS", Path(d)), \
                 mock.patch.object(calibrate, "run_beacon", return_value=fresh), \
                 mock.patch("sys.stderr"):
                calibrate.refresh(["45.1.1.1"], ["rdns"], pause=0)
            self.assertEqual([s["source"] for s in json.loads(path.read_text())["signals"]], ["tor", "rdns"])

    def test_malicious_labels_exclude_score_inputs(self):
        lists = {"blocklist.de": ["45.1.1.1", "45.1.1.2", "45.1.1.3", "10.0.0.1"],
                 "CINS Army": ["45.1.1.1", "45.1.1.2", "45.1.1.3", "10.0.0.1"],
                 "ET compromised": ["46.1.1.4"]}
        with mock.patch.object(calibrate, "_ip_list", side_effect=lambda name, url: lists[name]), \
             mock.patch.object(calibrate, "_feodo_index", return_value={"45.1.1.2": {}}), \
             mock.patch.object(calibrate, "_drop_networks", return_value=[["45.1.1.3/32", "SBL1"]]):
            picked = calibrate.malicious_set(10, seed=1)
        # .2 is on Feodo and .3 is in DROP (direct score inputs), 46.1.1.4 is on only
        # one list, and 10.0.0.1 is private - only 45.1.1.1 is a fair label.
        self.assertEqual(picked, ["45.1.1.1"])


class ReverseDnsTests(unittest.TestCase):
    def rdns(self, ip, ptr, forward):
        def addr(host, *_):
            return (ptr, [], [ip]) if ptr else (_ for _ in ()).throw(socket.herror(1, "none"))
        sig = Signal(source="rdns", name="rdns", tier="context")
        with mock.patch.object(sources.socket, "gethostbyaddr", side_effect=addr), \
             mock.patch.object(sources.socket, "getaddrinfo",
                               return_value=[(2, 1, 6, "", (a, 0)) for a in forward]):
            sources.check_rdns(ip, sig)
        return sig

    def test_forward_confirmed_scanner_is_a_scanner_label(self):
        sig = self.rdns("71.6.135.131", "soda.census.shodan.io", ["71.6.135.131"])
        self.assertEqual(sig.facts["label_kind"], "scanner")
        self.assertIn("Shodan", sig.facts["benign_label"])
        self.assertNotIn("spoofed_identity", sig.facts)

    def test_claim_that_does_not_resolve_back_is_forged(self):
        sig = self.rdns("45.1.1.1", "census9.shodan.io", ["198.20.69.74"])
        self.assertIn("does not resolve back", sig.facts["spoofed_identity"])
        self.assertNotIn("benign_label", sig.facts)

    def test_lookalike_domain_claims_nothing(self):
        sig = self.rdns("45.1.1.1", "crawl.googlebot.com.evil.example", ["45.1.1.1"])
        self.assertNotIn("claim", sig.facts)
        self.assertEqual(sources.claimed_identity("notshodan.io"), None)

    def test_no_ptr(self):
        sig = self.rdns("45.1.1.1", None, [])
        self.assertEqual(sig.summary, "No reverse DNS")

    def test_slow_resolver_is_a_beacon_error(self):
        sig = Signal(source="rdns", name="rdns", tier="context")
        with mock.patch.object(sources, "_resolve", side_effect=sources.FuturesTimeout()), \
             self.assertRaises(sources.BeaconError):
            sources.check_rdns("45.1.1.1", sig)

class PublishedRangeTests(unittest.TestCase):
    GOOGLE = json.dumps({"creationTime": "2026-10-29", "prefixes": [
        {"ipv4Prefix": "66.249.66.0/27"}, {"ipv6Prefix": "2001:4860:4801:10::/64"},
        {"ipv4Prefix": "10.0.0.0/8"}, {"ipv4Prefix": "not-a-range"}]}).encode()
    CENSYS = ("<p>Censys scans from:</p><code>162.142.125.0/24\n167.94.138.0/24\n167.94.145.0/24\n"
              "167.94.146.0/24\n199.45.154.0/24\n2602:80d:1003::/112\nAS398722</code>"
              "<a href='/v1.2.3.4/docs'>v1.2</a> see 1.0.0.0/8").encode()

    def test_json_feed_keeps_valid_public_ranges(self):
        self.assertEqual(sources.parse_ranges("json", self.GOOGLE),
                         ["2001:4860:4801:10::/64", "66.249.66.0/27"])   # private and junk dropped

    def test_html_page_ranges_are_validated(self):
        nets = sources.parse_ranges("html", self.CENSYS)
        self.assertIn("2602:80d:1003::/112", nets)
        self.assertNotIn("1.0.0.0/8", nets)                     # too broad for anyone to own
        self.assertEqual(len(nets), 6)

    def test_html_page_that_changed_shape_is_refused(self):
        with self.assertRaises(sources.BeaconError):
            sources.parse_ranges("html", b"<p>We moved our list to 162.142.125.0/24</p>")

    def test_membership_is_a_label(self):
        lists = {"Googlebot": ["66.249.66.0/27"], "Censys": ["162.142.125.0/24"]}
        def published(operator, fmt, url):
            if operator not in lists:
                raise sources.BeaconError("down")
            return lists[operator]
        with mock.patch.object(sources, "_published", side_effect=published):
            sig = Signal(source="published", name="p", tier="context")
            sources.check_published("162.142.125.10", sig)
            self.assertEqual(sig.facts["label_kind"], "scanner")
            self.assertIn("Censys", sig.facts["benign_label"])
            miss = Signal(source="published", name="p", tier="context")
            sources.check_published("45.1.1.1", miss)
            self.assertIn("unavailable: Bingbot", miss.summary)  # partial outage is reported, not fatal


if __name__ == "__main__":
    unittest.main()
