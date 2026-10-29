"""Beacon parsers against real (trimmed) API responses in tests/fixtures.

If a provider changes its response format, these fail before the scores
silently drift.
"""

import json
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

if __name__ == "__main__":
    unittest.main()
