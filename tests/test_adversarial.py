"""PDX-15: attack the scoring on purpose and pin how far each attack moves the score.

Fixtures are synthetic and everything runs offline, through the real OTX parser, reverse
DNS check and scorer. These numbers say what today's rules do, not what a real attacker
would manage. "Guarantee" tests are protections that must keep holding. "Known weakness"
tests pin attacks that work today, with the story that covers them, so a fix or a
regression has to change the number on purpose.
"""

import socket
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from paradox import sources
from paradox.scoring import compute
from paradox.sources import Signal, apply_otx

IP = "45.1.1.1"
NOW = datetime.now(timezone.utc)
RECENT = (NOW - timedelta(days=1)).date().isoformat()
VALIDATION = [{"name": "Majestic", "source": "majestic"}]


def pulse(author, **fields):
    return {"author": {"username": author}, "name": "attack campaign", "tags": ["c2"], "modified": NOW.isoformat(),
            "indicator_type_counts": {"IPv4": 20}, **fields}


def accounts(n, **fields):
    return [pulse(f"account{i}", **fields) for i in range(n)]


def otx(pulses=(), validation=()):
    sig = Signal("otx", "OTX", "fast")
    apply_otx(IP, sig, {"pulse_info": {"pulses": list(pulses), "count": len(pulses)}, "validation": list(validation)})
    return sig


def clean(**over):
    """Every other beacon reads clean, unless replaced."""
    beacons = {"greynoise": Signal("greynoise", "GreyNoise", "fast", threat=0.0, confidence=0.6),
               "abuseipdb": Signal("abuseipdb", "AbuseIPDB", "fast", threat=0.0, confidence=0.8),
               "spamhaus": Signal("spamhaus", "Spamhaus", "slow", threat=0.0, confidence=0.5),
               "virustotal": Signal("virustotal", "VirusTotal", "slow", threat=0.0, confidence=0.8),
               "internetdb": Signal("internetdb", "InternetDB", "slow", threat=0.0, confidence=0.5)}
    return list({**beacons, **over}.values())


def malicious():
    """Independent beacons that agree an IP is bad."""
    return {"abuseipdb": Signal("abuseipdb", "AbuseIPDB", "fast", threat=0.9, confidence=0.8, last_seen=RECENT,
                                facts={"reporters": 50}),
            "virustotal": Signal("virustotal", "VirusTotal", "slow", threat=0.8, confidence=0.8, last_seen=RECENT),
            "spamhaus": Signal("spamhaus", "Spamhaus", "slow", threat=1.0, confidence=0.95, facts={"current": True})}


def benign_greynoise():
    return Signal("greynoise", "GreyNoise", "fast", threat=0.0, confidence=0.6,
                  facts={"benign_label": "Google Public DNS", "label_kind": "infrastructure"})


def score(signal, *others, **over):
    return compute([signal, *clean(**over), *others], now=NOW)


class AttackCase(unittest.TestCase):
    def assertScore(self, result, paradox, threat):
        self.assertAlmostEqual(result["paradox"], paradox, delta=0.5)
        self.assertAlmostEqual(result["threat"], threat, delta=0.01)


class SmearingTests(AttackCase):
    """A burst of OTX pulses against an innocent IP."""

    def test_guarantee_one_account_gets_one_vote(self):
        one, flood = score(otx(accounts(1))), score(otx([pulse("account0") for _ in range(100)]))
        self.assertEqual((flood["paradox"], flood["threat"]), (one["paradox"], one["threat"]))
        self.assertEqual(flood["threat_label"], "Likely benign")

    def test_guarantee_old_pulses_fade(self):
        old = (NOW - timedelta(days=200)).isoformat()
        result = score(otx(accounts(10, modified=old)))
        self.assertEqual((result["paradox_label"], result["threat_label"]), ("Coherent", "Likely benign"))

    def test_known_weakness_new_accounts_can_condemn_a_clean_ip(self):
        """PDX-38. Anyone can open OTX accounts, and five flip a clean IP to Likely malicious."""
        for n, paradox, threat, threat_label in ((1, 18.9, 0.11, "Likely benign"), (2, 33.6, 0.195, "Suspicious"),
                                                 (3, 44.9, 0.26, "Suspicious"), (5, 60.3, 0.689, "Likely malicious"),
                                                 (10, 72.4, 0.819, "Malicious"), (100, 75.1, 0.85, "Malicious")):
            result = score(otx(accounts(n)))
            self.assertScore(result, paradox, threat)
            self.assertEqual(result["threat_label"], threat_label, n)
            self.assertEqual(result["direction"], "emerging")

    def test_known_weakness_the_contacted_discount_doesnt_stop_it(self):
        """PDX-38. Sock puppets pick their own pulse contents, so half weight only asks for more of them."""
        result = score(otx(accounts(10, indicator_type_counts={"FileHash-MD5": 20, "IPv4": 1})))
        self.assertScore(result, 60.9, 0.689)


class LaunderingTests(AttackCase):
    """A malicious IP acquires a whitelist entry or a benign label."""

    def test_guarantee_a_label_cant_clear_independent_evidence(self):
        bare = score(otx(accounts(10)), **malicious())
        self.assertScore(bare, 16.0, 0.87)
        self.assertFalse(bare["veneer"]["active"])
        for name, result, paradox in (
                ("OTX whitelist", score(otx(accounts(10), VALIDATION), **malicious()), 49.6),
                ("GreyNoise label", score(otx(accounts(10)), **{**malicious(), "greynoise": benign_greynoise()}), 37.5),
                ("both", score(otx(accounts(10), VALIDATION), **{**malicious(), "greynoise": benign_greynoise()}), 47.2)):
            with self.subTest(name):
                self.assertEqual(result["threat_label"], "Malicious")
                self.assertTrue(result["veneer"]["active"])
                self.assertAlmostEqual(result["paradox"], paradox, delta=0.5)

    def test_guarantee_another_beacons_label_cant_clear_otx(self):
        result = score(otx(accounts(10)), greynoise=benign_greynoise())
        self.assertScore(result, 98.8, 0.819)
        self.assertTrue(result["veneer"]["active"])

    def test_guarantee_otx_whitelist_doesnt_clear_other_beacons(self):
        result = score(otx((), VALIDATION), abuseipdb=malicious()["abuseipdb"])
        self.assertScore(result, 93.1, 0.765)
        self.assertTrue(result["veneer"]["active"])

    def test_guarantee_a_label_isnt_contradicted_by_its_own_origin(self):
        """Feodo and ThreatFox are both abuse.ch: one source disagreeing with itself isn't independent evidence."""
        label = Signal("feodo", "Feodo", "fast", threat=0.0, confidence=0.9, facts={"benign_label": "abuse.ch vouched"})
        hit = Signal("threatfox", "ThreatFox", "fast", threat=0.9, confidence=0.9, last_seen=RECENT)
        self.assertFalse(score(otx(), label, hit)["veneer"]["active"])
        outside = Signal("virustotal", "VirusTotal", "slow", threat=0.9, confidence=0.8, last_seen=RECENT)
        self.assertTrue(score(otx(), label, virustotal=outside)["veneer"]["active"])

    def test_guarantee_stale_evidence_cant_contradict_a_label(self):
        """An old report shouldn't paint a label as borrowed; only fresh or live evidence can."""
        old = (NOW - timedelta(days=200)).date().isoformat()
        hit = Signal("virustotal", "VirusTotal", "slow", threat=0.9, confidence=0.8, last_seen=old)
        self.assertFalse(score(otx(), greynoise=benign_greynoise(), virustotal=hit)["veneer"]["active"])
        hit = Signal("virustotal", "VirusTotal", "slow", threat=0.9, confidence=0.8, last_seen=RECENT)
        self.assertTrue(score(otx(), greynoise=benign_greynoise(), virustotal=hit)["veneer"]["active"])

    def test_known_weakness_otx_whitelist_clears_otx_only_evidence(self):
        """PDX-39. When OTX is the only witness, its own whitelist entry drops it from Severe paradox and Malicious
        to Coherent and Suspicious, and no veneer fires, because a label can't be contradicted by its own origin."""
        bare, laundered = score(otx(accounts(10))), score(otx(accounts(10), VALIDATION))
        self.assertScore(bare, 72.4, 0.819)
        self.assertScore(laundered, 14.5, 0.164)
        self.assertEqual((laundered["paradox_label"], laundered["threat_label"]), ("Coherent", "Suspicious"))
        self.assertFalse(laundered["veneer"]["active"])


class DilutionTests(AttackCase):
    """Padding pulses to trigger the specificity discount."""

    def test_guarantee_padded_pulses_cant_weaken_someone_elses_report(self):
        honest = accounts(5)
        padded = [pulse(f"padder{i}", indicator_count=200_000) for i in range(100)]
        before, after = score(otx(honest)), score(otx(honest + padded))
        self.assertGreaterEqual(after["threat"], before["threat"])
        self.assertGreaterEqual(after["paradox"], before["paradox"])

    def test_guarantee_an_author_padding_a_second_pulse_keeps_their_best(self):
        before = score(otx(accounts(5)))
        after = score(otx(accounts(5) + accounts(5, indicator_count=200_000)))
        self.assertEqual((after["paradox"], after["threat"]), (before["paradox"], before["threat"]))

    def test_guarantee_padding_cant_clear_independent_evidence(self):
        for size in (20_000, 200_000):
            result = score(otx(accounts(10, indicator_count=size)), **malicious())
            self.assertEqual(result["threat_label"], "Malicious", size)

    def test_known_weakness_padding_hides_otx_only_evidence(self):
        """PDX-40. If every pulse naming an IP is huge, OTX-only evidence fades to Likely benign. That's the discount
        working on sandbox dumps, and also what an attacker gets if the only reports are ones it padded."""
        for size, paradox, threat, threat_label in ((1_000, 60.3, 0.689, "Likely malicious"),
                                                    (3_000, 38.6, 0.441, "Likely malicious"),
                                                    (20_000, 12.1, 0.138, "Likely benign"),
                                                    (200_000, 2.3, 0.026, "Likely benign")):
            result = score(otx(accounts(5, indicator_count=size)))
            self.assertScore(result, paradox, threat)
            self.assertEqual(result["threat_label"], threat_label, size)

    def test_test_names_and_clones_count_for_less(self):
        for fields in ({"name": "test"}, {"cloned_from": "x"}):
            self.assertScore(score(otx(accounts(5, **fields))), 29.2, 0.334)


class LabelSpoofingTests(AttackCase):
    """A fake PTR record, through the real reverse DNS check."""

    def rdns(self, ptr, forward):
        sig = Signal("rdns", "Reverse DNS", "context")
        with mock.patch.object(sources.socket, "gethostbyaddr", return_value=(ptr, [], [IP])), \
                mock.patch.object(sources.socket, "getaddrinfo",
                                  return_value=[(socket.AF_INET, 1, 6, "", (a, 0)) for a in forward]):
            sources.check_rdns(IP, sig)
        return sig

    def test_guarantee_a_forged_ptr_earns_no_label_and_costs_the_forger(self):
        forged = self.rdns("census9.shodan.io", ["198.20.69.74"])
        self.assertNotIn("benign_label", forged.facts)
        result = score(otx(), forged)
        self.assertScore(result, 15.0, 0.30)
        self.assertTrue(result["veneer"]["active"])
        self.assertEqual(result["threat_label"], "Suspicious")

    def test_guarantee_a_forged_ptr_doesnt_lower_a_malicious_ip(self):
        bare = score(otx(accounts(10)), **malicious())
        forged = score(otx(accounts(10)), self.rdns("census9.shodan.io", ["198.20.69.74"]), **malicious())
        self.assertGreaterEqual(forged["threat"], bare["threat"])
        self.assertGreater(forged["paradox"], bare["paradox"])
        self.assertTrue(forged["veneer"]["active"])

    def test_guarantee_a_lookalike_domain_claims_nothing(self):
        sig = self.rdns("crawl.googlebot.com.evil.example", [IP])
        self.assertNotIn("benign_label", sig.facts)
        self.assertNotIn("claim", sig.facts)

    def test_guarantee_a_real_label_cant_clear_a_malicious_ip(self):
        label = Signal("rdns", "Reverse DNS", "context", facts={"benign_label": "Shodan", "label_kind": "scanner"})
        result = score(otx(accounts(10)), label, **malicious())
        self.assertEqual(result["threat_label"], "Malicious")
        self.assertTrue(result["veneer"]["active"])


if __name__ == "__main__":
    unittest.main()
