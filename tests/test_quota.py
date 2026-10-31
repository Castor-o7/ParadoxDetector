"""PDX-30: VirusTotal stays inside its free limits (fake clock, no network)."""

import calendar
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from paradox import config, logscan, mcp_server, net, quota, scoring, sources

START = calendar.timegm((2026, 10, 31, 12, 0, 0))
BODY = {"data": {"attributes": {"last_analysis_results": {"V1": {"category": "harmless"}}}}}
VT = next(b for b in sources.BEACONS if b.id == "virustotal")


class FakeClock:
    """time.time and time.sleep for the quota module and the cache. A sleep moves the clock on,
    unless frozen, which lets threads that overlap show the wait each one was given."""

    def __init__(self, now=START):
        self.now, self.sleeps, self.frozen, self.lock = now, [], False, threading.Lock()

    def time(self):
        return self.now

    def sleep(self, seconds):
        with self.lock:
            self.sleeps.append(seconds)
            if not self.frozen:
                self.now += seconds

    def __getattr__(self, name):    # strftime, gmtime and the rest
        import time
        return getattr(time, name)


class QuotaCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.clock = FakeClock()
        self.lookups = []

        def fetch(url, **kwargs):
            self.lookups.append(self.clock.now)
            return self.answer

        self.answer = (200, BODY)
        patches = [mock.patch.object(config, "CACHE_DIR", Path(tmp.name)),
                   mock.patch.object(quota, "time", self.clock), mock.patch.object(net, "time", self.clock),
                   mock.patch.object(sources, "fetch_json", side_effect=fetch),
                   mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "set"}),
                   mock.patch.dict(net._mem, clear=True), mock.patch.dict(quota._memory, clear=True)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("PARADOX_VT_MAX_WAIT", None)
        self.cache = Path(tmp.name)

    def scan(self, ip):
        return sources.run_beacon(VT, ip)

    def assertAtMostFourAMinute(self, times):
        times = sorted(times)
        for t in times:
            self.assertLessEqual(sum(t <= x < t + 60 for x in times), 4, times)


def report(ip, use_cache=True):
    sig = sources.run_beacon(VT, ip)
    return {"ip": ip, "signals": [sig], "score": scoring.compute([sig])}


LOG = "\n".join(f"seen 45.1.1.{i}" for i in range(1, 26))


class PacingTests(QuotaCase):
    def test_batch_of_25_makes_at_most_4_lookups_a_minute_and_none_are_lost(self):
        result = logscan.scan_lines(LOG.splitlines(), workers=1, scanner=report)
        self.assertEqual(len(self.lookups), 25)
        self.assertAtMostFourAMinute(self.lookups)
        self.assertEqual((result["summary"]["paced"], result["summary"]["errors"]), (0, 0))
        self.assertEqual(self.clock.now - START, 24 * quota.SPACING)

    def test_concurrent_lookups_take_distinct_slots(self):
        self.clock.frozen = True
        barrier = threading.Barrier(4)

        def one(i):
            barrier.wait()
            self.scan(f"45.2.2.{i}")

        threads = [threading.Thread(target=one, args=(i,)) for i in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(self.clock.sleeps), [15, 30, 45])
        state = json.loads((self.cache / "virustotal_quota.json").read_text())
        self.assertEqual(state["day_used"], 4)

    def test_too_long_a_wait_is_skipped_and_the_report_says_so(self):
        with mock.patch.dict(os.environ, {"PARADOX_VT_MAX_WAIT": "0"}):
            result = logscan.scan_lines(LOG.splitlines(), workers=1, scanner=report)
        self.assertEqual(len(self.lookups), 1)
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(result["summary"]["paced"], 24)
        self.assertEqual(sum(bool(r["paced"]) for r in result["results"]), 24)
        text = logscan.render(result)
        self.assertIn("24 IPs got no VirusTotal lookup", text)
        self.assertEqual(text.count(" *\n"), 24)
        out = io.StringIO()
        logscan.to_csv(result, out)
        self.assertIn(VT.name, out.getvalue())
        self.assertEqual(mcp_server.redact_log(result)["results"][0].get("paced"),
                         result["results"][0]["paced"])

    def test_a_skipped_ip_lists_virustotal_as_missing_with_the_reason(self):
        self.scan("45.3.3.1")
        with mock.patch.dict(os.environ, {"PARADOX_VT_MAX_WAIT": "0"}):
            sig = self.scan("45.3.3.2")
        self.assertEqual((sig.status, sig.failure), ("error", "paced"))
        self.assertIn("pacing to 4 a minute", sig.summary)
        self.assertIsNone(sig.threat)
        (missing,) = scoring.compute([sig])["missing"]
        self.assertEqual(missing["failure"], "paced")
        self.assertIn("vendor consensus", missing["cost"])

    def test_a_skipped_lookup_spends_no_quota_or_slot(self):
        self.scan("45.3.3.1")
        with mock.patch.dict(os.environ, {"PARADOX_VT_MAX_WAIT": "0"}):
            self.scan("45.3.3.2")
        state = json.loads((self.cache / "virustotal_quota.json").read_text())
        self.assertEqual((state["day_used"], state["next_slot"]), (1, START + quota.SPACING))


class CacheTests(QuotaCase):
    def test_repeat_inside_the_window_uses_no_quota(self):
        first, second = self.scan("45.4.4.1"), self.scan("45.4.4.1")
        self.assertEqual(len(self.lookups), 1)
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual((first.status, second.status), ("ok", "ok"))
        self.assertEqual(second.summary, first.summary)

    def test_repeat_survives_a_restart(self):
        self.scan("45.4.4.1")
        net._mem.clear()
        os.utime(self.cache / "virustotal_45.4.4.1.json", (self.clock.now, self.clock.now))
        self.scan("45.4.4.1")
        self.assertEqual(len(self.lookups), 1)

    def test_lookup_returns_after_the_window(self):
        self.scan("45.4.4.1")
        self.clock.now += sources.VT_CACHE_SECONDS + 1
        os.utime(self.cache / "virustotal_45.4.4.1.json", (self.clock.now - sources.VT_CACHE_SECONDS - 1,) * 2)
        self.scan("45.4.4.1")
        self.assertEqual(len(self.lookups), 2)

    def test_failed_lookup_is_not_cached_but_counts(self):
        self.answer = (429, {})
        sig = self.scan("45.4.4.1")
        self.assertEqual(sig.failure, "rate_limited")
        self.answer = (200, BODY)
        self.clock.now += quota.SPACING
        self.assertEqual(self.scan("45.4.4.1").status, "ok")
        self.assertEqual(len(self.lookups), 2)
        self.assertEqual(json.loads((self.cache / "virustotal_quota.json").read_text())["day_used"], 2)

    def test_ipv6_gets_a_usable_cache_name(self):
        self.assertEqual(self.scan("2606:4700::1").status, "ok")
        self.assertTrue((self.cache / "virustotal_2606_4700__1.json").exists())


class AllowanceTests(QuotaCase):
    def ledger(self, **state):
        (self.cache / "virustotal_quota.json").write_text(json.dumps(state))

    def test_day_allowance_stops_lookups_until_the_next_utc_day(self):
        self.ledger(day="2026-10-31", day_used=500, month="2026-10", month_used=500)
        sig = self.scan("45.5.5.1")
        self.assertEqual(sig.failure, "paced")
        self.assertIn("500 lookups", sig.summary)
        self.assertEqual(self.lookups, [])
        self.clock.now = calendar.timegm((2026, 11, 1, 0, 0, 1))
        self.assertEqual(self.scan("45.5.5.1").status, "ok")

    def test_month_allowance_stops_lookups_until_the_next_month(self):
        self.ledger(day="2026-10-30", day_used=500, month="2026-10", month_used=15_500)
        self.assertIn("15500 lookups", self.scan("45.5.5.1").summary)
        self.clock.now = calendar.timegm((2026, 11, 1, 0, 0, 1))
        self.assertEqual(self.scan("45.5.5.1").status, "ok")

    def test_ledger_survives_a_new_process_view(self):
        self.scan("45.5.5.1")
        quota._memory.clear()
        with mock.patch.dict(os.environ, {"PARADOX_VT_MAX_WAIT": "0"}):
            self.assertEqual(self.scan("45.5.5.2").failure, "paced")

    def test_corrupt_ledger_starts_over_instead_of_failing(self):
        (self.cache / "virustotal_quota.json").write_text("{not json")
        self.assertEqual(self.scan("45.5.5.1").status, "ok")


if __name__ == "__main__":
    unittest.main()
