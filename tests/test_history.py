import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from paradox import history


def report(ip, when, fast_threat, slow_threat):
    signals = [
        {"source": "feodo", "name": "Feodo", "tier": "fast", "status": "ok",
         "threat": fast_threat, "confidence": 0.9},
        {"source": "spamhaus", "name": "DROP", "tier": "slow", "status": "ok",
         "threat": slow_threat, "confidence": 0.95},
        {"source": "rdap", "name": "RDAP", "tier": "context", "status": "ok",
         "threat": None, "confidence": 0.0},
    ]
    return {"ip": ip, "scanned_at": when, "signals": signals,
            "score": {"paradox": 50.0, "threat": 0.5, "direction": "emerging",
                      "fast": {"score": fast_threat}, "slow": {"score": slow_threat},
                      "veneer": {"active": False}}}


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(history, "DB_PATH", Path(self.tmp.name) / "h.sqlite3")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_lag_measures_fast_to_slow_catch_up(self):
        history.record(report("203.0.113.5", "2026-10-01T00:00:00+00:00", 0.0, 0.0))
        history.record(report("203.0.113.5", "2026-10-03T00:00:00+00:00", 0.95, 0.0))
        history.record(report("203.0.113.5", "2026-10-10T12:00:00+00:00", 0.95, 1.0))
        lag = history.lag("203.0.113.5")
        self.assertEqual(lag["scans"], 3)
        self.assertEqual(lag["first_fast_flag"], "2026-10-03T00:00:00+00:00")
        self.assertEqual(lag["lag_days"], 7.5)
        self.assertEqual([b["name"] for b in lag["beacons"]], ["Feodo", "DROP"])

    def test_open_paradox_reports_days_waiting(self):
        history.record(report("203.0.113.6", "2026-10-20T00:00:00+00:00", 0.95, 0.0))
        lag = history.lag("203.0.113.6", now=datetime(2026, 10, 27, tzinfo=timezone.utc))
        self.assertIsNone(lag["lag_days"])
        self.assertEqual(lag["open_days"], 7.0)

    def test_scans_and_tracked_are_per_ip_and_ordered(self):
        history.record(report("203.0.113.7", "2026-10-02T00:00:00+00:00", 0.1, 0.0))
        history.record(report("203.0.113.7", "2026-10-01T00:00:00+00:00", 0.2, 0.0))
        history.record(report("198.51.100.1", "2026-10-05T00:00:00+00:00", 0.3, 0.0))
        self.assertEqual([s["fast"] for s in history.scans("203.0.113.7")], [0.2, 0.1])
        tracked = history.tracked()
        self.assertEqual([t["ip"] for t in tracked], ["198.51.100.1", "203.0.113.7"])
        self.assertEqual(tracked[1]["scans"], 2)


if __name__ == "__main__":
    unittest.main()
