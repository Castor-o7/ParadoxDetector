"""The `paradox` command and the headless watcher (scans are stubbed)."""

import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from paradox import cli, config, watch

from test_batch import fake_score


class LegacyCliTests(unittest.TestCase):
    def test_old_invocations_still_work(self):
        self.assertEqual(cli.legacy(["45.1.1.1", "--json"]), ["scan", "45.1.1.1", "--json"])
        self.assertEqual(cli.legacy(["--log", "a.log", "--csv"]), ["log", "a.log", "--csv"])
        self.assertEqual(cli.legacy(["1.1.1.1", "--history"]), ["history", "1.1.1.1"])
        self.assertEqual(cli.legacy(["--rescan-tracked"]), ["rescan"])
        self.assertEqual(cli.legacy(["scan", "1.1.1.1"]), ["scan", "1.1.1.1"])
        self.assertEqual(cli.legacy([]), [])          # -> app

    def test_every_command_parses(self):
        p = cli.parser()
        for argv in (["app", "--no-browser"], ["serve", "--port", "9"], ["scan", "1.1.1.1", "8.8.8.8"],
                     ["log", "-", "--csv"], ["watch", "--log", "a", "--log", "b", "--json"],
                     ["history", "1.1.1.1"], ["rescan"], ["mcp"], ["calibrate"],
                     ["beacons"], ["init"], ["where"]):
            self.assertTrue(callable(p.parse_args(argv).func), argv)

    def watch_webhook(self, *argv, env=None):
        with mock.patch.dict(os.environ, env or {}), mock.patch.object(watch, "Watcher") as w:
            os.environ.pop("PARADOX_WEBHOOK", None) if env is None else None
            w.return_value.run.return_value = 0
            cli.main(["watch", "--log", "a", *argv])
        return w.call_args.kwargs["webhook"]

    def test_webhook_url_comes_from_the_environment_and_the_flag_wins(self):
        env = {"PARADOX_WEBHOOK": "https://example.test/env"}
        self.assertEqual(self.watch_webhook(env=env), "https://example.test/env")
        self.assertEqual(self.watch_webhook("--webhook", "https://example.test/flag", env=env), "https://example.test/flag")
        self.assertIsNone(self.watch_webhook())

    def test_webhook_schemes(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("PARADOX_WEBHOOK_ALLOW_HTTP", None)
            for ok in ("https://example.test/x", "http://localhost:9/x", "http://127.0.0.1:9/x", "http://[::1]:9/x"):
                self.assertIsNone(watch.webhook_problem(ok), ok)
            for bad in ("http://example.test/secret", "http://127.0.0.1.example.test/secret", "file:///etc/secret",
                        "ftp://example.test/secret", "https:///secret", "secret"):
                problem = watch.webhook_problem(bad)
                self.assertTrue(problem, bad)
                self.assertNotIn("secret", problem)
            os.environ["PARADOX_WEBHOOK_ALLOW_HTTP"] = "1"
            self.assertIsNone(watch.webhook_problem("http://example.test/x"))
            self.assertTrue(watch.webhook_problem("file:///etc/secret"))    # the override is for http only

    def test_watcher_wont_start_with_an_unencrypted_webhook(self):
        with mock.patch.dict(os.environ, {"PARADOX_WEBHOOK": "http://example.test/secret"}), \
                mock.patch.object(watch, "Watcher") as w, mock.patch("sys.stderr", io.StringIO()) as err:
            os.environ.pop("PARADOX_WEBHOOK_ALLOW_HTTP", None)
            self.assertEqual(cli.main(["watch", "--log", "a"]), 2)
        w.assert_not_called()
        self.assertIn("unencrypted", err.getvalue())
        self.assertNotIn("secret", err.getvalue())

    def test_scan_exit_status_reflects_findings(self):
        def run(score):
            with mock.patch.object(cli, "scan", return_value={"ip": "45.1.1.1", "score": score}), \
                 mock.patch.object(cli, "render", return_value=""), \
                 mock.patch("sys.stdout", io.StringIO()):
                return cli.main(["scan", "45.1.1.1"])
        self.assertEqual(run(fake_score(paradox=50, threat=0.5)["score"]), 1)
        self.assertEqual(run(fake_score()["score"]), 0)
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(cli.main(["scan", "10.0.0.1"]), 2)

    def test_init_writes_a_private_keys_file_once(self):
        with tempfile.TemporaryDirectory() as home:
            env = Path(home) / "nested" / ".env"
            with mock.patch.object(config, "ENV_FILE", env), mock.patch("sys.stdout", io.StringIO()):
                cli.main(["init"])
                env.write_text("ABUSEIPDB_API_KEY=keep-me\n")
                cli.main(["init"])                      # must not overwrite
            self.assertEqual(env.read_text(), "ABUSEIPDB_API_KEY=keep-me\n")
            self.assertEqual(env.stat().st_mode & 0o777, 0o600)


class FollowTests(unittest.TestCase):
    def test_follows_appends_rotation_truncation_and_partial_lines(self):
        stop = threading.Event()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "app.log")
            Path(path).write_text("old line, skipped\n")
            got = []
            lines = watch.follow(path, stop, poll=0.01)

            def take(n):
                for _ in range(n):
                    got.append(next(lines))

            with open(path, "a") as f:
                f.write("one\ntw")                       # "tw" is half-written
            take(1)
            with open(path, "a") as f:
                f.write("o\n")
            take(1)
            os.rename(path, path + ".1")                 # logrotate
            Path(path).write_text("three\n")
            take(1)
            Path(path).write_text("")                    # truncate in place...
            with open(path, "a") as f:
                f.write("four\n")                        # ...then keep writing
            take(1)
            stop.set()
        self.assertEqual(got, ["one\n", "two\n", "three\n", "four\n"])


class WatcherTests(unittest.TestCase):
    def watcher(self, scores, **kw):
        calls = []

        def scanner(ip, use_cache=True):
            calls.append(ip)
            return scores[ip]
        out = io.StringIO()
        w = watch.Watcher(scanner=scanner, out=out, as_json=True, **kw)
        return w, calls, out

    def test_scans_once_and_alerts_on_flagged_ips_only(self):
        w, calls, out = self.watcher({"45.1.1.1": fake_score(paradox=50, threat=0.5), "8.8.8.8": fake_score()})
        for line in ["fail from 45.1.1.1", "fail from 45.1.1.1", "dns 8.8.8.8", "lan 192.168.0.9"]:
            w.feed(line, "auth.log")
        while not w.q.empty():
            ip = w.q.get()
            w.check(ip)
            w.pending.discard(ip)
        w.feed("again 45.1.1.1", "auth.log")              # within --rescan-after: no new scan
        self.assertEqual(calls, ["45.1.1.1", "8.8.8.8"])
        alerts = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([a["alert"]["ip"] for a in alerts], ["45.1.1.1"])
        self.assertIn("PARADOX 45.1.1.1", alerts[0]["text"])
        self.assertEqual(w.seen["45.1.1.1"]["hits"], 3)

    def test_webhook_gets_no_log_line_but_stdout_keeps_it(self):
        w, _, out = self.watcher({"45.1.1.1": fake_score(paradox=50, threat=0.5)}, webhook="https://example.test/x")
        w.feed("Failed password for token-s3cret from 45.1.1.1", "auth.log")
        posted, sent = [], threading.Event()

        def urlopen(req, timeout=None):
            posted.append(req.data.decode())
            sent.set()
            return mock.MagicMock()

        with mock.patch("urllib.request.urlopen", urlopen):
            w.check(w.q.get())
            self.assertTrue(sent.wait(5))
        self.assertNotIn("s3cret", posted[0])
        body = json.loads(posted[0])
        self.assertNotIn("sample", body["alert"])
        self.assertEqual(body["alert"]["ip"], "45.1.1.1")
        self.assertIn("PARADOX 45.1.1.1", body["text"])
        self.assertIn("s3cret", json.loads(out.getvalue())["alert"]["sample"])

    def test_new_ip_cap_stops_a_flood_and_recovers(self):
        w, _, _ = self.watcher({}, max_new_per_hour=3)
        with mock.patch("paradox.watch.time.time", return_value=1_800_000_000.0) as clock, \
                mock.patch("sys.stderr", io.StringIO()) as err:
            for i in range(1, 101):
                w.feed(f"forged 45.1.1.{i}", "x")
            self.assertEqual(w.q.qsize(), 3)
            self.assertEqual(w.stats["capped"], 97)
            self.assertEqual(err.getvalue().count("the limit"), 1)
            clock.return_value = 1_800_000_000.0 + 3599
            w.feed("real 45.1.1.50", "x")
            self.assertEqual(w.q.qsize(), 3)                  # still inside the hour
            clock.return_value = 1_800_000_000.0 + 3600
            w.feed("real 45.1.1.50", "x")                     # seen again later: gets its turn
            self.assertEqual(w.q.qsize(), 4)
            self.assertIn("45.1.1.50", w.pending)

    def test_new_ip_cap_doesnt_count_or_block_rescans(self):
        w, _, _ = self.watcher({}, max_new_per_hour=1, rescan_after_h=0)
        w.last_scan.update({"45.1.1.1": 0.0, "45.1.1.2": 0.0})
        w.feed("45.1.1.1 45.1.1.2", "x")
        self.assertEqual((w.q.qsize(), w.stats["capped"], len(w.new_scans)), (2, 0, 0))

    def test_new_ip_cap_of_zero_is_off(self):
        w, _, _ = self.watcher({}, max_new_per_hour=0)
        for i in range(1, 51):
            w.feed(f"45.1.1.{i}", "x")
        self.assertEqual((w.q.qsize(), w.stats["capped"]), (50, 0))

    def test_min_hits_and_flag_change_alerts(self):
        scores = {"45.1.1.1": fake_score(paradox=50, threat=0.5)}
        w, calls, out = self.watcher(scores, min_hits=2)
        w.feed("45.1.1.1", "x")
        self.assertEqual(w.q.qsize(), 0)                  # not yet
        w.feed("45.1.1.1", "x")
        self.assertEqual(w.q.qsize(), 1)
        w.check(w.q.get())
        w.check("45.1.1.1")                               # same flag again: no repeat alert
        scores["45.1.1.1"] = fake_score(paradox=20, threat=0.3, veneer=True)
        w.check("45.1.1.1")                               # flag changed to veneer: alert
        flags = [json.loads(line)["alert"]["flag"] for line in out.getvalue().splitlines()]
        self.assertEqual(flags, ["paradox", "veneer"])

    def test_piped_input_runs_to_completion(self):
        scores = {"45.1.1.1": fake_score(paradox=50, threat=0.5)}
        w, calls, out = self.watcher(scores)
        with mock.patch("sys.stdin", io.StringIO("x 45.1.1.1\ny 45.1.1.1\n")), \
             mock.patch("sys.stderr", io.StringIO()), mock.patch("signal.signal"):
            status = w.run(["-"])
        self.assertEqual(status, 1)
        self.assertEqual(calls, ["45.1.1.1"])


if __name__ == "__main__":
    unittest.main()
