"""Log scanner, MCP server, and web-server guards (no network: scans are stubbed)."""

import base64
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from paradox import logscan, mcp_server

LOG = """\
Oct 27 03:12:01 host sshd[811]: Failed password for root from 45.155.205.233 port 50122 ssh2
Oct 27 03:12:04 host sshd[811]: Failed password for root from 45.155.205.233 port 50130 ssh2
Oct 27 03:12:09 host sshd[812]: Accepted publickey for josh from 192.168.1.20 port 52211 ssh2
8.8.8.8 - - [27/Oct/2026:03:13:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 Chrome/120.0.6099.109"
{"src":"2606:4700:4700::1111","dst":"10.0.0.5","mac":"aa:bb:cc:dd:ee:ff","t":"12:34:56"}
[2001:db8::1]:443 documentation range, 999.1.1.1 is not an address, 1.2.3.4.5 is a version
"""


def fake_score(paradox=0.0, threat=0.0, veneer=False):
    return {"score": {
        "paradox": paradox, "paradox_label": "x", "direction": "emerging", "threat": threat,
        "threat_label": "y", "explanation": "z", "network": {"risk": 0.1},
        "veneer": {"active": veneer, "labels": ["GreyNoise benign: Example"] if veneer else []},
    }}


SCORES = {"45.155.205.233": fake_score(paradox=50, threat=0.5),
          "8.8.8.8": fake_score(),
          "2606:4700:4700::1111": fake_score(paradox=20, threat=0.3, veneer=True)}


def fake_scan(ip, use_cache=True):
    return SCORES[ip]


class ExtractTests(unittest.TestCase):
    def test_finds_public_ipv4_and_ipv6_and_skips_noise(self):
        found = logscan.extract(LOG.splitlines())
        self.assertEqual(set(found["public"]), {"45.155.205.233", "8.8.8.8", "2606:4700:4700::1111"})
        self.assertEqual(found["public"]["45.155.205.233"]["hits"], 2)
        self.assertEqual(found["public"]["45.155.205.233"]["first_line"], 1)
        # 192.168.1.20, 10.0.0.5 and the 2001:db8:: documentation address are not public
        self.assertEqual(found["private"], 3)

    def test_ip_counted_once_per_line(self):
        found = logscan.extract(["1.1.1.1 -> 1.1.1.1", "1.1.1.1"])
        self.assertEqual(found["public"]["1.1.1.1"]["hits"], 2)


class ScanLinesTests(unittest.TestCase):
    def test_ranks_veneer_then_paradox_then_quiet(self):
        res = logscan.scan_lines(LOG.splitlines(), scanner=fake_scan)
        self.assertEqual([r["ip"] for r in res["results"]],
                         ["2606:4700:4700::1111", "45.155.205.233", "8.8.8.8"])
        self.assertEqual([r["flag"] for r in res["results"]], ["veneer", "paradox", ""])
        self.assertEqual(res["summary"]["flags"]["veneer"], 1)

    def test_limit_keeps_most_active_and_errors_do_not_sink_batch(self):
        def flaky(ip, use_cache=True):
            raise RuntimeError("boom")
        res = logscan.scan_lines(LOG.splitlines(), limit=1, scanner=flaky)
        self.assertEqual(res["summary"]["scanned"], 1)
        self.assertEqual(res["summary"]["not_scanned"], 2)
        self.assertEqual(res["results"][0]["ip"], "45.155.205.233")   # 2 hits beats 1
        self.assertIn("boom", res["results"][0]["error"])

    def test_csv(self):
        out = io.StringIO()
        logscan.to_csv(logscan.scan_lines(LOG.splitlines(), scanner=fake_scan), out)
        self.assertTrue(out.getvalue().startswith("flag,ip,hits,paradox"))
        self.assertIn("GreyNoise benign: Example", out.getvalue())


def rpc(*messages):
    stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    stdout = io.StringIO()
    mcp_server.serve(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


class McpTests(unittest.TestCase):
    def test_handshake_and_tool_list(self):
        init, tools = rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("tools", init["result"]["capabilities"])
        self.assertEqual({t["name"] for t in tools["result"]["tools"]},
                         {"scan_ip", "scan_log", "ip_history", "beacon_status"})

    def test_unknown_version_gets_latest_and_unknown_method_errors(self):
        init, bad = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "1999"}},
                        {"jsonrpc": "2.0", "id": 2, "method": "nope"})
        self.assertEqual(init["result"]["protocolVersion"], mcp_server.PROTOCOL_VERSIONS[0])
        self.assertEqual(bad["error"]["code"], -32601)

    def test_invalid_ip_is_a_tool_error_not_a_crash(self):
        (r,) = rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "scan_ip", "arguments": {"ip": "10.0.0.1"}}})
        self.assertTrue(r["result"]["isError"])
        self.assertIn("private", r["result"]["content"][0]["text"])

    def test_scan_log_never_returns_log_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write(LOG)
        self.addCleanup(os.unlink, f.name)
        with mock.patch.object(logscan.engine, "scan", side_effect=fake_scan):
            (r,) = rpc({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                        "params": {"name": "scan_log", "arguments": {"path": f.name}}})
        data = r["result"]["structuredContent"]
        self.assertEqual(data["summary"]["scanned"], 3)
        self.assertNotIn("Failed password", r["result"]["content"][0]["text"])
        self.assertTrue(all("sample" not in row for row in data["results"]))

    def test_scan_log_needs_exactly_one_source(self):
        (r,) = rpc({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "scan_log", "arguments": {}}})
        self.assertTrue(r["result"]["isError"])


class ServerGuardTests(unittest.TestCase):
    def start(self, **settings):
        import server
        for k, v in settings.items():
            p = mock.patch.object(server, k, v)
            p.start()
            self.addCleanup(p.stop)
        server._hits.clear()
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(self, url, password=None):
        req = urllib.request.Request(url)
        if password:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"u:{password}".encode()).decode())
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.headers

    def test_password_guards_everything_but_healthz(self):
        base = self.start(PASSWORD="s3cret")
        self.assertEqual(self.get(base + "/healthz")[0], 200)
        status, headers = self.get(base + "/")
        self.assertEqual(status, 401)
        self.assertIn("Basic", headers["WWW-Authenticate"])
        self.assertEqual(self.get(base + "/", "wrong")[0], 401)
        status, headers = self.get(base + "/", "s3cret")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_rate_limit(self):
        base = self.start(PASSWORD=None, RATE_LIMIT=2)
        codes = [self.get(base + "/api/scan?ip=10.0.0.1")[0] for _ in range(3)]
        self.assertEqual(codes, [400, 400, 429])         # private IP: rejected before any beacon call

    def test_log_post_requires_json(self):
        base = self.start(PASSWORD=None)
        req = urllib.request.Request(base + "/api/logscan", data=b"text=1.2.3.4", method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 415)

    def test_open_bind_refused_without_password(self):
        import server
        with mock.patch.dict(os.environ, {"PARADOX_HOST": "0.0.0.0"}), \
             mock.patch.object(server, "PASSWORD", None), self.assertRaises(SystemExit):
            server.main()
        self.assertTrue(server.is_loopback("::1"))
        self.assertFalse(server.is_loopback("0.0.0.0"))


if __name__ == "__main__":
    unittest.main()
