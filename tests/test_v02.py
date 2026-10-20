import http.server
import threading
import unittest

from perimeter_watch.secrets import scan_asset, scan_all
from perimeter_watch.alerts import build_alert, should_alert, dispatch


class LeakySite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.git/HEAD":
            self.send_response(200); self.end_headers()
            self.wfile.write(b"ref: refs/heads/main"); return
        if self.path == "/.env":
            self.send_response(403); self.end_headers(); return
        if self.path == "/":
            self.send_response(200); self.end_headers()
            self.wfile.write(b'config: AKIAIOSFODNN7EXAMPLE key, see docs'); return
        self.send_response(404); self.end_headers()

    def log_message(self, *a): pass


def setUpModule():
    global server
    server = http.server.HTTPServer(("127.0.0.1", 0), LeakySite)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def tearDownModule():
    server.shutdown()


BASE = None  # set lazily


def base_url():
    global BASE
    if BASE is None:
        BASE = f"http://127.0.0.1:{server.server_address[1]}"
    return BASE


class TestSecretScan(unittest.TestCase):
    def test_exposed_git_head_detected(self):
        findings = scan_asset(base_url())
        kinds = {f["kind"]: f for f in findings}
        self.assertIn("sensitive-file", kinds)
        self.assertIn("/.git/HEAD", kinds["sensitive-file"]["url"])

    def test_403_env_not_flagged(self):
        findings = scan_asset(base_url())
        sensitive = [f for f in findings if f["kind"] == "sensitive-file"]
        self.assertFalse(any(".env" in f["url"] for f in sensitive))

    def test_aws_key_pattern_detected(self):
        findings = scan_asset(base_url())
        secrets = [f for f in findings if f["kind"] == "secret-pattern"]
        self.assertTrue(any("AWS access key ID" in f["evidence"] for f in secrets))

    def test_excerpt_is_truncated(self):
        findings = scan_asset(base_url())
        for f in findings:
            if "excerpt" in f:
                self.assertLessEqual(len(f["excerpt"]), 26)

    def test_scan_all_shape(self):
        results = scan_all([base_url()])
        self.assertEqual(list(results), [base_url()])


class TestAlerts(unittest.TestCase):
    ALERT = {"watch": "w", "newly_dangling": [], "added": ["a.x.com"],
             "removed": [], "takeover_risks": {}, "secret_exposures": {}}

    def test_should_alert_on_changes(self):
        self.assertTrue(should_alert(self.ALERT))

    def test_no_alert_when_quiet(self):
        quiet = {"watch": "w", "newly_dangling": [], "added": [], "removed": [],
                 "takeover_risks": {}, "secret_exposures": {}}
        self.assertFalse(should_alert(quiet))

    def test_dispatch_webhook(self):
        seen = []
        fake = {"webhook": lambda url, alert, **kw: seen.append((url, alert)) or 200}
        r = dispatch(self.ALERT, {"webhook": {"url": "https://hook.test/x"}}, senders=fake)
        self.assertEqual(r["webhook"], 200)
        self.assertEqual(seen[0][1]["added"], ["a.x.com"])

    def test_dispatch_email(self):
        sent = []
        fake = {"email": lambda config, alert: sent.append((config["to"], alert))}
        dispatch(self.ALERT, {"email": {"host": "h", "port": 587, "user": "u",
                                        "password": "p", "to": "ops@x.com"}},
                 senders=fake)
        self.assertEqual(sent[0][0], "ops@x.com")


if __name__ == "__main__":
    unittest.main()
