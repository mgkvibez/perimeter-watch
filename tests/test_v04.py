"""v0.4: multi-domain scheduling, scan-due, and delta alert digests (offline)."""
import datetime as dt
import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from perimeter_watch.scheduling import (
    parse_watchlist_domains,
    get_domain_due_status,
    evaluate_due_domains,
)
from perimeter_watch.alerts import (
    build_alert,
    build_digest_alert,
    get_digest_config,
    dispatch,
    send_email,
)
from perimeter_watch import __main__ as cli


class TestScheduling(unittest.TestCase):
    def test_parse_watchlist_domains_strings_and_dicts(self):
        wl = {
            "domains": [
                "plain.com",
                {"domain": "custom.com", "interval_days": 3},
                {"name": "named.com", "interval_days": 14},
            ],
            "default_interval_days": 7,
        }
        parsed = parse_watchlist_domains(wl)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], {"name": "plain.com", "interval_days": 7.0})
        self.assertEqual(parsed[1], {"name": "custom.com", "interval_days": 3.0})
        self.assertEqual(parsed[2], {"name": "named.com", "interval_days": 14.0})

    def test_get_domain_due_status_never_scanned(self):
        cfg = {"name": "a.com", "interval_days": 7.0}
        due, reason, elapsed = get_domain_due_status(cfg, None)
        self.assertTrue(due)
        self.assertIn("never scanned before", reason)
        self.assertIsNone(elapsed)

    def test_get_domain_due_status_not_due(self):
        cfg = {"name": "a.com", "interval_days": 7.0}
        now = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
        last_scanned = (now - dt.timedelta(days=2)).isoformat()
        due, reason, elapsed = get_domain_due_status(cfg, last_scanned, now=now)
        self.assertFalse(due)
        self.assertIn("due in 5.0d", reason)
        self.assertAlmostEqual(elapsed, 2.0, places=2)

    def test_get_domain_due_status_due(self):
        cfg = {"name": "a.com", "interval_days": 7.0}
        now = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
        last_scanned = (now - dt.timedelta(days=8)).isoformat()
        due, reason, elapsed = get_domain_due_status(cfg, last_scanned, now=now)
        self.assertTrue(due)
        self.assertIn("8.0d ago >= 7d interval", reason)

    def test_get_domain_due_status_invalid_and_future_ts(self):
        cfg = {"name": "a.com", "interval_days": 7.0}
        now = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
        due1, reason1, _ = get_domain_due_status(cfg, "invalid-date", now=now)
        self.assertTrue(due1)
        self.assertIn("invalid last_scanned timestamp", reason1)

        future_scanned = (now + dt.timedelta(days=1)).isoformat()
        due2, reason2, _ = get_domain_due_status(cfg, future_scanned, now=now)
        self.assertTrue(due2)
        self.assertIn("in future", reason2)

    def test_evaluate_due_domains(self):
        wl = {
            "domains": [
                {"name": "due.com", "interval_days": 1},
                {"name": "ok.com", "interval_days": 10},
            ]
        }
        now = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
        last_scanned = {
            "due.com": (now - dt.timedelta(days=2)).isoformat(),
            "ok.com": (now - dt.timedelta(days=2)).isoformat(),
        }
        evals = evaluate_due_domains(wl, last_scanned, now=now)
        self.assertEqual(len(evals), 2)
        ev_map = {e["name"]: e for e in evals}
        self.assertTrue(ev_map["due.com"]["due"])
        self.assertFalse(ev_map["ok.com"]["due"])


class TestScanDueAndRun(unittest.TestCase):
    def test_scan_due_only_filters_scans(self):
        scanned_domains = []

        def fake_enum(domain):
            scanned_domains.append(domain)
            return [f"sub.{domain}"]

        def fake_resolve(names):
            return {n: {"name": n, "aliases": [], "ips": ["1.1.1.1"]} for n in names}

        now = dt.datetime(2026, 10, 27, 12, 0, 0, tzinfo=dt.timezone.utc)
        two_days_ago = (now - dt.timedelta(days=2)).isoformat()

        wl = {
            "domains": [
                {"name": "due.com", "interval_days": 1},
                {"name": "ok.com", "interval_days": 10},
            ]
        }

        with tempfile.TemporaryDirectory() as td:
            state_file = Path(td) / "state.json"
            # seed state with last scanned times
            initial_state = {
                "captured_at": two_days_ago,
                "domains": {
                    "due.com": {"sub.due.com": {"name": "sub.due.com", "aliases": [], "ips": ["1.1.1.1"]}},
                    "ok.com": {"sub.ok.com": {"name": "sub.ok.com", "aliases": [], "ips": ["1.1.1.1"]}},
                },
                "last_scanned": {
                    "due.com": two_days_ago,
                    "ok.com": two_days_ago,
                }
            }
            state_file.write_text(json.dumps(initial_state), encoding="utf-8")

            report, risks, errors, _, _, _ = cli.run(
                wl,
                state_file,
                enum_fn=fake_enum,
                resolve_fn=fake_resolve,
                scan_due_only=True,
                now_fn=now,
            )

            self.assertEqual(scanned_domains, ["due.com"])
            # State file should have updated last_scanned for due.com, kept ok.com
            updated_state = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(updated_state["last_scanned"]["due.com"], now.isoformat(timespec="seconds"))
            self.assertEqual(updated_state["last_scanned"]["ok.com"], two_days_ago)


class TestDigest(unittest.TestCase):
    def test_get_digest_config(self):
        # watchlist bool
        e, t = get_digest_config({"digest": True})
        self.assertTrue(e)
        self.assertEqual(t, 1)

        # watchlist dict
        e, t = get_digest_config({"digest": {"enabled": True, "threshold": 3}})
        self.assertTrue(e)
        self.assertEqual(t, 3)

        # cli overrides
        e, t = get_digest_config({"digest": False}, cli_digest=True, cli_threshold=5)
        self.assertTrue(e)
        self.assertEqual(t, 5)

    def test_build_digest_alert(self):
        payloads = {
            "b.com": {
                "watch": "b.com",
                "added": ["sub.b.com"],
                "takeover_risks": {},
                "secret_exposures": {},
            },
            "a.com": {
                "watch": "a.com",
                "takeover_risks": {"sub.a.com": {"evidence": "Dangling Heroku CNAME"}},
                "secret_exposures": {},
            },
        }
        digest = build_digest_alert(payloads, watchlist_name="test-watch")
        self.assertTrue(digest["digest"])
        self.assertEqual(digest["domain_alerts_count"], 2)
        md = digest["summary_markdown"]
        self.assertIn("# Perimeter Alert Digest — test-watch", md)
        self.assertIn("## Domain: a.com", md)
        self.assertIn("## Domain: b.com", md)
        self.assertIn("Dangling Heroku CNAME", md)

    def test_run_digest_batching_threshold(self):
        dispatched_payloads = []
        fake_senders = {
            "webhook": lambda url, alert: dispatched_payloads.append(alert) or 200
        }

        def fake_enum(domain):
            return [f"new.{domain}"]

        def fake_resolve(names):
            return {n: {"name": n, "aliases": [], "ips": ["1.1.1.1"]} for n in names}

        wl = {
            "name": "my-watchlist",
            "domains": ["d1.com", "d2.com"],
            "alerts": {"webhook": {"url": "https://hook.test/x"}},
        }

        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "s.json"

            # Case 1: digest enabled with threshold 2 -> 2 alerts triggered -> 1 digest dispatch
            dispatched_payloads.clear()
            _, _, _, _, _, res = cli.run(
                wl,
                state,
                enum_fn=fake_enum,
                resolve_fn=fake_resolve,
                fetch_fn=lambda url: (0, "offline"),
                digest=True,
                digest_threshold=2,
                senders=fake_senders,
            )
            self.assertIn("digest", res)
            self.assertEqual(len(dispatched_payloads), 1)
            self.assertTrue(dispatched_payloads[0].get("digest"))

            # Case 2: threshold 3 with 2 alerts -> individual dispatches
            dispatched_payloads.clear()
            # reset state so new subdomains show up again
            state.write_text("{}", encoding="utf-8")
            _, _, _, _, _, res2 = cli.run(
                wl,
                state,
                enum_fn=fake_enum,
                resolve_fn=fake_resolve,
                fetch_fn=lambda url: (0, "offline"),
                digest=True,
                digest_threshold=3,
                senders=fake_senders,
            )
            self.assertEqual(len(dispatched_payloads), 2)
            self.assertNotIn("digest", dispatched_payloads[0])

    def test_email_digest_subject(self):
        sent_messages = []

        def fake_smtp(config, msg):
            sent_messages.append(msg)

        alert = {
            "digest": True,
            "watch": "test-watch",
            "domain_alerts_count": 3,
            "summary_markdown": "# Digest",
        }
        send_email({"host": "h", "port": 25, "user": "u", "password": "p", "to": "a@b.com"}, alert, smtp=fake_smtp)
        self.assertEqual(len(sent_messages), 1)
        self.assertIn("Alert Digest (3 domains)", sent_messages[0]["Subject"])


class TestCLIV04(unittest.TestCase):
    def test_due_flag_cli(self):
        wl_content = {
            "domains": ["d1.com", {"name": "d2.com", "interval_days": 14}]
        }
        with tempfile.TemporaryDirectory() as td:
            wl_path = Path(td) / "wl.json"
            state_path = Path(td) / "state.json"
            wl_path.write_text(json.dumps(wl_content), encoding="utf-8")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                exit_code = cli.main(["--watchlist", str(wl_path), "--state", str(state_path), "--due"])
                self.assertEqual(exit_code, 0)
                out = mock_out.getvalue()
                self.assertIn("Domain Due Status (v0.4.0)", out)
                self.assertIn("[DUE] d1.com", out)
                self.assertIn("[DUE] d2.com", out)

    def test_load_last_scanned_legacy_envelope(self):
        from perimeter_watch.state import load_last_scanned
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "legacy_state.json"
            legacy_data = {
                "captured_at": "2026-10-20T10:00:00+00:00",
                "domains": {"legacy.com": {"sub.legacy.com": None}}
            }
            p.write_text(json.dumps(legacy_data), encoding="utf-8")
            ls = load_last_scanned(p)
            self.assertEqual(ls, {"legacy.com": "2026-10-20T10:00:00+00:00"})

    def test_cli_clean_run_output_language(self):
        wl_content = {"domains": ["clean.com"]}
        with tempfile.TemporaryDirectory() as td:
            wl_path = Path(td) / "wl.json"
            state_path = Path(td) / "state.json"
            wl_path.write_text(json.dumps(wl_content), encoding="utf-8")

            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with patch("perimeter_watch.__main__.ct_subdomains", return_value=["sub.clean.com"]):
                    with patch("perimeter_watch.__main__.resolve_all", return_value={"sub.clean.com": {"name": "sub.clean.com", "aliases": [], "ips": ["1.1.1.1"]}}):
                        # First run creates baseline
                        cli.main(["--watchlist", str(wl_path), "--state", str(state_path)])

            # Second run with no changes
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                with patch("perimeter_watch.__main__.ct_subdomains", return_value=["sub.clean.com"]):
                    with patch("perimeter_watch.__main__.resolve_all", return_value={"sub.clean.com": {"name": "sub.clean.com", "aliases": [], "ips": ["1.1.1.1"]}}):
                        code = cli.main(["--watchlist", str(wl_path), "--state", str(state_path)])
                        self.assertEqual(code, 0)
                        out = mock_out.getvalue()
                        self.assertIn("no issues found by ruleset v0.4.0", out)
                        self.assertNotIn("safe", out.lower())


if __name__ == "__main__":
    unittest.main()
