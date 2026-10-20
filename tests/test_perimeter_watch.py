"""Fully offline: enumeration and resolution are injected."""
import json
import tempfile
import unittest
from pathlib import Path

from perimeter_watch.state import diff, load_state, save_state
from perimeter_watch.takeover import classify, classify_all
from perimeter_watch import __main__ as cli


class TestDiff(unittest.TestCase):
    def test_added_removed_changed(self):
        prev = {"d.com": {"a.d.com": {"name": "a.d.com", "aliases": [], "ips": ["1.1.1.1"]},
                                "b.d.com": {"name": "b.d.com", "aliases": [], "ips": ["2.2.2.2"]}}}
        cur = {"d.com": {"a.d.com": {"name": "a.d.com", "aliases": [], "ips": ["3.3.3.3"]},
                                "c.d.com": {"name": "c.d.com", "aliases": [], "ips": ["2.2.2.2"]}}}
        r = diff(prev, cur)["d.com"]
        self.assertEqual(r["added"], ["c.d.com"])
        self.assertEqual(r["removed"], ["b.d.com"])
        self.assertEqual(r["changed"], ["a.d.com"])

    def test_newly_dangling_detected(self):
        prev = {"d.com": {"a.d.com": {"name": "a.d.com", "aliases": [], "ips": ["1.1.1.1"]}}}
        cur = {"d.com": {"a.d.com": None}}
        r = diff(prev, cur)["d.com"]
        self.assertEqual(r["newly_dangling"], ["a.d.com"])

    def test_first_run_everything_added(self):
        r = diff({}, {"d.com": {"a.d.com": None}})["d.com"]
        self.assertEqual(r["added"], ["a.d.com"])
        self.assertEqual(r["newly_dangling"], [])


class TestState(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            save_state({"x": 1}, path)
            self.assertEqual(load_state(path), {"x": 1})

    def test_missing_state_is_empty(self):
        self.assertEqual(load_state("/nonexistent/state.json"), {})


class TestTakeover(unittest.TestCase):
    RECORD = {"name": "a.d.com", "aliases": ["a.d.com.herokuapp.com"], "ips": []}

    def test_dangling_alias_to_known_service(self):
        risk = classify(self.RECORD, resolve_fn=lambda name: None)
        self.assertEqual(risk["service"], "Heroku")
        self.assertEqual(risk["risk"], "takeover")

    def test_live_alias_no_risk(self):
        risk = classify(self.RECORD, resolve_fn=lambda name: {"ips": ["1.2.3.4"], "aliases": []})
        self.assertIsNone(risk)

    def test_dangling_alias_unknown_service_no_risk(self):
        record = {"name": "a.d.com", "aliases": ["a.d.com.unknown-svc.example"], "ips": []}
        self.assertIsNone(classify(record, resolve_fn=lambda name: None))

    def test_no_alias_no_risk(self):
        self.assertIsNone(classify({"name": "a", "aliases": [], "ips": ["1.1.1.1"]}))


class TestRun(unittest.TestCase):
    def test_full_run_with_injection(self):
        enum = lambda domain: ["a.d.com", "b.d.com"] if domain == "d.com" else []
        resolve = lambda names: {
            "a.d.com": {"name": "a.d.com", "aliases": [], "ips": ["1.1.1.1"]},
            "b.d.com": None,
        }
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "s.json"
            report, risks, errors = cli.run({"domains": ["d.com"]}, state,
                                            enum_fn=enum, resolve_fn=resolve)
            self.assertEqual(report["d.com"]["added"], ["a.d.com", "b.d.com"])
            self.assertEqual(report["d.com"]["newly_dangling"], [])
            self.assertEqual(errors, {})
            # second run: nothing new, state persisted
            report2, _, _ = cli.run({"domains": ["d.com"]}, state,
                                    enum_fn=enum, resolve_fn=resolve)
            self.assertEqual(report2["d.com"]["added"], [])
            self.assertEqual(report2["d.com"]["changed"], [])


if __name__ == "__main__":
    unittest.main()
