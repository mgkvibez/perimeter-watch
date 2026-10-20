"""v0.3: exposed bucket detection + historical trend reports (offline)."""
import json
import tempfile
import unittest
from pathlib import Path

from perimeter_watch.buckets import (
    detect_storage_targets, probe, scan_buckets)
from perimeter_watch.trends import (
    append_history, load_history, summarize, render_markdown)

S3_LIST = ('<ListBucketResult><Name>assets</Name>'
           '<Contents><Key>invoice-2026.pdf</Key></Contents></ListBucketResult>')
AZURE_LIST = ('<EnumerationResults><Blobs><Blob><Name>backup.zip</Name>'
              '</Blob></Blobs></EnumerationResults>')


def make_fetch(status_by_url, body_by_url):
    def fetch(url):
        return status_by_url.get(url, 404), body_by_url.get(url, "")
    return fetch


class TestBuckets(unittest.TestCase):
    def test_storage_target_detection(self):
        records = {
            "assets.client.test": {"cname": "assets.s3.amazonaws.com",
                                   "aliases": [], "ips": ["1.2.3.4"]},
            "plain.client.test": {"cname": "", "aliases": [],
                                  "ips": ["1.2.3.4"]},
            "data.client.test": {"cname": "data.blob.core.windows.net",
                                 "aliases": [], "ips": ["2.3.4.5"]},
        }
        found = {(n, p) for n, p, _ in detect_storage_targets(records)}
        self.assertEqual(found, {("assets.client.test", "s3"),
                                 ("data.client.test", "azure")})

    def test_exposed_s3_detected(self):
        fetch = make_fetch(
            {"https://assets.s3.amazonaws.com/?list-type=2&max-keys=1": 200},
            {"https://assets.s3.amazonaws.com/?list-type=2&max-keys=1": S3_LIST})
        records = {"assets.client.test": {"cname": "assets.s3.amazonaws.com",
                                          "aliases": [], "ips": ["1.2.3.4"]}}
        found = scan_buckets(records, fetch=fetch)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["provider"], "s3")

    def test_hardened_s3_not_flagged(self):
        fetch = make_fetch(
            {"https://assets.s3.amazonaws.com/?list-type=2&max-keys=1": 403},
            {"https://assets.s3.amazonaws.com/?list-type=2&max-keys=1": "AccessDenied"})
        records = {"assets.client.test": {"cname": "assets.s3.amazonaws.com",
                                          "aliases": [], "ips": ["1.2.3.4"]}}
        self.assertEqual(scan_buckets(records, fetch=fetch), [])

    def test_exposed_azure_detected(self):
        fetch = make_fetch(
            {"https://data.blob.core.windows.net/?$container&restype=container&comp=list&maxresults=1":
             200},
            {"https://data.blob.core.windows.net/?$container&restype=container&comp=list&maxresults=1":
             AZURE_LIST})
        records = {"data.client.test": {"cname": "data.blob.core.windows.net",
                                        "aliases": [], "ips": ["2.3.4.5"]}}
        found = scan_buckets(records, fetch=fetch)
        self.assertEqual(found[0]["provider"], "azure")

    def test_probe_direct(self):
        self.assertTrue(probe("https://x.s3.amazonaws.com", "s3",
                             fetch=lambda url: (200, S3_LIST)))
        self.assertFalse(probe("https://x.s3.amazonaws.com", "s3",
                               fetch=lambda url: (200, "not xml")))


class TestTrends(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "history.jsonl"
        for day, assets, take, sec in [
            ("2026-10-06", 10, 0, 0),
            ("2026-10-13", 12, 1, 0),
            ("2026-10-20", 15, 0, 2),
        ]:
            append_history(self.path, {
                "captured_at": f"{day}T08:00:00+00:00",
                "assets": assets, "dangling": 1,
                "takeovers": take, "secrets": sec, "buckets": 0})

    def tearDown(self):
        self.tmp.cleanup()

    def test_journal_load_and_summary(self):
        rows = load_history(self.path)
        self.assertEqual(len(rows), 3)
        s = summarize(rows)
        self.assertEqual(s["runs"], 3)
        self.assertEqual(s["assets_first"], 10)
        self.assertEqual(s["assets_last"], 15)
        self.assertEqual(s["assets_growth"], 5)
        self.assertEqual(s["total_incidents"], 3)
        self.assertEqual(list(s["by_week"]), ["2026-10-05", "2026-10-12", "2026-10-19"])

    def test_markdown_render(self):
        md = render_markdown(summarize(load_history(self.path)))
        self.assertIn("# Perimeter trend report", md)
        self.assertIn("| 2026-10-12 | 1 | 12 | 1 |", md)

    def test_corrupt_lines_tolerated(self):
        self.path.write_text("not json\n" + self.path.read_text(), encoding="utf-8")
        self.assertEqual(len(load_history(self.path)), 3)


if __name__ == "__main__":
    unittest.main()
