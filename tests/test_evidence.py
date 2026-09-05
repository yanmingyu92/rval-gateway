"""Tests for gateway.evidence — offline (network collectors stubbed)."""

import unittest

from gateway import evidence


def make_ingest(origin="cran", sha="cd" * 32, url=None):
    return {
        "package": "testpkg", "version": "1.0", "origin": origin,
        "tarball_path": "/tmp/testpkg_1.0.tar.gz", "sha256": sha,
        "source_url": url, "ref": None, "collection_mode": "network",
        "description": {"Package": "testpkg", "Version": "1.0",
                        "License": "MIT"},
        "ingested_at": "t", "provenance_path": "",
    }


def no_network(self):
    self.net_fail.append(("stub", "offline", "stubbed in test"))
    return None


class TestEvidenceRegister(unittest.TestCase):
    def setUp(self):
        # stub all network collectors to fail fast (offline test)
        self._orig = (evidence.Collector.crandb, evidence.Collector.cranlogs,
                      evidence.Collector.github)
        evidence.Collector.crandb = no_network
        evidence.Collector.cranlogs = no_network
        evidence.Collector.github = no_network

    def tearDown(self):
        (evidence.Collector.crandb, evidence.Collector.cranlogs,
         evidence.Collector.github) = self._orig

    def test_ids_sequential_and_no_empty_values(self):
        reg = evidence.EvidenceRegister()
        reg.add("a", "x", "src", "local")
        reg.add("b", None, "src", "local")   # dropped: no empty-value entries
        reg.add("c", 3, "src", "local")
        self.assertEqual([e["evidence_id"] for e in reg.entries],
                         ["EV-001", "EV-002"])
        self.assertEqual(reg.entries[1]["metric"], "c")

    def test_local_description_always_collected(self):
        ev = evidence.collect("testpkg", make_ingest())
        metrics = [e["metric"] for e in ev["entries"]]
        self.assertIn("description.version", metrics)
        self.assertIn("tarball.sha256", metrics)
        self.assertIn("ingest.origin", metrics)
        self.assertEqual(ev["collection_mode"], "local-only")
        self.assertEqual(ev["network_sources_ok"], 0)
        self.assertTrue(ev["network_sources_failed"])  # degraded, recorded

    def test_riskmetric_merge_gets_evidence_ids(self):
        score = {
            "overall_score": 0.42, "metric_scores": {"has_news": 0.0},
            "metric_raw": {"has_news": "0"}, "excluded_metrics": ["a", "b"],
            "r_version": "R 4.6.0", "riskmetric_version": "0.2.7",
        }
        ev = evidence.collect("testpkg", make_ingest(), score)
        index = {e["metric"]: e for e in ev["entries"]}
        self.assertEqual(index["riskmetric.overall_score"]["value"], 0.42)
        self.assertEqual(index["riskmetric.score.has_news"]["value"], 0.0)
        self.assertIn("riskmetric", index["riskmetric.overall_score"]["source"])
        self.assertIn("0.2.7", index["riskmetric.overall_score"]["source"])
        self.assertIn("a, b",
                      index["riskmetric.excluded_metrics"]["value"])

    def test_github_slug_from_description(self):
        ing = make_ingest()
        ing["description"]["URL"] = "https://github.com/acme/widgets"
        c = evidence.Collector("testpkg", ing)
        self.assertEqual(c._github_repo_slug(), "acme/widgets")

    def test_github_slug_from_codeload_url(self):
        ing = make_ingest(
            origin="github",
            url="https://codeload.github.com/acme/widgets/tar.gz/HEAD")
        c = evidence.Collector("testpkg", ing)
        self.assertEqual(c._github_repo_slug(), "acme/widgets")


if __name__ == "__main__":
    unittest.main()
