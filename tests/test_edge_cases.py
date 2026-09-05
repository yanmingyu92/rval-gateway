"""Edge-case tests — Phase 3, workstream 3. Offline where possible."""

import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path

from gateway import decision, evidence, ingest, report
from gateway.decision import RuleSet
from gateway.ingest import IngestError
from test_ingest import make_pkg_tarball


def _net_down(url, timeout=ingest.TIMEOUT_S):
    raise OSError("network down (simulated)")


def _http404(url, timeout=ingest.TIMEOUT_S):
    raise urllib.error.HTTPError(url, 404, "Not Found", None, None)


class TestArchivedCranPackage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_edge_test_"))
        self.data_dir = self.tmp / "data"
        self.tarball = make_pkg_tarball(self.tmp, pkg="oldpkg", version="0.9.0")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_archive_fallback_offline_simulated(self):
        """Main contrib 404s; Archive URL serves the tarball."""
        payload = self.tarball.read_bytes()

        def fake_fetch(url, timeout=ingest.TIMEOUT_S):
            if "/Archive/" in url:
                return payload
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

        orig = ingest._fetch
        ingest._fetch = fake_fetch
        try:
            res = ingest.ingest_cran("oldpkg", "0.9.0", self.data_dir)
        finally:
            ingest._fetch = orig
        self.assertEqual(res.version, "0.9.0")
        self.assertEqual(res.collection_mode, "network")
        self.assertIn("/Archive/oldpkg/", res.source_url)
        self.assertEqual(res.description["Package"], "oldpkg")

    def test_archive_only_version_live(self):
        """xfun 0.56 is older than the current CRAN version -> Archive path."""
        try:
            res = ingest.ingest_cran("xfun", "0.56", self.data_dir)
        except Exception as e:  # noqa: BLE001
            self.skipTest(f"network unavailable: {e}")
        self.assertEqual(res.version, "0.56")


class TestNonexistentPackage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_edge_test_"))
        self.data_dir = self.tmp / "data"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_404_no_cache_raises_without_fabrication(self):
        orig = ingest._fetch
        ingest._fetch = _http404
        try:
            with self.assertRaises(IngestError):
                ingest.ingest_cran("nosuchpkg", "1.0.0", self.data_dir)
        finally:
            ingest._fetch = orig
        # nothing stored, nothing fabricated
        self.assertFalse((self.data_dir / "tarballs" / "nosuchpkg").exists())

    def test_unresolvable_current_version_raises(self):
        orig = ingest._fetch
        ingest._fetch = _net_down
        try:
            with self.assertRaises(IngestError):
                ingest.ingest_cran("nosuchpkg", None, self.data_dir)
        finally:
            ingest._fetch = orig

    def test_nonexistent_package_live(self):
        try:
            ingest.ingest_cran("this-pkg-cannot-possibly-exist-zzz999", "0.0.1",
                               self.data_dir)
        except IngestError:
            return  # expected clean failure
        except Exception as e:  # noqa: BLE001
            self.skipTest(f"network unavailable: {e}")
        self.fail("expected IngestError for nonexistent package")


class TestCollectorDegradation(unittest.TestCase):
    def setUp(self):
        self._orig_fetch = evidence._fetch_json
        self.ingest_d = {
            "package": "newpkg", "version": "0.0.1", "origin": "cran",
            "tarball_path": "/tmp/newpkg_0.0.1.tar.gz", "sha256": "ef" * 32,
            "source_url": None, "ref": None, "collection_mode": "network",
            "description": {"Package": "newpkg", "Version": "0.0.1"},
            "ingested_at": "t", "provenance_path": "",
        }

    def tearDown(self):
        evidence._fetch_json = self._orig_fetch

    def test_all_sources_fail_marks_local_only(self):
        evidence._fetch_json = lambda url: (_ for _ in ()).throw(
            OSError("down"))
        ev = evidence.collect("newpkg", self.ingest_d)
        self.assertEqual(ev["collection_mode"], "local-only")
        self.assertEqual(ev["network_sources_ok"], 0)
        self.assertGreaterEqual(len(ev["network_sources_failed"]), 2)
        # local facts still collected
        metrics = [e["metric"] for e in ev["entries"]]
        self.assertIn("description.version", metrics)

    def test_partial_failure_marks_network_with_failures_listed(self):
        def selective(url):
            if "crandb" in url:
                return {"Version": "0.0.1", "Title": "New"}
            raise OSError("down")
        evidence._fetch_json = selective
        ev = evidence.collect("newpkg", self.ingest_d)
        self.assertEqual(ev["collection_mode"], "network")
        failed = [f["collector"] for f in ev["network_sources_failed"]]
        self.assertIn("cranlogs", failed)
        self.assertNotIn("crandb", failed)

    def test_empty_api_response_yields_no_empty_entries(self):
        evidence._fetch_json = lambda url: {}
        ev = evidence.collect("newpkg", self.ingest_d)
        cran_entries = [e for e in ev["entries"]
                        if e["metric"].startswith("cran.")]
        self.assertEqual(cran_entries, [])  # no empty-value entries fabricated


class TestMinimalEvidenceDecision(unittest.TestCase):
    """Brand-new package: only local DESCRIPTION facts, thin riskmetric run."""

    @classmethod
    def setUpClass(cls):
        cls.rs = RuleSet.load()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_edge_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _minimal_evidence(self, overall=0.1):
        entries = [
            {"evidence_id": "EV-001", "metric": "description.version",
             "value": "0.0.1", "source": "local DESCRIPTION", "mode": "local",
             "collected_at": "t"},
        ]
        if overall is not None:
            entries.append({"evidence_id": "EV-002",
                            "metric": "riskmetric.overall_score",
                            "value": overall, "source": "riskmetric run",
                            "mode": "riskmetric", "collected_at": "t"})
        return {"entries": entries, "collection_mode": "local-only"}

    def test_decision_still_emitted_with_gap_conditions(self):
        ev = self._minimal_evidence(overall=0.1)
        d = decision.decide(0.1, "exploratory", ev, self.rs)
        self.assertEqual(d["decision"], "GO")
        # evidence-gap rules fire explicitly (is_na on missing metrics)
        self.assertIn("news_not_measurable", d["fired_rules"])
        self.assertIn("no_source_control", d["fired_rules"])
        self.assertTrue(d["conditions"])

    def test_no_score_means_no_go_with_explicit_reason(self):
        ev = self._minimal_evidence(overall=None)
        d = decision.decide(None, "exploratory", ev, self.rs)
        self.assertEqual(d["decision"], "NO-GO")
        self.assertTrue(any("No overall risk score could be computed" in c
                            for c in d["conditions"]))

    def test_report_suppresses_evidenceless_sections(self):
        ev = self._minimal_evidence(overall=0.1)
        d = decision.decide(0.1, "exploratory", ev, self.rs)
        a = {
            "spec": {"package": "newpkg"},
            "ingest": {"package": "newpkg", "version": "0.0.1",
                       "origin": "cran", "sha256": "ef" * 32,
                       "source_url": None, "collection_mode": "local-only",
                       "description": {}},
            "score": {"r_version": "R version 4.6.0",
                      "riskmetric_version": "0.2.7"},
            "evidence": ev, "decision": d,
            "generated_at": "2026-01-01T00:00:00Z",
        }
        orig_pdf = report._render_pdf
        report._render_pdf = lambda *a, **k: (False, "skipped in test")
        try:
            out = report.render(a, self.tmp)
        finally:
            report._render_pdf = orig_pdf
        h = Path(out["html"]).read_text(encoding="utf-8")
        # CRAN Metadata + Community sections suppressed; metric section too
        self.assertGreaterEqual(h.count(report.NO_EVIDENCE), 2)
        self.assertIn("PENDING HUMAN REVIEW", h)
        self.assertIn("pdf rendering degraded", h.lower())


class TestHugeDependencyTree(unittest.TestCase):
    """Canned evidence with a large dependency footprint; report must not
    truncate or crash."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_edge_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_large_evidence_register_renders(self):
        entries = [
            {"evidence_id": "EV-001", "metric": "description.version",
             "value": "1.0", "source": "local DESCRIPTION", "mode": "local",
             "collected_at": "t"},
            {"evidence_id": "EV-002", "metric": "cran.imports_count",
             "value": 250, "source": "https://crandb.r-pkg.org/bigpkg",
             "mode": "network", "collected_at": "t", "unit": "packages"},
            {"evidence_id": "EV-003", "metric": "riskmetric.overall_score",
             "value": 0.55, "source": "riskmetric run", "mode": "riskmetric",
             "collected_at": "t"},
            {"evidence_id": "EV-004",
             "metric": "riskmetric.score.dependencies", "value": 0.9,
             "source": "riskmetric run", "mode": "riskmetric",
             "collected_at": "t"},
        ]
        # simulate a very large raw dependency listing
        big_raw = ", ".join(f"dep{i:03d} (>= 1.0)" for i in range(300))
        entries.append({"evidence_id": "EV-005",
                        "metric": "riskmetric.raw.dependencies",
                        "value": big_raw, "source": "riskmetric run",
                        "mode": "riskmetric", "collected_at": "t"})
        ev = {"entries": entries, "collection_mode": "network"}
        rs = RuleSet.load()
        d = decision.decide(0.55, "exploratory", ev, rs)
        self.assertIn("heavy_dependencies", d["fired_rules"])
        a = {
            "spec": {"package": "bigpkg"},
            "ingest": {"package": "bigpkg", "version": "1.0",
                       "origin": "cran", "sha256": "ab" * 32,
                       "source_url": None, "collection_mode": "network",
                       "description": {}},
            "score": {"r_version": "R version 4.6.0",
                      "riskmetric_version": "0.2.7"},
            "evidence": ev, "decision": d,
            "generated_at": "2026-01-01T00:00:00Z",
        }
        orig_pdf = report._render_pdf
        report._render_pdf = lambda *a2, **k: (False, "skipped in test")
        try:
            out = report.render(a, self.tmp)
        finally:
            report._render_pdf = orig_pdf
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("250", h)            # dependency count surfaced
        self.assertIn("dep000", h)         # raw listing begins...
        self.assertIn("...", h)            # ...and is capped, not crashing
        self.assertIn("EV-005", h)


if __name__ == "__main__":
    unittest.main()
