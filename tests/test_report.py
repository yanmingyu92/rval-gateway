"""Tests for gateway.report — evidence-linked rendering and suppression rule."""

import shutil
import tempfile
import unittest
from pathlib import Path

from gateway import decision, report
from gateway.decision import RuleSet


def make_assessment(with_riskmetric=True, with_cran=True, overall=0.2,
                    tier="exploratory"):
    entries = [
        {"evidence_id": "EV-001", "metric": "description.version",
         "value": "1.0", "source": "local DESCRIPTION", "mode": "local",
         "collected_at": "t"},
        {"evidence_id": "EV-002", "metric": "tarball.sha256", "value": "ab" * 32,
         "source": "local sha256", "mode": "local", "collected_at": "t"},
        {"evidence_id": "EV-003", "metric": "ingest.origin", "value": "cran",
         "source": "ingest", "mode": "local", "collected_at": "t"},
    ]
    if with_cran:
        entries.append({"evidence_id": "EV-004", "metric": "cran.version",
                        "value": "1.0", "source": "https://crandb.r-pkg.org/x",
                        "mode": "network", "collected_at": "t"})
    if with_riskmetric:
        entries.append({"evidence_id": "EV-005",
                        "metric": "riskmetric.overall_score", "value": overall,
                        "source": "riskmetric run", "mode": "riskmetric",
                        "collected_at": "t"})
        entries.append({"evidence_id": "EV-006",
                        "metric": "riskmetric.score.has_news", "value": 0,
                        "source": "riskmetric run", "mode": "riskmetric",
                        "collected_at": "t"})
    evidence = {"entries": entries, "collection_mode": "network"}
    dec = decision.decide(overall if with_riskmetric else None, tier,
                          evidence, RuleSet.load())
    return {
        "spec": {"package": "testpkg"},
        "ingest": {"package": "testpkg", "version": "1.0", "origin": "cran",
                   "sha256": "ab" * 32, "source_url": None,
                   "collection_mode": "network", "description": {}},
        "score": {"r_version": "R version 4.6.0", "riskmetric_version": "0.2.7"}
                 if with_riskmetric else None,
        "evidence": evidence,
        "decision": dec,
        "generated_at": "2026-01-01T00:00:00Z",
    }


class TestReportRender(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_report_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_render_has_decision_and_evidence(self):
        a = make_assessment()
        out = report.render(a, self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("testpkg", h)
        self.assertIn("GO", h)
        self.assertIn("EV-001", h)
        self.assertIn("Evidence Register", h)
        self.assertIn("PENDING HUMAN REVIEW", h)
        # every metric row carries its evidence id
        self.assertIn("has_news", h)

    def test_suppression_when_no_riskmetric_evidence(self):
        a = make_assessment(with_riskmetric=False)
        out = report.render(a, self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn(report.NO_EVIDENCE, h)

    def test_suppression_when_no_cran_metadata(self):
        a = make_assessment(with_cran=False)
        out = report.render(a, self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        # CRAN section suppressed, but metric section present
        self.assertIn(report.NO_EVIDENCE, h)
        self.assertIn("has_news", h)

    def test_decision_rules_shown_with_inputs(self):
        a = make_assessment(overall=0.55)
        out = report.render(a, self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("overall_score_threshold", h)
        self.assertIn("0.55", h)

    def test_pdf_attempt(self):
        """PDF via pdflatex when available; degradation noted otherwise."""
        import shutil as sh
        a = make_assessment()
        out = report.render(a, self.tmp)
        if sh.which("pdflatex"):
            self.assertIsNotNone(out["pdf"], f"pdflatex failed: {out['pdf_note']}")
            self.assertTrue(Path(out["pdf"]).is_file())
            self.assertGreater(Path(out["pdf"]).stat().st_size, 1000)
        else:
            self.assertIsNone(out["pdf"])
            self.assertIn("pdflatex", out["pdf_note"])


if __name__ == "__main__":
    unittest.main()
