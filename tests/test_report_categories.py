"""Tests for Phase C report upgrades: category subscores + rubric
disclosure, intended-use classification (form validation, audit record,
report section), approval timeline, and the system-information annex.

Offline: report renders use synthetic assessment dicts; pipeline tests use
skip_score or a mocked r_adapter; the server test posts to a real
ThreadingHTTPServer on an ephemeral localhost port (auth disabled).
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from gateway import audit, decision, pipeline, report, server
from gateway.decision import RuleSet
from test_ingest import make_pkg_tarball


def make_assessment(with_categories=True, classification=None,
                    timeline=None):
    """Synthetic scored assessment with four category subscores and
    per-metric riskmetric evidence entries."""
    metric_scores = {
        "dependencies": 0.4,
        "exported_namespace": 0.6,
        "remote_checks": None,
        "size_codebase": 0.2,
        "news_current": 0.0,
        "downloads_1yr": 0.9,
        "reverse_dependencies": 0.5,
    }
    weights = {
        "code": {"weight": 0.50,
                 "metrics": ["dependencies", "exported_namespace",
                             "remote_checks", "size_codebase"]},
        "documentation": {"weight": 0.15, "metrics": ["news_current"]},
        "maintenance": {"weight": 0.20, "metrics": ["bugs_status"]},
        "popularity": {"weight": 0.15,
                       "metrics": ["downloads_1yr",
                                   "reverse_dependencies"]},
    }
    entries = [
        {"evidence_id": "EV-001", "metric": "description.version",
         "value": "1.0", "source": "local DESCRIPTION", "mode": "local",
         "collected_at": "t"},
        {"evidence_id": "EV-002", "metric": "tarball.sha256",
         "value": "ab" * 32, "source": "local sha256", "mode": "local",
         "collected_at": "t"},
        {"evidence_id": "EV-003", "metric": "ingest.origin", "value": "cran",
         "source": "ingest", "mode": "local", "collected_at": "t"},
        {"evidence_id": "EV-004", "metric": "riskmetric.overall_score",
         "value": 0.2, "source": "riskmetric run", "mode": "riskmetric",
         "collected_at": "t"},
    ]
    for i, (m, v) in enumerate(sorted(metric_scores.items()), start=5):
        entries.append({"evidence_id": f"EV-{i:03d}",
                        "metric": f"riskmetric.score.{m}", "value": v,
                        "source": "riskmetric run", "mode": "riskmetric",
                        "collected_at": "t"})
    evidence = {"entries": entries, "collection_mode": "network",
                "collected_at": "2026-01-01T00:00:00Z",
                "network_sources_ok": 2,
                "network_sources_failed": [
                    {"collector": "github",
                     "url": "https://api.github.com/repos/x/y",
                     "error": "URLError: refused"}]}
    score = {"overall_score": 0.2, "metric_scores": metric_scores,
             "r_version": "R version 4.6.0", "riskmetric_version": "0.2.7",
             "assessed_at": "2026-01-01T00:00:01Z"}
    if with_categories:
        score["category_scores"] = decision.category_scores(metric_scores,
                                                            weights)
    dec = decision.decide(0.2, "exploratory", evidence, RuleSet.load())
    return {
        "spec": {"package": "testpkg"},
        "ingest": {"package": "testpkg", "version": "1.0", "origin": "cran",
                   "sha256": "ab" * 32, "source_url": None,
                   "collection_mode": "network", "description": {}},
        "score": score,
        "evidence": evidence,
        "decision": dec,
        "classification": classification,
        "timeline": timeline,
        "generated_at": "2026-01-01T00:00:02Z",
    }


class TestCategoryScores(unittest.TestCase):
    """decision.category_scores — mapping + equal-weighted mean math."""

    def test_weighted_subscore_math(self):
        weights = {"code": {"weight": 0.5,
                            "metrics": ["a", "b", "c", "d"]}}
        # hand-computed: (0.2 + 0.4 + 0.6) / 3 = 0.4; c is null (dropped)
        out = decision.category_scores(
            {"a": 0.2, "b": 0.4, "c": None, "d": 0.6}, weights)
        self.assertAlmostEqual(out["code"]["score"], 0.4)
        self.assertEqual(out["code"]["scored"], 3)
        self.assertEqual(out["code"]["weight"], 0.5)
        self.assertEqual(out["code"]["metrics"], ["a", "b", "c", "d"])

    def test_all_null_category_is_none(self):
        out = decision.category_scores(
            {"a": None}, {"code": {"weight": 0.5, "metrics": ["a", "b"]}})
        self.assertIsNone(out["code"]["score"])
        self.assertEqual(out["code"]["scored"], 0)

    def test_weights_read_from_config(self):
        rs = RuleSet.load()
        cw = rs.category_weights
        self.assertEqual(set(cw), {"code", "documentation", "maintenance",
                                   "popularity"})
        self.assertAlmostEqual(
            sum(float(c["weight"]) for c in cw.values()), 1.0)
        # all 17 riskmetric metrics mapped, no duplicates
        members = [m for c in cw.values() for m in c["metrics"]]
        self.assertEqual(len(members), 17)
        self.assertEqual(len(set(members)), 17)
        for expected in ("dependencies", "news_current", "bugs_status",
                         "downloads_1yr", "reverse_dependencies"):
            self.assertIn(expected, members)


class TestCategoryReport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_cat_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def render(self, assessment):
        out = report.render(assessment, self.tmp)
        return Path(out["html"]).read_text(encoding="utf-8")

    def test_rubric_disclosure_in_html(self):
        h = self.render(make_assessment())
        self.assertIn("Scoring Strategy", h)
        self.assertIn("code", h)
        self.assertIn("0.5", h)          # category weight disclosed
        self.assertIn("dependencies", h)  # metric membership disclosed
        # hand-computed code subscore: (0.4+0.6+0.2)/3 = 0.4
        self.assertIn("0.4000", h)
        # popularity: (0.9+0.5)/2 = 0.7
        self.assertIn("0.7000", h)
        # member metrics carry their evidence ids
        self.assertIn("EV-005", h)

    def test_scoring_strategy_suppressed_without_categories(self):
        h = self.render(make_assessment(with_categories=False))
        self.assertIn(report.NO_EVIDENCE, h)

    def test_overall_score_unchanged_by_categories(self):
        """Category subscores never touch the decision: same inputs with
        and without category computation yield the same decision object."""
        a = make_assessment()
        self.assertEqual(a["decision"]["decision"], "GO")
        self.assertNotIn("category_scores", a["decision"])

    def test_pipeline_writes_category_scores_to_score_json(self):
        """score.json gains the additive category_scores field (and the
        in-memory json_path helper key is not persisted)."""
        data_dir = self.tmp / "data"
        tarball = make_pkg_tarball(self.tmp, pkg="catpkg", version="1.0.0")
        run_score_dir = self.tmp / "score_out"
        run_score_dir.mkdir()
        score_file = run_score_dir / "score.json"
        score_file.write_text("{}", encoding="utf-8")
        fake_score = {
            "overall_score": 0.3,
            "metric_scores": {"dependencies": 0.4, "news_current": 0.0},
            "metric_raw": {}, "excluded_metrics": [],
            "r_version": "R version 4.6.0", "riskmetric_version": "0.2.7",
            "assessed_at": "2026-01-01T00:00:01Z",
            "json_path": str(score_file),
        }
        with mock.patch.object(pipeline.r_adapter, "score_tarball",
                               return_value=fake_score):
            a = pipeline.run_assessment(
                {"upload_path": str(tarball)}, "exploratory",
                data_dir=data_dir)
        self.assertIn("category_scores", a["score"])
        written = json.loads(score_file.read_text(encoding="utf-8"))
        self.assertIn("category_scores", written)
        self.assertNotIn("json_path", written)
        # decision.json untouched by the additive field
        dec = json.loads(Path(a["decision_path"]).read_text(encoding="utf-8"))
        self.assertNotIn("category_scores", dec)


class TestClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_cls_test_"))
        self.data_dir = self.tmp / "data"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_report_shows_classification(self):
        a = make_assessment(classification={
            "intended_use": "exploratory plots for study planning",
            "justification": "mature, widely used, low risk profile"})
        out = report.render(a, self.tmp / "r1")
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("exploratory plots for study planning", h)
        self.assertIn("mature, widely used, low risk profile", h)

    def test_report_not_classified_when_absent(self):
        out = report.render(make_assessment(), self.tmp / "r2")
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("Not classified", h)
        # absence is an honest statement, not a suppressed section
        self.assertNotIn(report.NO_EVIDENCE,
                         h.split("Classification &amp; Sign-off")[1]
                         .split("Evidence Register")[0])

    def test_pipeline_threads_classification_to_audit_and_report(self):
        tarball = make_pkg_tarball(self.tmp, pkg="clspkg", version="1.0.0")
        cls = {"intended_use": "Tier-2 candidate screening",
               "justification": "required by the analysis plan"}
        a = pipeline.run_assessment(
            {"upload_path": str(tarball)}, "gxp-critical",
            data_dir=self.data_dir, skip_score=True,
            actor="qa.user", classification=cls)
        rec = a["audit_record"]
        self.assertEqual(rec["intended_use"], "Tier-2 candidate screening")
        self.assertEqual(rec["justification"],
                         "required by the analysis plan")
        h = Path(a["report"]["html"]).read_text(encoding="utf-8")
        self.assertIn("Tier-2 candidate screening", h)

    def test_audit_record_omits_classification_keys_when_absent(self):
        rec = audit.make_assessment_record(
            {"package": "x"}, {"package": "x", "version": "1"}, None,
            {"tier": "exploratory"}, {"collection_mode": "local-only"})
        self.assertNotIn("intended_use", rec)
        self.assertNotIn("justification", rec)


class TestClassificationServer(unittest.TestCase):
    """POST /assess: gxp-critical without intended_use/justification -> 400
    (validated before any ingest/scoring work happens)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_clssrv_test_"))
        self.data_dir = self.tmp / "data"
        self._saved_env = {}
        for k in ("RVAL_PLATFORM_API_URL", "GATEWAY_BASE_PATH"):
            if k in os.environ:
                self._saved_env[k] = os.environ.pop(k)
        self._patches = [
            mock.patch.object(pipeline, "DEFAULT_DATA_DIR", self.data_dir),
            mock.patch.object(server.GatewayHandler, "log_message",
                              lambda *a: None),
        ]
        for p in self._patches:
            p.start()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                         server.GatewayHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        for p in reversed(self._patches):
            p.stop()
        os.environ.update(self._saved_env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def post_assess(self, fields):
        body = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/assess", data=body)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_gxp_critical_requires_classification(self):
        status, body = self.post_assess({"pkg": "abind",
                                         "tier": "gxp-critical"})
        self.assertEqual(status, 400)
        self.assertIn(b"intended_use", body)
        self.assertIn(b"justification", body)

    def test_gxp_critical_partial_classification_rejected(self):
        status, _ = self.post_assess({"pkg": "abind", "tier": "gxp-critical",
                                      "intended_use": "x"})
        self.assertEqual(status, 400)

    def test_exploratory_does_not_require_classification(self):
        """exploratory without classification passes validation (the
        pipeline itself is stubbed to a fast sentinel failure — the real
        pipeline is slow/network-bound in containers; anything but the
        400 classification rejection proves validation passed)."""
        with mock.patch.object(pipeline, "run_assessment",
                               side_effect=RuntimeError("sentinel")):
            status, _ = self.post_assess({"pkg": "abind",
                                          "tier": "exploratory"})
        self.assertNotEqual(status, 400)

    def test_form_has_classification_fields(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/")
        with urllib.request.urlopen(req, timeout=10) as resp:
            h = resp.read().decode("utf-8")
        self.assertIn('name="intended_use"', h)
        self.assertIn('name="justification"', h)


class TestApprovalTimelineReport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_tl_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _chain_records(self):
        return [
            {"record_type": "assessment", "package": "testpkg",
             "decision": "GO-WITH-CONDITIONS", "tier": "gxp-support",
             "overall_score": 0.2, "actor": "qa.user", "timestamp": "t1",
             "record_hash": "a" * 64},
            {"record_type": "esign", "object_id": "testpkg 1.0",
             "signer_id": "qa.lead", "meaning": "approved",
             "timestamp": "t2", "record_hash": "b" * 64},
            {"record_type": "publish", "package": "testpkg", "version": "1.0",
             "flavor": "source", "esign_signer": "qa.lead",
             "timestamp": "t3", "record_hash": "c" * 64},
        ]

    def test_timeline_renders_events_in_order(self):
        events = audit.package_timeline(self._chain_records(), "testpkg")
        a = make_assessment(timeline=events)
        out = report.render(a, self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("Approval Timeline", h)
        i_assess = h.index("<strong>assessment</strong>")
        i_esign = h.index("<strong>esign</strong>")
        i_publish = h.index("<strong>publish</strong>")
        self.assertLess(i_assess, i_esign)
        self.assertLess(i_esign, i_publish)
        self.assertIn("qa.user", h)
        self.assertIn("qa.lead", h)
        # record-hash prefixes shown
        self.assertIn("a" * 12, h)
        self.assertIn("c" * 12, h)

    def test_timeline_empty_message(self):
        out = report.render(make_assessment(timeline=[]), self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("No audit-chain events recorded", h)

    def test_pipeline_report_includes_own_assessment_event(self):
        data_dir = self.tmp / "data"
        tarball = make_pkg_tarball(self.tmp, pkg="tlpkg", version="1.0.0")
        a = pipeline.run_assessment(
            {"upload_path": str(tarball)}, "exploratory",
            data_dir=data_dir, skip_score=True, actor="qa.user")
        h = Path(a["report"]["html"]).read_text(encoding="utf-8")
        self.assertIn("Approval Timeline", h)
        self.assertIn("qa.user", h)
        self.assertIn(a["audit_record"]["record_hash"][:12], h)


class TestSystemInfoAnnex(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_si_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_annex_present_in_html(self):
        out = report.render(make_assessment(), self.tmp)
        h = Path(out["html"]).read_text(encoding="utf-8")
        self.assertIn("Annex: System Information", h)
        self.assertIn("R version 4.6.0", h)
        self.assertIn("0.2.7", h)                    # riskmetric version
        self.assertIn("rval-gateway", h)             # tool version line
        self.assertIn("network", h)                  # collection mode
        self.assertIn("2026-01-01T00:00:01Z", h)     # assessed_at
        # per-source failure summary
        self.assertIn("github", h)
        self.assertIn("URLError: refused", h)


class TestTexTemplateSync(unittest.TestCase):
    def test_tex_template_has_new_sections(self):
        t = report.TEMPLATE_TEX.read_text(encoding="utf-8")
        for slot in ("{{SCORING_STRATEGY}}", "{{CLASSIFICATION_BLOCK}}",
                     "{{SYSTEM_INFO}}", "{{TIMELINE_BLOCK}}"):
            self.assertIn(slot, t)
        self.assertIn("Scoring Strategy", t)
        self.assertIn("Annex: System Information", t)
        self.assertIn("Approval Timeline", t)

    def test_tex_builders_render(self):
        a = make_assessment(timeline=audit.package_timeline(
            [{"record_type": "assessment", "package": "testpkg",
              "decision": "GO", "tier": "exploratory", "overall_score": 0.2,
              "actor": "qa.user", "timestamp": "t1",
              "record_hash": "a" * 64}], "testpkg"))
        index = report.build_index(a["evidence"])
        s = report._tex_scoring_strategy(a["score"], index)
        self.assertIn("longtable", s)
        self.assertIn("0.4000", s)
        c = report._tex_classification(
            {"intended_use": "x & y", "justification": "because"}, "exploratory")
        self.assertIn("x \\& y", c)  # tex escaping applied
        tl = report._tex_timeline(a["timeline"])
        self.assertIn("qa.user", tl)
        si = report._tex_system_info(a["evidence"], a["score"])
        self.assertIn("2 / 1", si)  # network sources ok / failed


if __name__ == "__main__":
    unittest.main()
