"""Tests for Phase B: /dashboard page, /api/* read-only JSON, /runs/
whitelisted static serving, and actor plumbing through the audit chain.

Offline: a fixture data-dir is built with skip_score pipeline runs (no R,
no network); the HTTP layer runs against a real ThreadingHTTPServer on an
ephemeral localhost port. Auth-gate tests set RVAL_PLATFORM_API_URL and send no
credentials, so the gate fails closed with 401 without ever calling the
platform API (same pattern as tests/test_platform_auth.py).
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from gateway import audit, dashboard, pipeline, server
from test_ingest import make_pkg_tarball

# env vars that must be neutralised for the dev-mode (auth-off) fixture
_STRIP_ENV = ("RVAL_PLATFORM_API_URL", "GATEWAY_BASE_PATH")


class DashboardServerBase(unittest.TestCase):
    """Spin up the real handler against a tmp data-dir with:
    - dashfix 1.0.0 assessed (skip_score -> NO-GO) by actor qa.user, and
      published in the manifest with a dependency gap on 'missingdep'
    - legacypkg assessed by a pre-actor-plumbing record (no actor field)
    - unassessedpkg in the inventory only
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_dash_test_"))
        self.data_dir = self.tmp / "data"

        tarball = make_pkg_tarball(self.tmp, pkg="dashfix", version="1.0.0")
        a = pipeline.run_assessment(
            {"upload_path": str(tarball)}, "gxp-support",
            data_dir=self.data_dir, skip_score=True, actor="qa.user")
        self.run_id = Path(a["run_dir"]).name

        # legacy record (pre-actor-plumbing shape: no actor key), chained
        log = audit.AuditLog(self.data_dir / "audit" / "assessments.jsonl")
        log.append({"record_type": "assessment", "package": "legacypkg",
                    "version": "9.9", "decision": "GO", "overall_score": 0.9,
                    "tier": "exploratory",
                    "config_sha256": self._config_sha()})

        self.inv = self.tmp / "inventory.json"
        self.inv.write_text(json.dumps({
            "schema": "rval-gateway inventory v1",
            "snapshot": "2026-08-01",
            "packages": [
                {"name": "dashfix", "version": "1.0.0", "sources": ["code"]},
                {"name": "legacypkg", "version": "9.9", "sources": ["code"]},
                {"name": "unassessedpkg", "version": "0.1",
                 "sources": ["code"]},
            ]}), encoding="utf-8")

        repo_dir = self.data_dir / "repo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "manifest.json").write_text(json.dumps({
            "schema": "rval-gateway repo manifest v1",
            "artifacts": [{
                "package": "dashfix", "version": "1.0.0", "flavor": "source",
                "sha256": "ab" * 32, "assessment_decision": "NO-GO",
                "published_at": "2026-09-03T00:00:00Z",
                "dependency_gaps": {"dependencies": ["missingdep"],
                                    "covered": [],
                                    "missing": ["missingdep"]}}]}),
            encoding="utf-8")

        self._saved_env = {}
        for k in _STRIP_ENV:
            if k in os.environ:
                self._saved_env[k] = os.environ.pop(k)
        self._patches = [
            mock.patch.object(pipeline, "DEFAULT_DATA_DIR", self.data_dir),
            mock.patch.object(dashboard, "DEFAULT_INVENTORY", self.inv),
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

    @staticmethod
    def _config_sha():
        from gateway import decision as decision_mod
        return decision_mod.RuleSet.load().sha256

    def get(self, path, headers=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers

    def get_json(self, path):
        status, body, _ = self.get(path)
        self.assertEqual(status, 200, f"GET {path} -> {status}")
        return json.loads(body.decode("utf-8"))


class TestAuthGate(DashboardServerBase):
    """All new routes go through _gate(): with RVAL_PLATFORM_API_URL set and no
    credentials, every one answers 401 (fail-closed unchanged)."""

    AUTHED = {"RVAL_PLATFORM_API_URL": "http://api.test:9095"}

    def test_new_routes_401_without_credentials(self):
        paths = ["/dashboard", "/api/assessments", "/api/assessments?limit=5",
                 "/api/inventory",
                 f"/runs/{self.run_id}/decision.json",
                 f"/runs/{self.run_id}/report.html"]
        with mock.patch.dict(os.environ, self.AUTHED, clear=False):
            for p in paths:
                status, _, _ = self.get(p)
                self.assertEqual(status, 401, f"GET {p} -> {status}")

    def test_repo_stays_public_without_auth(self):
        with mock.patch.dict(os.environ, self.AUTHED, clear=False):
            status, _, _ = self.get("/repo/manifest.json")
        self.assertEqual(status, 200)


class TestApiAssessments(DashboardServerBase):

    def test_shape_and_chain_ok(self):
        payload = self.get_json("/api/assessments")
        self.assertEqual(payload["schema"], "rval-gateway assessments v1")
        self.assertTrue(payload["chain_ok"])
        self.assertEqual(payload["total"], 2)
        self.assertEqual(payload["limit"], 100)
        self.assertEqual(len(payload["records"]), 2)
        last = payload["records"][-1]
        self.assertEqual(last["record_type"], "assessment")
        self.assertIn("record_hash", last)

    def test_actor_on_new_record_dash_on_legacy(self):
        payload = self.get_json("/api/assessments")
        by_pkg = {r["package"]: r for r in payload["records"]}
        self.assertEqual(by_pkg["dashfix"]["actor"], "qa.user")
        self.assertNotIn("actor", by_pkg["legacypkg"])  # legacy shape kept

    def test_limit_param_and_clamp(self):
        payload = self.get_json("/api/assessments?limit=1")
        self.assertEqual(len(payload["records"]), 1)
        self.assertEqual(payload["limit"], 1)
        payload = self.get_json("/api/assessments?limit=99999")
        self.assertEqual(payload["limit"], 1000)

    def test_broken_chain_reported(self):
        path = self.data_dir / "audit" / "assessments.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        bad = json.loads(lines[-1])
        bad["decision"] = "TAMPERED"  # hash no longer matches
        lines[-1] = json.dumps(bad)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        payload = self.get_json("/api/assessments")
        self.assertFalse(payload["chain_ok"])


class TestApiInventory(DashboardServerBase):

    def test_shape(self):
        payload = self.get_json("/api/inventory")
        self.assertEqual(payload["schema"],
                         "rval-gateway inventory status v1")
        self.assertEqual(payload["snapshot"], "2026-08-01")
        self.assertEqual(len(payload["config_sha256"]), 64)
        rows = {r["name"]: r for r in payload["packages"]}
        self.assertEqual(set(rows), {"dashfix", "legacypkg",
                                     "unassessedpkg"})

        d = rows["dashfix"]
        self.assertTrue(d["assessed"])
        self.assertEqual(d["decision"], "NO-GO")  # skip_score never fabricates
        self.assertIsNone(d["overall_score"])
        self.assertEqual(d["tier"], "gxp-support")
        self.assertEqual(d["actor"], "qa.user")
        self.assertFalse(d["stale"])  # version + config both current
        self.assertEqual(d["stale_reason"], "current")
        self.assertTrue(d["published"])

        legacy = rows["legacypkg"]
        self.assertTrue(legacy["assessed"])
        self.assertEqual(legacy["actor"], dashboard.NO_ACTOR)  # "—"

        u = rows["unassessedpkg"]
        self.assertFalse(u["assessed"])
        self.assertTrue(u["stale"])
        self.assertEqual(u["stale_reason"], "never-assessed")

        totals = payload["totals"]
        self.assertEqual(totals["packages"], 3)
        self.assertEqual(totals["assessed"], 2)
        self.assertEqual(totals["NO-GO"], 1)
        self.assertEqual(totals["GO"], 1)


class TestRunFileServing(DashboardServerBase):

    def test_whitelisted_files_served(self):
        status, body, headers = self.get(f"/runs/{self.run_id}/decision.json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        d = json.loads(body.decode("utf-8"))
        self.assertEqual(d["decision"], "NO-GO")

        status, body, headers = self.get(f"/runs/{self.run_id}/report.html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])

        status, _, _ = self.get(f"/runs/{self.run_id}/evidence.json")
        self.assertEqual(status, 200)

    def test_non_whitelisted_name_404(self):
        status, _, _ = self.get(f"/runs/{self.run_id}/report/report.tex")
        self.assertEqual(status, 404)

    def test_missing_file_404(self):
        # skip_score run never writes score/score.json
        status, _, _ = self.get(f"/runs/{self.run_id}/score/score.json")
        self.assertEqual(status, 404)
        status, _, _ = self.get("/runs/no_such_run/decision.json")
        self.assertEqual(status, 404)

    def test_traversal_rejected(self):
        for p in ("/runs/../decision.json",
                  "/runs/%2e%2e/x/decision.json",
                  "/runs/..%2F..%2Fetc/decision.json"):
            status, body, _ = self.get(p)
            self.assertIn(status, (400, 404), f"GET {p} -> {status}")
            self.assertNotIn(b'"decision"', body)


class TestDashboardPage(DashboardServerBase):

    def test_stat_cards_table_and_gap_section(self):
        status, body, _ = self.get("/dashboard")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        # stat cards
        self.assertIn("id='stat-cards'", page)
        for label in ("inventory", "assessed", "GO", "no-go", "stale",
                      "audit chain"):
            self.assertIn(label, page)
        self.assertIn("✓ intact", page)
        # package table + controls
        self.assertIn("id='pkg-table'", page)
        self.assertIn("id='q'", page)
        self.assertIn("id='dec-filter'", page)
        self.assertIn("dashfix", page)
        self.assertIn("unassessed", page)
        # actor column: new record shows the actor, legacy shows the dash
        self.assertIn("qa.user", page)
        # dependency-gap warning card
        self.assertIn("id='dependency-gaps'", page)
        self.assertIn("missingdep", page)
        # nav (shared skeleton: Intake / Dashboard / Repository links)
        self.assertIn(">Intake</a>", page)
        self.assertIn("href='/repo-view'", page)

    def test_detail_rows_metrics_rules_timeline(self):
        status, body, _ = self.get("/dashboard")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        self.assertIn("Fired rules:", page)
        self.assertIn("Approval timeline", page)
        self.assertIn("assessment", page)
        # skip_score runs have no metrics file -> honest placeholder
        self.assertIn("No per-metric scores on record", page)

    def test_form_page_links_to_dashboard(self):
        status, body, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn('/dashboard', body.decode("utf-8"))


class TestActorPlumbing(DashboardServerBase):

    def test_pipeline_records_actor(self):
        tarball = make_pkg_tarball(self.tmp, pkg="actorfix", version="2.0.0")
        a = pipeline.run_assessment(
            {"upload_path": str(tarball)}, "exploratory",
            data_dir=self.data_dir, skip_score=True, actor="cli.test")
        self.assertEqual(a["audit_record"]["actor"], "cli.test")

    def test_pipeline_actor_defaults_to_none(self):
        tarball = make_pkg_tarball(self.tmp, pkg="noactorfix",
                                   version="3.0.0")
        a = pipeline.run_assessment(
            {"upload_path": str(tarball)}, "exploratory",
            data_dir=self.data_dir, skip_score=True)
        self.assertIsNone(a["audit_record"]["actor"])

    def test_cli_defaults_actor_to_cli(self):
        import run as run_cli
        tarball = make_pkg_tarball(self.tmp, pkg="clifix", version="4.0.0")
        rc = run_cli.main(["--tarball", str(tarball), "--skip-score",
                           "--data-dir", str(self.data_dir)])
        self.assertEqual(rc, 2)  # skip_score -> NO-GO -> exit 2
        log = audit.AuditLog(self.data_dir / "audit" / "assessments.jsonl")
        recs = dashboard.read_audit_records(self.data_dir)
        self.assertEqual(recs[-1]["package"], "clifix")
        self.assertEqual(recs[-1]["actor"], "cli")
        self.assertTrue(log.verify_chain()["ok"])


class TestTimelineUnit(unittest.TestCase):
    """dashboard._timeline on synthetic chain records (incl. esign, which
    the fixture data-dir above never produces offline)."""

    def test_assessment_esign_publish_order(self):
        records = [
            {"record_type": "assessment", "package": "glue",
             "decision": "GO", "tier": "gxp-support", "overall_score": 0.9,
             "actor": "qa.user", "timestamp": "t1",
             "record_hash": "a" * 64},
            {"record_type": "esign", "object_id": "glue 1.7.0",
             "signer_id": "qa.lead", "meaning": "approved",
             "timestamp": "t2", "record_hash": "b" * 64},
            {"record_type": "publish", "package": "glue", "version": "1.7.0",
             "flavor": "source", "esign_signer": "qa.lead",
             "timestamp": "t3", "record_hash": "c" * 64},
            {"record_type": "assessment", "package": "other",
             "timestamp": "t4", "record_hash": "d" * 64},
        ]
        events = dashboard._timeline(records, "glue")
        self.assertEqual([e["event"] for e in events],
                         ["assessment", "esign", "publish"])
        self.assertEqual([e["actor"] for e in events],
                         ["qa.user", "qa.lead", "qa.lead"])
        self.assertTrue(all(e["hash"] for e in events))

    def test_missing_actor_renders_dash(self):
        events = dashboard._timeline(
            [{"record_type": "assessment", "package": "p",
              "timestamp": "t", "record_hash": "a" * 64}], "p")
        self.assertEqual(events[0]["actor"], dashboard.NO_ACTOR)


if __name__ == "__main__":
    unittest.main()
