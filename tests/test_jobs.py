"""Tests for the async assessment job model (POST /assess -> 202 + job_id,
GET /api/jobs/<id> state machine, GET /jobs/<id> result page, 429
concurrency cap) and the gated /static/ asset route.

Offline: pipeline.run_assessment is stubbed with a fast fake that writes a
minimal run dir; the HTTP layer runs against a real ThreadingHTTPServer on
an ephemeral localhost port (same pattern as tests/test_dashboard.py).
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from gateway import jobs, pipeline, server

_STRIP_ENV = ("RVAL_PLATFORM_API_URL", "GATEWAY_BASE_PATH")


def fake_assessment(data_dir, decision="GO", fail=None, hold=None):
    """Fast stand-in for pipeline.run_assessment: writes a minimal run dir
    (decision.json only) and returns the assessment-shaped dict the jobs
    worker needs."""
    def run(spec, tier, actor=None, classification=None, **kw):
        if hold is not None:
            hold.wait(timeout=10)
        if fail:
            raise RuntimeError(fail)
        pkg = spec.get("package") or "upkg"
        ver = spec.get("version") or "1.0"
        run_id = f"{pkg}_{ver}_2099-01-01T000000Z"
        run_dir = Path(data_dir) / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "decision.json").write_text(json.dumps({
            "decision": decision, "tier": tier, "overall_score": 0.2,
            "config_version": "1"}), encoding="utf-8")
        return {
            "ingest": {"package": pkg, "version": ver},
            "run_dir": str(run_dir),
            "audit_record": {"record_hash": "ab" * 32},
            "report": {"pdf": None, "pdf_note": "pdflatex not on PATH"},
        }
    return run


class JobServerBase(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_jobs_test_"))
        self.data_dir = self.tmp / "data"
        self._saved_env = {}
        for k in _STRIP_ENV:
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

    def req(self, path, data=None, accept=None):
        headers = {}
        if accept:
            headers["Accept"] = accept
        r = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data,
            headers=headers)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers

    def post_assess(self, fields, accept="application/json"):
        body = urllib.parse.urlencode(fields).encode()
        return self.req("/assess", data=body, accept=accept)

    def wait_job(self, job_id, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            status, body, _ = self.req(f"/api/jobs/{job_id}")
            payload = json.loads(body.decode("utf-8"))
            if payload["status"] in ("done", "failed"):
                return payload
            time.sleep(0.05)
        self.fail(f"job {job_id} did not finish within {timeout}s")


class TestAssessAsyncContract(JobServerBase):

    def test_post_assess_returns_202_job(self):
        with mock.patch.object(pipeline, "run_assessment",
                               fake_assessment(self.data_dir)):
            status, body, _ = self.post_assess({"pkg": "jobpkg",
                                                "tier": "exploratory"})
        self.assertEqual(status, 202)
        payload = json.loads(body.decode("utf-8"))
        self.assertIn("job_id", payload)
        self.assertIn(payload["status"], ("queued", "running"))
        self.assertTrue(payload["status_url"].startswith("/api/jobs/"))
        self.assertTrue(payload["page_url"].startswith("/jobs/"))

    def test_post_assess_html_fallback_page(self):
        """Without an Accept: application/json header the 202 is an HTML
        waiting page that forwards to the job page (no-JS browsers)."""
        with mock.patch.object(pipeline, "run_assessment",
                               fake_assessment(self.data_dir)):
            status, body, _ = self.post_assess({"pkg": "jobpkg"}, accept=None)
        self.assertEqual(status, 202)
        h = body.decode("utf-8")
        self.assertIn("http-equiv='refresh'", h)
        self.assertIn("/jobs/", h)

    def test_job_done_state_machine(self):
        with mock.patch.object(pipeline, "run_assessment",
                               fake_assessment(self.data_dir)):
            _, body, _ = self.post_assess({"pkg": "jobpkg"})
            job_id = json.loads(body.decode("utf-8"))["job_id"]
            final = self.wait_job(job_id)
        self.assertEqual(final["status"], "done")
        self.assertEqual(final["package"], "jobpkg")
        self.assertTrue(final["run_id"].startswith("jobpkg_1.0_"))
        self.assertIn("record_hash", final)

    def test_job_failed_state(self):
        with mock.patch.object(pipeline, "run_assessment",
                               fake_assessment(self.data_dir,
                                               fail="boom")):
            _, body, _ = self.post_assess({"pkg": "jobpkg"})
            job_id = json.loads(body.decode("utf-8"))["job_id"]
            final = self.wait_job(job_id)
        self.assertEqual(final["status"], "failed")
        self.assertIn("boom", final["error"])

    def test_unknown_job_is_lost_404(self):
        status, body, _ = self.req("/api/jobs/deadbeef00")
        self.assertEqual(status, 404)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["status"], "lost")
        status, body, _ = self.req("/jobs/deadbeef00")
        self.assertEqual(status, 404)
        self.assertIn(b"Job lost, please resubmit", body)

    def test_job_page_renders_summary_when_done(self):
        with mock.patch.object(pipeline, "run_assessment",
                               fake_assessment(self.data_dir)):
            _, body, _ = self.post_assess({"pkg": "jobpkg"})
            job_id = json.loads(body.decode("utf-8"))["job_id"]
            self.wait_job(job_id)
            status, body, _ = self.req(f"/jobs/{job_id}")
        self.assertEqual(status, 200)
        h = body.decode("utf-8")
        self.assertIn("gw-badge-go", h)          # decision badge
        self.assertIn("jobpkg", h)
        self.assertIn("/report.html", h)         # full-report link
        self.assertIn("/publish", h)             # GO -> publish form

    def test_job_page_fragment_mode(self):
        with mock.patch.object(pipeline, "run_assessment",
                               fake_assessment(self.data_dir,
                                               decision="NO-GO")):
            _, body, _ = self.post_assess({"pkg": "nogopkg"})
            job_id = json.loads(body.decode("utf-8"))["job_id"]
            self.wait_job(job_id)
            status, body, _ = self.req(f"/jobs/{job_id}?fragment=1")
        self.assertEqual(status, 200)
        h = body.decode("utf-8")
        self.assertIn("gw-badge-nogo", h)
        self.assertIn("/remediate", h)           # NO-GO -> remediation form
        self.assertNotIn("<html", h)             # fragment, not a full page

    def test_concurrency_cap_returns_429(self):
        hold = threading.Event()
        try:
            with mock.patch.object(jobs, "MAX_CONCURRENT", 1), \
                 mock.patch.object(pipeline, "run_assessment",
                                   fake_assessment(self.data_dir, hold=hold)):
                status, body, _ = self.post_assess({"pkg": "slowpkg"})
                self.assertEqual(status, 202)
                status, body, _ = self.post_assess({"pkg": "fastpkg"})
                self.assertEqual(status, 429)
                payload = json.loads(body.decode("utf-8"))
                self.assertEqual(payload["status"], "busy")
        finally:
            hold.set()  # release the held worker


class TestStaticRoute(JobServerBase):

    def test_whitelisted_assets_served(self):
        status, body, headers = self.req("/static/gateway.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers["Content-Type"])
        self.assertIn(b"--kg-accent", body)
        status, body, headers = self.req("/static/bootstrap.min.css")
        self.assertEqual(status, 200)
        status, body, headers = self.req("/static/bootstrap-icons.css")
        self.assertEqual(status, 200)
        # icon font URL rewritten to a relative path (base-path safe)
        self.assertIn(b'url("fonts/bootstrap-icons.woff2")', body)
        status, _, headers = self.req("/static/fonts/bootstrap-icons.woff2")
        self.assertEqual(status, 200)
        self.assertIn("font/woff2", headers["Content-Type"])
        status, _, headers = self.req("/static/favicon.svg")
        self.assertEqual(status, 200)
        self.assertIn("image/svg", headers["Content-Type"])

    def test_non_whitelisted_name_404(self):
        status, _, _ = self.req("/static/server.py")
        self.assertEqual(status, 404)
        status, _, _ = self.req("/static/../gateway/server.py")
        self.assertIn(status, (400, 404))

    def test_pages_link_versioned_static_urls(self):
        """Cache-busting: pages must reference /static/... with a ?v= query
        so a deploy invalidates the 1h browser cache."""
        status, body, _ = self.req("/")
        self.assertEqual(status, 200)
        h = body.decode("utf-8")
        self.assertRegex(h, r"/static/gateway\.css\?v=[0-9]")
        self.assertRegex(h, r"/static/bootstrap-icons\.css\?v=")
        # the query string does not break routing (path is parsed clean)
        status, _, headers = self.req("/static/gateway.css?v=0.0.0")
        self.assertEqual(status, 200)

    def test_traversal_rejected(self):
        for p in ("/static/../server.py",
                  "/static/%2e%2e/server.py",
                  "/static/fonts/../../../../etc/passwd"):
            status, body, _ = self.req(p)
            self.assertIn(status, (400, 404), f"GET {p} -> {status}")
            self.assertNotIn(b"import", body)


class TestStaticAuthGate(JobServerBase):
    """/static/ and /api/jobs/ go through _gate() like every other route."""

    AUTHED = {"RVAL_PLATFORM_API_URL": "http://api.test:9095"}

    def test_static_and_jobs_401_without_credentials(self):
        with mock.patch.dict(os.environ, self.AUTHED, clear=False):
            for p in ("/static/gateway.css", "/api/jobs/whatever",
                      "/jobs/whatever"):
                status, _, _ = self.req(p)
                self.assertEqual(status, 401, f"GET {p} -> {status}")

    def test_health_and_repo_stay_public(self):
        with mock.patch.dict(os.environ, self.AUTHED, clear=False):
            status, _, _ = self.req("/health")
            self.assertEqual(status, 200)


class TestHowItWorksPage(JobServerBase):

    def test_page_renders_config_driven_content(self):
        status, body, _ = self.req("/how-it-works")
        self.assertEqual(status, 200)
        h = body.decode("utf-8")
        for marker in ("How the gateway works", "{riskmetric}",
                       "Evidence-bound reporting", "dual approval",
                       "OpenVal", "Axon.R", "Litmus",
                       "0.3", "0.6",       # exploratory thresholds
                       "code", "maintenance", "documentation",
                       "popularity"):
            self.assertIn(marker, h)
        # shared skeleton + nav tab present and active
        self.assertIn(">How it works</a>", h)

    def test_thresholds_track_config(self):
        """The tier table is rendered from the live rule config, not
        hardcoded: a config bump changes the page."""
        from gateway import decision as decision_mod
        cfg = decision_mod.RuleSet.load()
        low = cfg.tiers["exploratory"]["low"]
        _, body, _ = self.req("/how-it-works")
        self.assertIn(f"<b>{low}</b>", body.decode("utf-8"))

    def test_how_it_works_gated(self):
        with mock.patch.dict(os.environ,
                             {"RVAL_PLATFORM_API_URL": "http://api.test:9095"},
                             clear=False):
            status, _, _ = self.req("/how-it-works")
            self.assertEqual(status, 401)


class TestScoreBar(unittest.TestCase):

    def test_fill_width_and_band_class(self):
        from gateway import webui
        h = webui.score_bar(0.2)
        self.assertIn("width:20.0%", h)
        self.assertIn("fill low", h)
        h = webui.score_bar(0.9)
        self.assertIn("fill high", h)
        # the CSS must blockify the inline spans or the fill collapses
        css = (server.STATIC_DIR / "gateway.css").read_text(encoding="utf-8")
        self.assertIn(".gw-score .track {\n  display: block;", css)
        self.assertIn(".gw-score .fill { display: block;", css)


if __name__ == "__main__":
    unittest.main()
