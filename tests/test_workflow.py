"""Tests for Phase D workflow hardening: dual approval for gxp-critical
publishes, the NO-GO remediation loop, and the dashboard staleness banner.

Offline: fixture tarballs + synthetic audit logs; esign re-authentication is
mocked (same pattern as tests/test_repo.py); the HTTP tests run against a
real ThreadingHTTPServer on an ephemeral localhost port with auth off
(same pattern as tests/test_dashboard.py).
"""

import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from gateway import audit, dashboard, esign, pipeline, repo, server
from gateway.audit import AuditLog
from gateway.repo import RepoError
from test_ingest import make_pkg_tarball

_STRIP_ENV = ("RVAL_PLATFORM_API_URL", "GATEWAY_BASE_PATH")


def assess_record(log: AuditLog, pkg, ver, sha, dec, tier="exploratory"):
    return log.append({
        "record_type": "assessment", "input_spec": {"package": pkg},
        "package": pkg, "version": ver, "origin": "cran",
        "source_url": None, "tarball_sha256": sha,
        "collection_mode": "network", "r_version": "R version 4.6.0",
        "riskmetric_version": "0.2.7", "config_version": "1.0.0",
        "config_sha256": "ab" * 32, "overall_score": 0.2, "decision": dec,
        "tier": tier, "fired_rules": [], "conditions": [],
        "assessed_at": "t", "timestamp": "t",
    })


def fake_reauth(api_url, user_id, password):
    """Offline stand-in for esign.reauthenticate: any non-empty password
    authenticates as the requested user."""
    if not password:
        raise esign.ESIGNAuthError(
            "re-authentication failed (HTTP 401) — signature refused")
    return {"user_id": user_id, "role": "Analyst"}


class WorkflowRepoBase(unittest.TestCase):
    """Tmp data-dir with one pinned tarball; esign re-authentication mocked
    so publish() runs the full signature -> chain -> publish path offline."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_wf_test_"))
        self.data = self.tmp / "data"
        self.log = AuditLog(self.data / "audit" / "assessments.jsonl")
        tb = make_pkg_tarball(self.tmp, pkg="goodpkg", version="1.0.0")
        store = self.data / "tarballs" / "goodpkg" / "1.0.0"
        store.mkdir(parents=True)
        self.tarball = store / tb.name
        shutil.copy(tb, self.tarball)
        self.sha = repo._sha256(self.tarball)
        reauth = mock.patch("gateway.esign.reauthenticate",
                            side_effect=fake_reauth)
        self.mock_reauth = reauth.start()
        self.addCleanup(reauth.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def records(self):
        return [json.loads(line) for line in
                self.log.path.read_text(encoding="utf-8").splitlines()]


class TestDualApproval(WorkflowRepoBase):

    def test_two_distinct_signers_publish_gxp_critical(self):
        gate = assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                             "GO-WITH-CONDITIONS", tier="gxp-critical")
        res = repo.publish("goodpkg", "1.0.0", data_dir=self.data,
                           signers=[("qa.one", "pw1"), ("qa.two", "pw2")])
        self.assertTrue(res["published"])
        self.assertEqual([s["signer_id"] for s in res["esign_signatures"]],
                         ["qa.one", "qa.two"])
        # chain: assessment + 2 esign + publish, all verified
        v = self.log.verify_chain()
        self.assertTrue(v["ok"])
        self.assertEqual(v["records"], 4)
        recs = self.records()
        esign_recs = [r for r in recs if r["record_type"] == "esign"]
        self.assertEqual(len(esign_recs), 2)
        for r in esign_recs:
            self.assertEqual(r["meaning"], "approved")
            self.assertEqual(r["object_hash"], gate["record_hash"])
        pub = recs[-1]
        self.assertEqual(pub["record_type"], "publish")
        self.assertEqual([s["signer_id"] for s in pub["esign_signatures"]],
                         ["qa.one", "qa.two"])
        self.assertEqual({s["record_hash"] for s in pub["esign_signatures"]},
                         {r["record_hash"] for r in esign_recs})
        # backward-compatible first-signature fields
        self.assertEqual(pub["esign_signer"], "qa.one")
        # manifest carries the full signature list too
        art = repo.load_manifest(self.data)["artifacts"][0]
        self.assertEqual([s["signer_id"] for s in art["esign_signatures"]],
                         ["qa.one", "qa.two"])
        self.assertEqual(art["assessment_tier"], "gxp-critical")

    def test_single_signer_refused_gxp_critical(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                      "GO-WITH-CONDITIONS", tier="gxp-critical")
        with self.assertRaises(RepoError) as cm:
            repo.publish("goodpkg", "1.0.0", data_dir=self.data,
                         signers=[("qa.one", "pw1")])
        self.assertIn("dual approval", str(cm.exception))
        self.assertIn("2 distinct signers", str(cm.exception))
        # refused before any signature event was appended
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])

    def test_same_signer_twice_refused(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                      "GO-WITH-CONDITIONS", tier="gxp-critical")
        with self.assertRaises(RepoError) as cm:
            repo.publish("goodpkg", "1.0.0", data_dir=self.data,
                         signers=[("qa.one", "pw1"), ("qa.one", "pw2")])
        self.assertIn("distinct signer", str(cm.exception))
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])

    def test_invalid_second_signature_refused(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                      "GO-WITH-CONDITIONS", tier="gxp-critical")
        with self.assertRaises(RepoError) as cm:
            repo.publish("goodpkg", "1.0.0", data_dir=self.data,
                         signers=[("qa.one", "pw1"), ("qa.two", "")])
        self.assertIn("signature refused", str(cm.exception))
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])
        recs = self.records()
        # the first (valid) signature stays on the append-only chain —
        # honest — but no publish record exists
        self.assertEqual([r["record_type"] for r in recs],
                         ["assessment", "esign"])
        self.assertTrue(self.log.verify_chain()["ok"])

    def test_single_signer_ok_exploratory(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO",
                      tier="exploratory")
        res = repo.publish("goodpkg", "1.0.0", data_dir=self.data,
                           signers=[("qa.one", "pw1")])
        self.assertTrue(res["published"])
        self.assertEqual(len(res["esign_signatures"]), 1)
        self.assertEqual(res["esign_signer"], "qa.one")

    def test_single_signer_ok_gxp_support(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO",
                      tier="gxp-support")
        res = repo.publish("goodpkg", "1.0.0", data_dir=self.data,
                           signer_id="qa.one", signer_password="pw1")
        self.assertTrue(res["published"])
        self.assertEqual(len(res["esign_signatures"]), 1)


class TestCliPublish(WorkflowRepoBase):

    def test_cli_dual_signer_publish(self):
        import run as run_cli
        assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                      "GO-WITH-CONDITIONS", tier="gxp-critical")
        with mock.patch("getpass.getpass", return_value="pw"):
            rc = run_cli.main(["--publish", "--pkg", "goodpkg",
                               "--version", "1.0.0",
                               "--data-dir", str(self.data),
                               "--signer", "qa.one", "--signer", "qa.two"])
        self.assertEqual(rc, 0)
        pub = self.records()[-1]
        self.assertEqual(pub["record_type"], "publish")
        self.assertEqual(len(pub["esign_signatures"]), 2)

    def test_cli_single_signer_gxp_critical_refused(self):
        import run as run_cli
        assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                      "GO-WITH-CONDITIONS", tier="gxp-critical")
        with mock.patch("getpass.getpass", return_value="pw"):
            rc = run_cli.main(["--publish", "--pkg", "goodpkg",
                               "--version", "1.0.0",
                               "--data-dir", str(self.data),
                               "--signer", "qa.one"])
        self.assertEqual(rc, 2)  # refused publish
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])


class TestRemediationUnit(WorkflowRepoBase):

    def test_remediation_record_and_timeline_linkage(self):
        nogo = assess_record(self.log, "goodpkg", "1.0.0", self.sha, "NO-GO",
                             tier="gxp-support")
        rec = self.log.append(audit.make_remediation_record(
            package="goodpkg", version="1.0.0",
            assessment_record_hash=nogo["record_hash"],
            note="escalated to Tier 2 full validation", actor="qa.one"))
        self.assertTrue(self.log.verify_chain()["ok"])
        self.assertEqual(rec["record_type"], "remediation")
        self.assertEqual(rec["assessment_record_hash"],
                         nogo["record_hash"])
        events = dashboard._timeline(self.records(), "goodpkg")
        self.assertEqual([e["event"] for e in events],
                         ["assessment", "remediation"])
        rem = events[-1]
        self.assertEqual(rem["actor"], "qa.one")
        self.assertIn(nogo["record_hash"][:12], rem["detail"])
        self.assertIn("Tier 2", rem["detail"])

    def test_remediation_of_other_package_not_in_timeline(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "NO-GO")
        self.log.append(audit.make_remediation_record(
            package="otherpkg", version="2.0",
            assessment_record_hash="ff" * 32, note="unrelated"))
        events = dashboard._timeline(self.records(), "goodpkg")
        self.assertEqual([e["event"] for e in events], ["assessment"])


class RemediateServerBase(unittest.TestCase):
    """Real HTTP layer, auth off (dev mode): one skip_score (NO-GO)
    assessment in a tmp data-dir."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_remed_test_"))
        self.data_dir = self.tmp / "data"
        tarball = make_pkg_tarball(self.tmp, pkg="nogofix", version="1.0.0")
        a = pipeline.run_assessment(
            {"upload_path": str(tarball)}, "gxp-support",
            data_dir=self.data_dir, skip_score=True, actor="qa.user")
        self.nogo_hash = a["audit_record"]["record_hash"]
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

    def post(self, path, fields):
        body = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def remediate(self, **over):
        fields = {"package": "nogofix", "version": "1.0.0",
                  "assessment_record_hash": self.nogo_hash,
                  "note": "pin an older version and re-assess"}
        fields.update(over)
        return self.post("/remediate", fields)


class TestRemediateRoute(RemediateServerBase):

    def test_remediation_accepted_and_in_timeline(self):
        status, body = self.remediate()
        self.assertEqual(status, 200)
        self.assertIn(b"Remediation recorded", body)
        records = dashboard.read_audit_records(self.data_dir)
        rem = records[-1]
        self.assertEqual(rem["record_type"], "remediation")
        self.assertEqual(rem["package"], "nogofix")
        self.assertEqual(rem["assessment_record_hash"], self.nogo_hash)
        self.assertIn("pin an older version", rem["note"])
        # linkage visible in the shared approval timeline
        events = dashboard._timeline(records, "nogofix")
        self.assertEqual([e["event"] for e in events],
                         ["assessment", "remediation"])
        self.assertIn(self.nogo_hash[:12], events[-1]["detail"])
        log = AuditLog(self.data_dir / "audit" / "assessments.jsonl")
        self.assertTrue(log.verify_chain()["ok"])

    def test_remediation_refused_for_non_nogo(self):
        log = AuditLog(self.data_dir / "audit" / "assessments.jsonl")
        go = assess_record(log, "nogofix", "9.9", "ab" * 32, "GO")
        status, body = self.remediate(version="9.9",
                                      assessment_record_hash=go["record_hash"])
        self.assertEqual(status, 403)
        self.assertIn(b"NO-GO assessments only", body)

    def test_remediation_refused_for_unknown_record(self):
        status, _ = self.remediate(assessment_record_hash="ff" * 32)
        self.assertEqual(status, 403)

    def test_remediation_requires_note(self):
        status, _ = self.remediate(note="")
        self.assertEqual(status, 400)


class TestPublishAndRemediationForms(unittest.TestCase):
    """The post-assessment forms state the workflow honestly."""

    def test_gxp_critical_form_requires_two_signers(self):
        form = server._publish_form("goodpkg", "1.0.0", "gxp-critical")
        self.assertIn("esign_signer2", form)
        self.assertIn("esign_password2", form)
        self.assertIn("Dual approval required", form)
        self.assertIn("two distinct signers", form)

    def test_other_tiers_form_single_signer(self):
        for tier in ("exploratory", "gxp-support"):
            form = server._publish_form("goodpkg", "1.0.0", tier)
            self.assertIn("esign_signer", form)
            self.assertNotIn("esign_signer2", form)
            self.assertNotIn("Dual approval", form)

    def test_remediation_form_links_assessment(self):
        form = server._remediation_form("nogofix", "1.0.0", "ab" * 32)
        self.assertIn("/remediate", form)
        self.assertIn("assessment_record_hash", form)
        self.assertIn("ab" * 32, form)
        self.assertIn("name='note'", form)


class TestStalenessBanner(unittest.TestCase):
    """Banner present when any inventory package is stale, absent otherwise.
    render_html is exercised directly with crafted rows (the staleness data
    itself comes from run_inventory.staleness, covered elsewhere)."""

    URL = staticmethod(lambda p: p)

    def _data(self, rows):
        return {"snapshot": "2026-08-01",
                "chain": {"ok": True, "records": 0},
                "totals": dashboard._totals(rows),
                "rows": rows,
                "dependency_gaps": []}

    def _row(self, name, stale, reason):
        return {"name": name, "version": "1.0", "sources": ["code"],
                "assessed": True, "tier": "exploratory",
                "overall_score": 0.2, "decision": "GO", "actor": "qa.user",
                "assessed_at": "t", "stale": stale, "stale_reason": reason,
                "published": False, "published_version": None}

    def test_banner_present_with_reason_breakdown(self):
        rows = [self._row("aaa", True, "version-mismatch"),
                self._row("bbb", True, "config-changed"),
                self._row("ccc", True, "config-changed"),
                self._row("ddd", False, "current")]
        page = dashboard.render_html(self._data(rows), self.URL).decode()
        self.assertIn("id='stale-banner'", page)
        self.assertIn("3 packages are stale", page)
        self.assertIn("version/config/snapshot drift", page)
        self.assertIn("rerun inventory assessment", page)
        self.assertIn("config-changed: 2", page)
        self.assertIn("version-mismatch: 1", page)

    def test_banner_absent_when_all_current(self):
        rows = [self._row("aaa", False, "current"),
                self._row("bbb", False, "current")]
        page = dashboard.render_html(self._data(rows), self.URL).decode()
        self.assertNotIn("stale-banner", page)
        self.assertNotIn("are stale", page)


if __name__ == "__main__":
    unittest.main()
