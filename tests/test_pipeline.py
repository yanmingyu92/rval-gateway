"""Offline end-to-end pipeline test (skip_score=True forces NO-GO)."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from gateway import audit, pipeline
from test_ingest import make_pkg_tarball


class TestPipelineOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_pipe_test_"))
        self.data_dir = self.tmp / "data"
        self.tarball = make_pkg_tarball(self.tmp, pkg="pipefix", version="2.0.0")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pipeline_skip_score(self):
        a = pipeline.run_assessment(
            {"upload_path": str(self.tarball)}, "gxp-support",
            data_dir=self.data_dir, skip_score=True)
        # no score -> NO-GO with escalation condition, never fabricated
        self.assertEqual(a["decision"]["decision"], "NO-GO")
        self.assertIsNone(a["decision"]["overall_score"])
        self.assertIn("score_error", a["decision"])
        # artifacts exist
        self.assertTrue(Path(a["evidence_path"]).is_file())
        self.assertTrue(Path(a["decision_path"]).is_file())
        self.assertTrue(Path(a["report"]["html"]).is_file())
        # evidence carries local facts even with no network/score
        metrics = [e["metric"] for e in a["evidence"]["entries"]]
        self.assertIn("description.version", metrics)
        self.assertIn("tarball.sha256", metrics)
        # audit chain
        log = audit.AuditLog(a["audit_log"])
        v = log.verify_chain()
        self.assertTrue(v["ok"])
        rec = a["audit_record"]
        self.assertEqual(rec["package"], "pipefix")
        self.assertEqual(rec["decision"], "NO-GO")
        self.assertEqual(rec["tarball_sha256"], a["ingest"]["sha256"])
        self.assertEqual(len(rec["config_sha256"]), 64)
        # decision JSON on disk round-trips
        d = json.loads(Path(a["decision_path"]).read_text(encoding="utf-8"))
        self.assertEqual(d["tier"], "gxp-support")


if __name__ == "__main__":
    unittest.main()
