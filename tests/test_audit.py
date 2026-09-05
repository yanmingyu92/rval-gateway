"""Tests for gateway.audit — append-only hash-chained JSONL."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from gateway import audit
from gateway.audit import AuditLog


class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_audit_test_"))
        self.log = AuditLog(self.tmp / "audit" / "assessments.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_genesis_and_links(self):
        r1 = self.log.append({"record_type": "assessment", "package": "a"})
        r2 = self.log.append({"record_type": "assessment", "package": "b"})
        self.assertEqual(r1["prev_hash"], audit.GENESIS)
        self.assertEqual(r2["prev_hash"], r1["record_hash"])
        self.assertEqual(len(r1["record_hash"]), 64)
        v = self.log.verify_chain()
        self.assertTrue(v["ok"])
        self.assertEqual(v["records"], 2)

    def test_tamper_detection(self):
        self.log.append({"record_type": "assessment", "package": "a"})
        self.log.append({"record_type": "assessment", "package": "b"})
        # tamper: rewrite the first record's payload in place
        lines = self.log.path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["package"] = "forged"
        lines[0] = json.dumps(rec)
        self.log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        v = self.log.verify_chain()
        self.assertFalse(v["ok"])
        self.assertEqual(v["first_bad_index"], 0)

    def test_append_only_no_rewrite(self):
        self.log.append({"record_type": "assessment", "package": "a"})
        before = self.log.path.read_bytes()
        self.log.append({"record_type": "assessment", "package": "b"})
        after = self.log.path.read_bytes()
        self.assertTrue(after.startswith(before))

    def test_empty_log_verifies(self):
        v = self.log.verify_chain()
        self.assertTrue(v["ok"])
        self.assertEqual(v["records"], 0)


if __name__ == "__main__":
    unittest.main()
