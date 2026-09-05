"""Tests for gateway.esign — 21 CFR Part 11 electronic signatures.

Offline: the platform login API is mocked at the urllib boundary.
"""
import json
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from gateway import esign
from gateway.audit import AuditLog


class ESIGNTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_esign_test_"))
        self.log = AuditLog(self.tmp / "audit" / "assessments.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._payload


class TestReauthenticate(unittest.TestCase):
    API = "http://platform-api.local"

    def test_success_returns_identity(self):
        with mock.patch("urllib.request.urlopen",
                        return_value=FakeResponse(
                            200, {"user_id": ["alice"], "role": ["Analyst"]})):
            auth = esign.reauthenticate(self.API, "alice", "pw")
        self.assertEqual(auth["user_id"], "alice")
        self.assertEqual(auth["role"], "Analyst")

    def test_http_401_refused(self):
        def raise_401(*a, **k):
            raise urllib.error.HTTPError("u", 401, "Unauthorized", None, None)
        with mock.patch("urllib.request.urlopen", side_effect=raise_401):
            with self.assertRaises(esign.ESIGNAuthError) as cm:
                esign.reauthenticate(self.API, "alice", "bad")
        self.assertIn("HTTP 401", str(cm.exception))

    def test_transport_failure_fails_closed(self):
        with mock.patch("urllib.request.urlopen",
                        side_effect=OSError("conn refused")):
            with self.assertRaises(esign.ESIGNAuthError) as cm:
                esign.reauthenticate(self.API, "alice", "pw")
        self.assertIn("unreachable", str(cm.exception))
        self.assertIn("fail closed", str(cm.exception))

    def test_missing_api_url_refused(self):
        with self.assertRaises(esign.ESIGNAuthError):
            esign.reauthenticate("", "alice", "pw")


class TestSign(ESIGNTestBase):
    def test_sign_appends_chained_record(self):
        with mock.patch("gateway.esign.reauthenticate",
                        return_value={"user_id": "bob", "role": "QA"}):
            rec = esign.sign(self.log, "approved", "bob", "pw",
                             "http://api", "assessment", "glue 1.7.0",
                             "ab" * 32)
        self.assertEqual(rec["record_type"], "esign")
        self.assertEqual(rec["meaning"], "approved")
        self.assertEqual(rec["signer_id"], "bob")
        self.assertEqual(rec["signer_role"], "QA")
        self.assertEqual(rec["object_hash"], "ab" * 32)
        self.assertEqual(rec["reauth_method"], "platform-login")
        v = self.log.verify_chain()
        self.assertTrue(v["ok"])

    def test_sign_rejects_unknown_meaning(self):
        with self.assertRaises(esign.ESIGNError):
            esign.make_esign_record("maybe", "bob", "QA", "assessment",
                                    "x", "h")

    def test_sign_propagates_auth_failure(self):
        with mock.patch("gateway.esign.reauthenticate",
                        side_effect=esign.ESIGNAuthError("nope")):
            with self.assertRaises(esign.ESIGNAuthError):
                esign.sign(self.log, "approved", "bob", "pw", "http://api",
                           "assessment", "x", "h")
        # nothing appended on failure
        self.assertEqual(self.log.verify_chain()["records"], 0)


class TestValidateForPublish(ESIGNTestBase):
    def _signed(self, meaning="approved", object_hash="ab" * 32):
        rec = self.log.append(esign.make_esign_record(
            meaning, "bob", "QA", "assessment", "glue 1.7.0", object_hash))
        return rec

    def test_valid_signature_passes(self):
        rec = self._signed()
        out = esign.validate_for_publish(
            self.log._records(), rec, "ab" * 32)
        self.assertEqual(out["signer_id"], "bob")

    def test_missing_record_refused(self):
        with self.assertRaises(esign.ESIGNError):
            esign.validate_for_publish(self.log._records(), None, "ab" * 32)

    def test_record_not_in_chain_refused(self):
        rec = self._signed()
        forged = dict(rec)
        forged["meaning"] = "approved"
        forged["record_hash"] = "ff" * 32  # not chained
        with self.assertRaises(esign.ESIGNError) as cm:
            esign.validate_for_publish(self.log._records(), forged, "ab" * 32)
        self.assertIn("not found in the audit chain", str(cm.exception))

    def test_wrong_meaning_refused(self):
        rec = self._signed(meaning="rejected")
        with self.assertRaises(esign.ESIGNError) as cm:
            esign.validate_for_publish(self.log._records(), rec, "ab" * 32)
        self.assertIn("'approved' required", str(cm.exception))

    def test_object_hash_mismatch_refused(self):
        rec = self._signed(object_hash="cd" * 32)
        with self.assertRaises(esign.ESIGNError) as cm:
            esign.validate_for_publish(self.log._records(), rec, "ab" * 32)
        self.assertIn("does not bind the assessment", str(cm.exception))

    def test_incomplete_record_refused(self):
        rec = self._signed()
        rec.pop("reauth_method")
        # re-append mutated copy so the chain contains it without the field
        rec2 = dict(rec)
        rec2.pop("record_hash", None)
        chained = self.log.append(rec2)
        with self.assertRaises(esign.ESIGNError) as cm:
            esign.validate_for_publish(self.log._records(), chained, "ab" * 32)
        self.assertIn("incomplete", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
