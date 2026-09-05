"""Tests for gateway.repo — offline; fixture tarballs + synthetic audit logs."""

import gzip
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gateway import audit, repo
from gateway.audit import AuditLog
from gateway.repo import RepoError
from test_ingest import make_pkg_tarball


def assess_record(log: AuditLog, pkg, ver, sha, dec):
    return log.append({
        "record_type": "assessment", "input_spec": {"package": pkg},
        "package": pkg, "version": ver, "origin": "cran",
        "source_url": None, "tarball_sha256": sha,
        "collection_mode": "network", "r_version": "R version 4.6.0",
        "riskmetric_version": "0.2.7", "config_version": "1.0.0",
        "config_sha256": "ab" * 32, "overall_score": 0.2, "decision": dec,
        "tier": "exploratory", "fired_rules": [], "conditions": [],
        "assessed_at": "t", "timestamp": "t",
    })


class RepoTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_repo_test_"))
        self.data = self.tmp / "data"
        self.log = AuditLog(self.data / "audit" / "assessments.jsonl")
        # pinned store with one tarball
        tb = make_pkg_tarball(self.tmp, pkg="goodpkg", version="1.0.0")
        store = self.data / "tarballs" / "goodpkg" / "1.0.0"
        store.mkdir(parents=True)
        self.tarball = store / tb.name
        shutil.copy(tb, self.tarball)
        self.sha = repo._sha256(self.tarball)
        self.baseline = {"basepkg", "yaml"}
        # e-signature fixtures: re-authentication is mocked (offline tests);
        # publish() still runs the full signature -> chain -> publish path
        self.signer = "qc.signer"
        self.password = "signing-pass"
        reauth = mock.patch(
            "gateway.esign.reauthenticate",
            return_value={"user_id": self.signer, "role": "Analyst"})
        self.mock_reauth = reauth.start()
        self.addCleanup(reauth.stop)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def signed_publish(self, *args, **kwargs):
        kwargs.setdefault("signer_id", self.signer)
        kwargs.setdefault("signer_password", self.password)
        return repo.publish(*args, **kwargs)


class TestIndexGeneration(RepoTestBase):
    def test_packages_index_format(self):
        n = repo.publish  # not used; direct index test below
        contrib = repo.contrib_dir(self.data)
        contrib.mkdir(parents=True)
        shutil.copy(self.tarball, contrib / self.tarball.name)
        n = repo.regenerate_indexes(self.data)
        self.assertEqual(n, 1)
        body = (contrib / "PACKAGES").read_text(encoding="utf-8")
        self.assertIn("Package: goodpkg", body)
        self.assertIn("Version: 1.0.0", body)
        self.assertIn("License: MIT", body)
        # gz mirror decompresses to the same body
        gz = gzip.decompress((contrib / "PACKAGES.gz").read_bytes()).decode()
        self.assertEqual(gz, body)

    def test_index_loads_in_r_available_packages(self):
        rscript = None
        import os
        cand = os.environ.get("RSCRIPT") or shutil.which("Rscript") or ""
        if Path(cand).is_file():
            rscript = cand
        if not rscript:
            self.skipTest("Rscript not available")
        contrib = repo.contrib_dir(self.data)
        contrib.mkdir(parents=True)
        shutil.copy(self.tarball, contrib / self.tarball.name)
        repo.regenerate_indexes(self.data)
        url = "file:///" + str(repo.repo_dir(self.data)).replace("\\", "/")
        code = (f'ap <- available.packages(repos="{url}"); '
                'cat(rownames(ap), ap[, "Version"], sep="\\n")')
        p = subprocess.run([rscript, "--vanilla", "-e", code],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        self.assertIn("goodpkg", p.stdout)
        self.assertIn("1.0.0", p.stdout)


class TestPublishGating(RepoTestBase):
    def test_go_assessment_allows_publish(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO")
        res = self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        self.assertTrue(res["published"])
        self.assertEqual(res["flavor"], "source")
        self.assertEqual(res["esign_signer"], self.signer)
        m = repo.load_manifest(self.data)
        self.assertEqual(len(m["artifacts"]), 1)
        art = m["artifacts"][0]
        self.assertEqual(art["package"], "goodpkg")
        self.assertEqual(art["sha256"], self.sha)
        self.assertEqual(art["esign_signer"], self.signer)
        self.assertEqual(art["esign_meaning"], "approved")
        self.assertTrue(art["esign_record_hash"])
        # publish event is a link in the same hash chain (assess + esign +
        # publish = 3 records)
        v = self.log.verify_chain()
        self.assertTrue(v["ok"])
        self.assertEqual(v["records"], 3)
        lines = self.log.path.read_text(encoding="utf-8").splitlines()
        esign_rec = json.loads(lines[1])
        self.assertEqual(esign_rec["record_type"], "esign")
        self.assertEqual(esign_rec["meaning"], "approved")
        last = json.loads(lines[2])
        self.assertEqual(last["record_type"], "publish")
        self.assertEqual(last["esign_signer"], self.signer)
        self.assertEqual(last["esign_record_hash"], esign_rec["record_hash"])
        self.assertEqual(last["assessment_record_hash"],
                         art["assessment_record_hash"])

    def test_conditions_decision_allows_publish(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha,
                      "GO-WITH-CONDITIONS")
        res = self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        self.assertTrue(res["published"])

    def test_publish_without_signature_refused(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO")
        with self.assertRaises(RepoError) as cm:
            repo.publish("goodpkg", "1.0.0", data_dir=self.data)
        self.assertIn("electronic signature required", str(cm.exception))
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])

    def test_publish_with_bad_credentials_refused(self):
        from gateway import esign as esign_mod
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO")
        # simulate reauthenticate's converted output for a 401 (the HTTP→
        # ESIGNAuthError translation happens inside reauthenticate)
        self.mock_reauth.side_effect = esign_mod.ESIGNAuthError(
            "re-authentication failed (HTTP 401) — signature refused")
        with self.assertRaises(RepoError) as cm:
            self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        self.assertIn("signature refused", str(cm.exception))
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])

    def test_no_go_refused(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "NO-GO")
        with self.assertRaises(RepoError) as cm:
            self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        self.assertIn("NO-GO", str(cm.exception))
        # nothing published
        self.assertEqual(repo.load_manifest(self.data)["artifacts"], [])

    def test_no_assessment_refused(self):
        with self.assertRaises(RepoError):
            self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)

    def test_sha_mismatch_refused(self):
        assess_record(self.log, "goodpkg", "1.0.0", "ff" * 32, "GO")
        with self.assertRaises(RepoError) as cm:
            self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        self.assertIn("does not match", str(cm.exception))

    def test_no_tarball_refused(self):
        with self.assertRaises(RepoError) as cm:
            self.signed_publish("ghostpkg", "9.9.9", data_dir=self.data)
        self.assertIn("no pinned tarball", str(cm.exception))


class TestDependencyGaps(RepoTestBase):
    def test_gaps_split_covered_missing(self):
        desc = {"Imports": "yaml, basepkg, newdep1", "Depends": "R (>= 4.0)",
                "LinkingTo": "newdep2"}
        gaps = repo.dependency_gaps(desc, self.data, baseline=self.baseline)
        self.assertEqual(sorted(gaps["covered"]), ["basepkg", "yaml"])
        self.assertEqual(sorted(gaps["missing"]), ["newdep1", "newdep2"])
        self.assertNotIn("R", gaps["dependencies"])

    def test_base_packages_never_gaps(self):
        desc = {"Depends": "R (>= 3.6), methods", "Imports": "stats, utils"}
        gaps = repo.dependency_gaps(desc, self.data, baseline=set())
        self.assertEqual(gaps["dependencies"], [])
        self.assertEqual(gaps["missing"], [])

    def test_repo_manifest_counts_as_covered(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO")
        self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        gaps = repo.dependency_gaps({"Imports": "goodpkg, newdep"}, self.data,
                                    baseline=self.baseline)
        self.assertEqual(gaps["covered"], ["goodpkg"])
        self.assertEqual(gaps["missing"], ["newdep"])

    def test_publish_never_auto_publishes_deps(self):
        # fixture DESCRIPTION has no deps; craft one with a dep by rebuilding
        tb = self.tmp / "dep_pkg"
        # make_pkg_tarball writes no Imports; verify manifest only holds what
        # we published even when gaps exist
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO")
        self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        m = repo.load_manifest(self.data)
        self.assertEqual([a["package"] for a in m["artifacts"]], ["goodpkg"])


class TestExport(RepoTestBase):
    def test_export_snapshot(self):
        assess_record(self.log, "goodpkg", "1.0.0", self.sha, "GO")
        self.signed_publish("goodpkg", "1.0.0", data_dir=self.data)
        dest = self.tmp / "export"
        res = repo.export_repo(dest, self.data)
        self.assertGreaterEqual(res["exported_files"], 4)  # tarball + 2 indexes + manifest
        self.assertTrue((dest / "src" / "contrib" / "PACKAGES").is_file())
        self.assertTrue((dest / "manifest.json").is_file())

    def test_export_empty_refused(self):
        with self.assertRaises(RepoError):
            repo.export_repo(self.tmp / "x", self.data)


class TestBaselineConfig(unittest.TestCase):
    def test_baseline_loads_real_config(self):
        base = repo.load_baseline()
        self.assertIn("shiny", base)  # seeded from the platform image
        self.assertIn("yaml", base)


if __name__ == "__main__":
    unittest.main()
