"""Tests for Phase A: tools/build_inventory.py + run_inventory.py.

Offline: version resolution uses a fixture PACKAGES index; the batch test
replays the committed regression cache into a tmp data-dir.
"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO))

import build_inventory  # noqa: E402
import run_inventory  # noqa: E402

FIXTURE_PACKAGES = REPO / "tests" / "fixtures" / "PACKAGES"
REGRESSION_CACHE = REPO / "tests" / "regression" / "cache"


class InventoryTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_inv_test_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_sources(self):
        """tmp baseline + dockerfile + R-code dir with known overlaps."""
        baseline = self.tmp / "baseline.json"
        baseline.write_text(json.dumps(
            {"packages": ["dplyr", "glue", "notacranpkg"]}), encoding="utf-8")
        dockerfile = self.tmp / "Dockerfile"
        dockerfile.write_text(
            "RUN Rscript -e 'install.packages(c( \\\n"
            '  "dplyr", "xfun"))\'\n'
            "RUN Rscript -e 'install.packages(c(\"shiny\"))'\n",
            encoding="utf-8")
        code_dir = self.tmp / "platform"
        (code_dir / "app").mkdir(parents=True)
        (code_dir / "app" / "server.R").write_text(
            "library(glue)\n"
            "require(xfun)\n"
            "library(stats)\n"      # base package — must be excluded
            'library("shiny")\n'
            "require(methods)\n"    # base package — must be excluded
            "#' library(commentpkg)  # roxygen comment — not a real call\n"
            "## see require(alsocomment) for details\n",
            encoding="utf-8")
        return baseline, dockerfile, code_dir


class TestSources(InventoryTestBase):

    def test_dockerfile_parse_multiline(self):
        _, dockerfile, _ = self._make_sources()
        self.assertEqual(build_inventory.parse_dockerfile(dockerfile),
                         {"dplyr", "xfun", "shiny"})

    def test_code_scan_excludes_base_packages(self):
        _, _, code_dir = self._make_sources()
        names = build_inventory.scan_r_code(code_dir)
        self.assertEqual(names, {"glue", "xfun", "shiny"})
        self.assertNotIn("stats", names)
        self.assertNotIn("methods", names)
        self.assertNotIn("commentpkg", names)     # roxygen comment, not a call
        self.assertNotIn("alsocomment", names)

    def test_merge_dedup_and_source_attribution(self):
        baseline, dockerfile, code_dir = self._make_sources()
        index = build_inventory.parse_packages_index(
            FIXTURE_PACKAGES.read_text(encoding="utf-8"))
        inv, unresolved = build_inventory.build_inventory(
            baseline, dockerfile, code_dir, index, "2026-08-01")
        pkgs = {p["name"]: p for p in inv["packages"]}
        self.assertEqual(set(pkgs),
                         {"dplyr", "glue", "xfun", "shiny", "notacranpkg"})
        self.assertEqual(pkgs["dplyr"]["sources"], ["baseline", "dockerfile"])
        self.assertEqual(pkgs["glue"]["sources"], ["baseline", "code"])
        self.assertEqual(pkgs["xfun"]["sources"], ["dockerfile", "code"])
        self.assertEqual(pkgs["shiny"]["sources"], ["dockerfile", "code"])

    def test_version_resolution_from_fixture_index(self):
        baseline, dockerfile, code_dir = self._make_sources()
        index = build_inventory.parse_packages_index(
            FIXTURE_PACKAGES.read_text(encoding="utf-8"))
        inv, _ = build_inventory.build_inventory(
            baseline, dockerfile, code_dir, index, "2026-08-01")
        pkgs = {p["name"]: p for p in inv["packages"]}
        self.assertEqual(pkgs["dplyr"]["version"], "1.1.4")
        self.assertEqual(pkgs["glue"]["version"], "1.7.0")
        self.assertEqual(pkgs["xfun"]["version"], "0.56")
        self.assertEqual(inv["snapshot"], "2026-08-01")
        self.assertEqual(inv["schema"], "rval-gateway inventory v1")

    def test_unresolved_version_is_null(self):
        baseline, dockerfile, code_dir = self._make_sources()
        index = build_inventory.parse_packages_index(
            FIXTURE_PACKAGES.read_text(encoding="utf-8"))
        inv, unresolved = build_inventory.build_inventory(
            baseline, dockerfile, code_dir, index, "2026-08-01")
        pkgs = {p["name"]: p for p in inv["packages"]}
        self.assertIsNone(pkgs["notacranpkg"]["version"])
        self.assertEqual(unresolved, ["notacranpkg"])

    def test_main_with_packages_file(self):
        baseline, dockerfile, code_dir = self._make_sources()
        out = self.tmp / "inventory.json"
        rc = build_inventory.main([
            "--packages-file", str(FIXTURE_PACKAGES),
            "--baseline", str(baseline),
            "--dockerfile", str(dockerfile),
            "--platform-dir", str(code_dir),
            "--snapshot", "2026-08-01",
            "--out", str(out)])
        self.assertEqual(rc, 0)
        inv = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(len(inv["packages"]), 5)


class TestStaleness(unittest.TestCase):

    SHA = "ab" * 32

    def _record(self, version="1.1.4", sha=SHA):
        return {"record_type": "assessment", "package": "dplyr",
                "version": version, "config_sha256": sha}

    def test_never_assessed_is_stale(self):
        stale, reason = run_inventory.staleness(
            {"name": "dplyr", "version": "1.1.4"}, None, self.SHA)
        self.assertTrue(stale)
        self.assertEqual(reason, "never-assessed")

    def test_version_mismatch_is_stale(self):
        stale, reason = run_inventory.staleness(
            {"name": "dplyr", "version": "1.1.4"},
            self._record(version="1.1.3"), self.SHA)
        self.assertTrue(stale)
        self.assertEqual(reason, "version-mismatch")

    def test_config_change_is_stale(self):
        stale, reason = run_inventory.staleness(
            {"name": "dplyr", "version": "1.1.4"},
            self._record(sha="cd" * 32), self.SHA)
        self.assertTrue(stale)
        self.assertEqual(reason, "config-changed")

    def test_current_is_not_stale(self):
        stale, reason = run_inventory.staleness(
            {"name": "dplyr", "version": "1.1.4"}, self._record(), self.SHA)
        self.assertFalse(stale)
        self.assertEqual(reason, "current")

    def test_unresolved_version_is_stale(self):
        stale, reason = run_inventory.staleness(
            {"name": "notacranpkg", "version": None},
            self._record(), self.SHA)
        self.assertTrue(stale)
        self.assertEqual(reason, "version-unresolved")

    def test_latest_assessments_picks_newest(self):
        data = self_tmp = Path(tempfile.mkdtemp(prefix="rval_inv_audit_"))
        self.addCleanup(shutil.rmtree, self_tmp, True)
        audit_dir = data / "audit"
        audit_dir.mkdir(parents=True)
        lines = [
            {"record_type": "assessment", "package": "dplyr",
             "version": "1.1.3", "timestamp": "t1"},
            {"record_type": "publish", "package": "dplyr",
             "version": "9.9.9"},
            {"record_type": "assessment", "package": "dplyr",
             "version": "1.1.4", "timestamp": "t2"},
        ]
        (audit_dir / "assessments.jsonl").write_text(
            "\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
        latest = run_inventory.latest_assessments(data)
        self.assertEqual(latest["dplyr"]["version"], "1.1.4")


class TestOfflineBatch(InventoryTestBase):

    def test_offline_batch_two_fixtures(self):
        inv_path = self.tmp / "inventory.json"
        inv_path.write_text(json.dumps({
            "schema": "rval-gateway inventory v1",
            "snapshot": "2026-08-01",
            "generated_at": "t",
            "packages": [
                {"name": "abind", "version": "1.4-8", "sources": ["code"]},
                {"name": "xfun", "version": "0.56", "sources": ["code"]},
            ]}), encoding="utf-8")
        data_dir = self.tmp / "data"
        rc = run_inventory.main([
            "--offline", "--jobs", "2",
            "--data-dir", str(data_dir),
            "--inventory", str(inv_path),
            "--cache-dir", str(REGRESSION_CACHE)])
        self.assertEqual(rc, 0)

        summaries = list(data_dir.glob("inventory_runs/*/summary.json"))
        self.assertEqual(len(summaries), 1)
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        self.assertEqual(summary["schema"], "rval-gateway inventory run v1")
        self.assertEqual(summary["totals"]["packages"], 2)
        self.assertEqual(summary["totals"]["stale"], 2)
        self.assertEqual(summary["totals"]["assessed"], 2)
        self.assertEqual(summary["totals"]["failed"], 0)
        rows = {r["name"]: r for r in summary["results"]}
        for name in ("abind", "xfun"):
            self.assertEqual(rows[name]["status"], "assessed")
            self.assertIn(rows[name]["decision"],
                          ("GO", "GO-WITH-CONDITIONS", "NO-GO"))
            self.assertIsNotNone(rows[name]["overall_score"])
            self.assertEqual(rows[name]["mode"], "offline-replay")
            self.assertEqual(rows[name]["stale_reason"], "never-assessed")

    def test_batch_continues_past_failure(self):
        inv_path = self.tmp / "inventory.json"
        inv_path.write_text(json.dumps({
            "packages": [
                {"name": "abind", "version": "1.4-8", "sources": ["code"]},
                {"name": "nocachepkg", "version": "0.1",
                 "sources": ["code"]},
            ]}), encoding="utf-8")
        data_dir = self.tmp / "data"
        rc = run_inventory.main([
            "--offline", "--jobs", "1",
            "--data-dir", str(data_dir),
            "--inventory", str(inv_path),
            "--cache-dir", str(REGRESSION_CACHE)])
        self.assertEqual(rc, 1)  # one failure -> non-zero exit
        summary = json.loads(next(
            data_dir.glob("inventory_runs/*/summary.json"))
            .read_text(encoding="utf-8"))
        self.assertEqual(summary["totals"]["assessed"], 1)
        self.assertEqual(summary["totals"]["failed"], 1)
        rows = {r["name"]: r for r in summary["results"]}
        self.assertEqual(rows["abind"]["status"], "assessed")
        self.assertEqual(rows["nocachepkg"]["status"], "failed")
        self.assertIn("no regression cache", rows["nocachepkg"]["error"])


if __name__ == "__main__":
    unittest.main()
