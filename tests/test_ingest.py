"""Tests for gateway.ingest — offline; fixture tarballs are built in setUp."""

import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from gateway import ingest
from gateway.ingest import IngestError


def make_pkg_tarball(dest: Path, pkg="fixturepkg", version="0.1.0",
                     with_description=True) -> Path:
    """Build a minimal R package source tarball (DESCRIPTION + NAMESPACE)."""
    src = dest / f"{pkg}_{version}_src"
    root = src / pkg
    root.mkdir(parents=True)
    if with_description:
        (root / "DESCRIPTION").write_text(
            f"Package: {pkg}\n"
            f"Version: {version}\n"
            "Title: A Minimal Fixture Package\n"
            "Description: Long description text\n"
            "  continued on a second line.\n"
            "License: MIT\n"
            "Maintainer: Someone <someone@example.org>\n",
            encoding="utf-8",
        )
    (root / "NAMESPACE").write_text("export(dummy)\n", encoding="utf-8")
    (root / "R").mkdir()
    (root / "R" / "dummy.R").write_text("dummy <- function() 1\n",
                                        encoding="utf-8")
    tarball = dest / f"{pkg}_{version}.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(root, arcname=pkg)
    return tarball


class TestDescriptionParsing(unittest.TestCase):
    def test_parse_description_continuation(self):
        d = ingest.parse_description(
            "Package: x\nVersion: 1.0\nDescription: line one\n  line two.\n")
        self.assertEqual(d["Package"], "x")
        self.assertEqual(d["Description"], "line one line two.")


class TestUploadIngest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_ingest_test_"))
        self.data_dir = self.tmp / "data"
        self.tarball = make_pkg_tarball(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_upload_provenance(self):
        res = ingest.ingest_upload(self.tarball, self.data_dir)
        self.assertEqual(res.package, "fixturepkg")
        self.assertEqual(res.version, "0.1.0")
        self.assertEqual(res.origin, "upload")
        self.assertEqual(res.collection_mode, "local")
        self.assertEqual(len(res.sha256), 64)
        self.assertEqual(res.description["License"], "MIT")
        # stored under data/tarballs/<pkg>/<version>/ with provenance record
        stored = Path(res.tarball_path)
        self.assertTrue(stored.is_file())
        self.assertIn("fixturepkg", str(stored))
        self.assertTrue(Path(res.provenance_path).is_file())

    def test_upload_missing_file(self):
        with self.assertRaises(IngestError):
            ingest.ingest_upload(self.tmp / "nope.tar.gz", self.data_dir)

    def test_tarball_without_description_fails(self):
        bad = make_pkg_tarball(self.tmp, pkg="nodesc", version="9.9.9",
                               with_description=False)
        with self.assertRaises(IngestError):
            ingest.ingest_upload(bad, self.data_dir)


class TestSpecDispatch(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_ingest_test_"))
        self.data_dir = self.tmp / "data"
        self.tarball = make_pkg_tarball(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dispatch_upload(self):
        res = ingest.ingest({"upload_path": str(self.tarball)}, self.data_dir)
        self.assertEqual(res.origin, "upload")

    def test_dispatch_empty_spec(self):
        with self.assertRaises(IngestError):
            ingest.ingest({}, self.data_dir)

    def test_bad_github_url(self):
        with self.assertRaises(IngestError):
            ingest.ingest({"github_url": "https://example.com/not/github"},
                          self.data_dir)


class TestOfflineFallback(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_ingest_test_"))
        self.data_dir = self.tmp / "data"
        # pre-seed the cache as if a previous networked run had fetched it
        tb = make_pkg_tarball(self.tmp)
        store = self.data_dir / "tarballs" / "fixturepkg" / "0.1.0"
        store.mkdir(parents=True)
        shutil.copy(tb, store / tb.name)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cran_fetch_failure_falls_back_to_cache(self):
        def boom(url, timeout=ingest.TIMEOUT_S):
            raise OSError("network down (simulated)")
        orig = ingest._fetch
        ingest._fetch = boom
        try:
            res = ingest.ingest_cran("fixturepkg", "0.1.0", self.data_dir)
        finally:
            ingest._fetch = orig
        self.assertEqual(res.collection_mode, "offline-fallback")
        self.assertEqual(res.package, "fixturepkg")
        self.assertEqual(res.version, "0.1.0")

    def test_cran_fetch_failure_no_cache_raises(self):
        def boom(url, timeout=ingest.TIMEOUT_S):
            raise OSError("network down (simulated)")
        orig = ingest._fetch
        ingest._fetch = boom
        try:
            with self.assertRaises(IngestError):
                ingest.ingest_cran("fixturepkg", "9.9.9", self.data_dir)
        finally:
            ingest._fetch = orig


class TestNetworkedIngest(unittest.TestCase):
    """Live CRAN round-trip; skipped when the network is unavailable."""

    def test_cran_current_version(self):
        try:
            ver = ingest._cran_current_version("abind")
        except Exception as e:  # noqa: BLE001
            self.skipTest(f"network unavailable: {e}")
        self.assertRegex(ver, r"^\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
