"""Tests for GATEWAY_BASE_PATH URL generation — offline."""

import os
import unittest
from unittest import mock

from gateway import server


class TestBasePath(unittest.TestCase):
    def test_default_root(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(server.base_path(), "/")
            self.assertEqual(server.url("/assess"), "/assess")
            self.assertEqual(server.url("/repo-view"), "/repo-view")

    def test_prefixed(self):
        with mock.patch.dict(os.environ,
                             {"GATEWAY_BASE_PATH": "/rval-gateway/"}):
            self.assertEqual(server.base_path(), "/rval-gateway/")
            self.assertEqual(server.url("/assess"), "/rval-gateway/assess")
            self.assertEqual(server.url("/report/run_1/report.pdf"),
                             "/rval-gateway/report/run_1/report.pdf")

    def test_normalization(self):
        with mock.patch.dict(os.environ, {"GATEWAY_BASE_PATH": "gw"}):
            self.assertEqual(server.base_path(), "/gw/")
            self.assertEqual(server.url("/health"), "/gw/health")

    def test_form_uses_base_path(self):
        with mock.patch.dict(os.environ,
                             {"GATEWAY_BASE_PATH": "/rval-gateway/"}):
            html = server._form_html().decode()
        self.assertIn('action="/rval-gateway/assess"', html)
        self.assertIn('href="/rval-gateway/repo-view"', html)

    def test_form_default_root(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            html = server._form_html().decode()
        self.assertIn('action="/assess"', html)


if __name__ == "__main__":
    unittest.main()
