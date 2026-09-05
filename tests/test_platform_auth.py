"""Tests for gateway.platform_auth — offline; platform API mocked."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gateway import platform_auth as pa


class FakeHeaders(dict):
    def get(self, k, default=None):
        return super().get(k, default)


def set_env(**env):
    return mock.patch.dict(os.environ, env, clear=False)


class AuthTestBase(unittest.TestCase):
    def setUp(self):
        pa._CACHE.clear()
        self.tmp = Path(tempfile.mkdtemp(prefix="rval_auth_test_"))
        self.ac = self.tmp / "access_control.json"
        self.ac.write_text(json.dumps({
            "default_policy": "scope",
            "user_rules": {
                "limited.user": {"mode": "whitelist",
                                 "apps": ["other-app"]},
                "allowed.user": {"mode": "whitelist",
                                 "apps": ["rval-gateway"]},
                "landing.only": {"landing": "/#x"},
            },
        }), encoding="utf-8")
        self.env = {"RVAL_PLATFORM_API_URL": "http://api.test:9095",
                    "RVAL_ACCESS_CONTROL": str(self.ac),
                    "RVAL_APP_ID": "rval-gateway"}

    def tearDown(self):
        pa._CACHE.clear()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def mock_api(self, session_info=None, verify_info=None, fail=None):
        """Patch _http_get_json. fail=Exception instance simulates transport
        failure."""
        def fake(url, headers):
            if fail:
                raise fail
            if url.endswith("/api/session"):
                return 200, session_info or {}
            if url.endswith("/api/verify-session"):
                return 200, verify_info or {}
            return 404, {}
        return mock.patch.object(pa, "_http_get_json", side_effect=fake)


class TestTokenAuth(AuthTestBase):
    def test_bearer_token_valid(self):
        with set_env(**self.env), self.mock_api(
                session_info={"user_id": ["some.user"], "compounds": []}):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer abc"), {})
        self.assertTrue(r.ok)
        self.assertEqual(r.user_id, "some.user")  # plumber array unwrapped

    def test_query_token_valid(self):
        with set_env(**self.env), self.mock_api(
                session_info={"user_id": "some.user"}):
            r = pa.authenticate(FakeHeaders(), {"token": ["abc"]})
        self.assertTrue(r.ok)

    def test_invalid_token_401(self):
        with set_env(**self.env), self.mock_api(session_info={}):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer bad"), {})
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 401)

    def test_whitelist_denied_403(self):
        with set_env(**self.env), self.mock_api(
                session_info={"user_id": "limited.user"}):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer abc"), {})
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 403)

    def test_whitelist_allowed(self):
        with set_env(**self.env), self.mock_api(
                session_info={"user_id": "allowed.user"}):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer abc"), {})
        self.assertTrue(r.ok)

    def test_no_rule_means_allowed(self):
        with set_env(**self.env), self.mock_api(
                session_info={"user_id": "unrestricted.user"}):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer abc"), {})
        self.assertTrue(r.ok)

    def test_landing_only_rule_is_not_whitelist(self):
        with set_env(**self.env), self.mock_api(
                session_info={"user_id": "landing.only"}):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer abc"), {})
        self.assertTrue(r.ok)


class TestCookieAuth(AuthTestBase):
    def test_platform_session_cookie_valid(self):
        with set_env(**self.env), self.mock_api(
                verify_info={"valid": True, "user_id": "some.user",
                             "role": "Analyst"}):
            r = pa.authenticate(FakeHeaders(Cookie="platform_session=xyz; other=1"),
                                {})
        self.assertTrue(r.ok)
        self.assertEqual(r.user_id, "some.user")
        self.assertEqual(r.role, "Analyst")

    def test_cookie_forwarded_verbatim(self):
        seen = {}

        def fake(url, headers):
            seen.update(headers)
            return 200, {"valid": True, "user_id": "u"}
        with set_env(**self.env), \
                mock.patch.object(pa, "_http_get_json", side_effect=fake):
            pa.authenticate(FakeHeaders(Cookie="a=1; platform_session=xyz"), {})
        self.assertEqual(seen.get("Cookie"), "a=1; platform_session=xyz")

    def test_invalid_cookie_401(self):
        with set_env(**self.env), self.mock_api(verify_info={"valid": False}):
            r = pa.authenticate(FakeHeaders(Cookie="platform_session=xyz"), {})
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 401)


class TestFailClosed(AuthTestBase):
    def test_api_unreachable_503(self):
        with set_env(**self.env), self.mock_api(fail=pa.ApiUnreachable("boom")):
            r = pa.authenticate(FakeHeaders(Authorization="Bearer abc"), {})
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 503)
        self.assertIn("fail-closed", r.detail)

    def test_transport_error_503(self):
        with set_env(**self.env), \
                mock.patch.object(pa, "_http_get_json",
                                  side_effect=pa.ApiUnreachable("timeout")):
            r = pa.authenticate(FakeHeaders(Cookie="platform_session=x"), {})
        self.assertEqual(r.status, 503)


class TestDevMode(unittest.TestCase):
    def setUp(self):
        pa._CACHE.clear()

    def test_auth_disabled_without_api_url(self):
        env = {k: v for k, v in os.environ.items()
               if k != "RVAL_PLATFORM_API_URL"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertFalse(pa.auth_enabled())
            r = pa.authenticate(FakeHeaders(), {})
            self.assertTrue(r.ok)
            self.assertEqual(r.user_id, "dev-mode")
            self.assertIsNotNone(pa.dev_mode_warning())


class TestPublicPaths(unittest.TestCase):
    def test_public_prefixes(self):
        self.assertTrue(pa.is_public_path("/health"))
        self.assertTrue(pa.is_public_path("/repo/src/contrib/PACKAGES"))
        self.assertFalse(pa.is_public_path("/"))
        self.assertFalse(pa.is_public_path("/repo-view"))
        self.assertFalse(pa.is_public_path("/assess"))


if __name__ == "__main__":
    unittest.main()
