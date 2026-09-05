"""platform_auth.py — platform session auth for the gateway (stdlib-only).

Deployed on the platform, every request path EXCEPT ``/health`` and
``/repo/`` requires authentication; the gate fails closed.

Credentials accepted (checked in order):

- ``Authorization: Bearer <token>`` or ``?token=`` — validated via
  ``GET {RVAL_PLATFORM_API_URL}/api/session`` (60s TTL
  cache so a page of requests doesn't hammer the platform API).
- ``platform_session`` cookie — validated via
  ``GET {RVAL_PLATFORM_API_URL}/api/verify-session``; the incoming ``Cookie``
  header is forwarded verbatim, and the response shape is
  ``{valid: bool, user_id, role, compounds}`` (plumber serializes scalars as
  single-element arrays — unwrapped here).

Authorization after authentication: ``access_control.json`` (path from
``RVAL_ACCESS_CONTROL``, default ``/etc/rval-gateway/access_control.json``) is
re-read per request (hot-reloadable, bind-mounted on the platform). A user
whose ``user_rules`` entry has ``mode: whitelist`` may only proceed if the
gateway's slug (``RVAL_APP_ID``, default ``rval-gateway``) is in their
``apps`` list → else 403. Users with no entry are unrestricted
(``default_policy=scope``).

Dev mode: when ``RVAL_PLATFORM_API_URL`` is unset, auth is DISABLED and the
server prints a prominent startup warning (mirrors the platform's
disable-auth guard philosophy). When the variable IS set but the API is
unreachable, the gate fails closed with 503 — never silently allow.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ACCESS_CONTROL = "/etc/rval-gateway/access_control.json"
APP_SLUG_DEFAULT = "rval-gateway"
_CACHE_TTL_S = 60
_TIMEOUT_S = 5

# token-or-cookie -> {"exp": float, "user_id": str, "role": str}
_CACHE: dict[str, dict] = {}

# paths that never require auth: health probes (compose healthcheck) and the
# approved-package repository (image builds cannot perform SSO; the repo only
# ever contains approved artifacts; the port is localhost-bound behind nginx)
PUBLIC_PREFIXES = ("/health", "/repo")


@dataclass
class AuthResult:
    ok: bool
    status: int = 200          # 401 / 403 / 503 when not ok
    user_id: str | None = None
    role: str | None = None
    detail: str = ""


class ApiUnreachable(RuntimeError):
    """Platform API configured but unreachable/erroring — fail closed."""


def is_public_path(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in PUBLIC_PREFIXES)


def auth_enabled() -> bool:
    return bool(os.environ.get("RVAL_PLATFORM_API_URL"))


def dev_mode_warning() -> str | None:
    if auth_enabled():
        return None
    return ("RVAL_PLATFORM_API_URL is not set — platform auth DISABLED "
            "(local development mode). Do NOT expose this server.")


def _unwrap(value):
    """Plumber serializes scalars as single-element arrays — unwrap them."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _http_get_json(url: str, headers: dict) -> tuple[int, dict]:
    """One stdlib GET. Returns (status, parsed_json).
    Raises ApiUnreachable on transport errors and 5xx."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code >= 500:
            raise ApiUnreachable(f"platform API HTTP {e.code}") from e
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {}
    except Exception as e:  # noqa: BLE001 — transport failure
        raise ApiUnreachable(f"{type(e).__name__}: {e}") from e


def _cache_get(key: str) -> dict | None:
    hit = _CACHE.get(key)
    if hit and hit["exp"] > time.time():
        return hit
    return None


def _cache_put(key: str, user_id: str, role: str | None) -> dict:
    now = time.time()
    for k in [k for k, v in _CACHE.items() if v["exp"] <= now]:
        _CACHE.pop(k, None)
    entry = {"exp": now + _CACHE_TTL_S, "user_id": user_id, "role": role}
    _CACHE[key] = entry
    return entry


def _validate_token(api_url: str, token: str) -> dict | None:
    """Bearer/query token against /api/session. Raises ApiUnreachable."""
    hit = _cache_get("tok:" + token)
    if hit:
        return hit
    status, info = _http_get_json(f"{api_url}/api/session",
                                  {"Authorization": f"Bearer {token}"})
    if status != 200:
        return None
    user_id = _unwrap(info.get("user_id"))
    if not user_id:
        return None
    return _cache_put("tok:" + token, str(user_id),
                      _unwrap(info.get("role")))


def _validate_cookie(api_url: str, cookie_header: str) -> dict | None:
    """platform_session cookie against /api/verify-session; Cookie forwarded
    verbatim. Raises ApiUnreachable."""
    hit = _cache_get("cook:" + cookie_header)
    if hit:
        return hit
    status, info = _http_get_json(f"{api_url}/api/verify-session",
                                  {"Cookie": cookie_header})
    if status != 200 or not _unwrap(info.get("valid")):
        return None
    user_id = _unwrap(info.get("user_id"))
    if not user_id:
        return None
    return _cache_put("cook:" + cookie_header, str(user_id),
                      _unwrap(info.get("role")))


def _extract_cookie(cookie_header: str | None, name: str) -> str | None:
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name and v:
            return v
    return None


def _whitelist_allows(user_id: str) -> bool:
    """access_control.json user_rules semantics; re-read every call."""
    path = Path(os.environ.get("RVAL_ACCESS_CONTROL",
                               DEFAULT_ACCESS_CONTROL))
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True  # feature not configured → unrestricted baseline
    slug = os.environ.get("RVAL_APP_ID", APP_SLUG_DEFAULT)
    rules = cfg.get("user_rules") or {}
    rule = next((r for name, r in rules.items()
                 if name.lower() == user_id.lower()), None)
    if not rule or rule.get("mode") != "whitelist":
        return True  # no whitelist rule → default_policy=scope → allow
    return slug in (rule.get("apps") or [])


def authenticate(headers, query: dict) -> AuthResult:
    """Gate one request. `headers` is the request's header mapping (case-
    insensitive access via .get), `query` the parsed query dict of lists.

    Never raises: transport problems become 503, bad credentials 401,
    whitelist denial 403. Dev mode (no RVAL_PLATFORM_API_URL) returns ok."""
    if not auth_enabled():
        return AuthResult(ok=True, user_id="dev-mode", detail="auth disabled")
    api_url = os.environ["RVAL_PLATFORM_API_URL"].rstrip("/")

    token = None
    authz = headers.get("Authorization") or headers.get("authorization")
    if authz and authz.startswith("Bearer "):
        token = authz[7:].strip()
    if not token:
        q = query.get("token")
        if q:
            token = q[0]

    cookie_header = headers.get("Cookie") or headers.get("cookie")

    try:
        session = None
        if token:
            session = _validate_token(api_url, token)
        if session is None and _extract_cookie(cookie_header, "platform_session"):
            session = _validate_cookie(api_url, cookie_header)
    except ApiUnreachable as e:
        return AuthResult(ok=False, status=503,
                          detail=f"platform auth API unreachable: {e} "
                                 "(fail-closed)")

    if session is None:
        return AuthResult(ok=False, status=401,
                          detail="not authenticated — sign in via the "
                                 "platform portal, or pass a session token")
    if not _whitelist_allows(session["user_id"]):
        return AuthResult(ok=False, status=403, user_id=session["user_id"],
                          role=session.get("role"),
                          detail=f"user {session['user_id']} is not whitelisted "
                                 "for this app")
    return AuthResult(ok=True, user_id=session["user_id"],
                      role=session.get("role"))
