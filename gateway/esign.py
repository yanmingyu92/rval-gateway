"""esign.py — 21 CFR Part 11 electronic signatures (stdlib-only).

Three signature elements (§11.50):

1. **Signer identity** — ``signer_id`` (platform user id) resolved through
   re-authentication, not through an existing session.
2. **Meaning** — one of ``approved`` / ``rejected`` / ``locked``; publish
   gating only accepts ``approved``.
3. **Re-authentication at signing time** (§11.200(a)(3)) — the signer's
   password is verified against the platform login API
   (``POST {api_url}/api/login``) inside ``sign()``. A session cookie or
   bearer token is deliberately NOT sufficient for signing.

Signed records join the same hash-chained audit log as assessments and
publishes (``record_type: "esign"``) and bind the signed object by its
``record_hash`` — signatures are frozen by the append-only chain.

Failure behaviour: any authentication failure (bad credentials, non-200,
platform unreachable) raises :class:`ESIGNAuthError` — signing fails
closed; there is no bypass.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

MEANINGS = ("approved", "rejected", "locked")
_TIMEOUT_S = 10


class ESIGNError(Exception):
    """Generic e-signature failure (validation of a supplied record)."""


class ESIGNAuthError(ESIGNError):
    """Re-authentication failed — signing is refused (fail closed)."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reauthenticate(api_url: str, user_id: str, password: str) -> dict:
    """Verify user_id + password against the platform login API.

    Returns ``{"user_id": ..., "role": ...}`` on success.
    Raises ESIGNAuthError on bad credentials or any transport problem
    (fail closed — an unreachable auth service must never allow signing).
    """
    if not api_url:
        raise ESIGNAuthError("no platform API URL configured for signing "
                             "(set RVAL_PLATFORM_API_URL)")
    body = json.dumps({"user_id": user_id, "password": password}).encode()
    req = urllib.request.Request(
        api_url.rstrip("/") + "/api/login", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            info = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise ESIGNAuthError(
            f"re-authentication failed (HTTP {e.code}) — signature refused"
        ) from e
    except Exception as e:  # noqa: BLE001 — transport failure
        raise ESIGNAuthError(
            f"auth service unreachable ({type(e).__name__}) — signature "
            "refused (fail closed)") from e

    def _scalar(v):
        # plumber serializes scalars as single-element arrays
        return v[0] if isinstance(v, list) and v else v

    uid = _scalar(info.get("user_id")) or user_id
    role = _scalar(info.get("role"))
    return {"user_id": str(uid), "role": str(role) if role else ""}


def make_esign_record(meaning: str, signer_id: str, signer_role: str,
                      object_type: str, object_id: str, object_hash: str,
                      reauth_method: str = "platform-login") -> dict:
    """Assemble the audit record for one signing event (pre-hash)."""
    if meaning not in MEANINGS:
        raise ESIGNError(f"signature meaning must be one of {MEANINGS}, "
                         f"got {meaning!r}")
    return {
        "record_type": "esign",
        "meaning": meaning,
        "signer_id": signer_id,
        "signer_role": signer_role,
        "object_type": object_type,
        "object_id": object_id,
        "object_hash": object_hash,
        "reauth_method": reauth_method,
        "timestamp": _now(),
    }


def sign(audit_log, meaning: str, signer_id: str, password: str,
         api_url: str, object_type: str, object_id: str,
         object_hash: str) -> dict:
    """Re-authenticate the signer, then append an esign record to the chain.

    ``audit_log`` is an :class:`gateway.audit.AuditLog` instance. Returns
    the chained record (with ``record_hash``).
    """
    auth = reauthenticate(api_url, signer_id, password)
    record = make_esign_record(
        meaning=meaning, signer_id=auth["user_id"],
        signer_role=auth["role"], object_type=object_type,
        object_id=object_id, object_hash=object_hash)
    return audit_log.append(record)


def validate_for_publish(records: list[dict], esign_rec: dict | None,
                         gate_record_hash: str) -> dict:
    """Validate an esign record for the publish flow. Returns the record
    when valid; raises ESIGNError otherwise.

    Checks:
    - the record exists and is present in the audit chain (by record_hash);
    - it is an esign record with meaning ``approved``;
    - it binds the exact assessment being published (object_hash match);
    - it was produced through re-authentication.
    """
    if not isinstance(esign_rec, dict):
        raise ESIGNError("electronic signature required (21 CFR Part 11) — "
                         "publish refused")
    chained = next((r for r in records
                    if r.get("record_hash") == esign_rec.get("record_hash")),
                   None)
    if chained is None:
        raise ESIGNError("signature record not found in the audit chain — "
                         "publish refused")
    if chained.get("record_type") != "esign":
        raise ESIGNError("supplied record is not an electronic signature")
    if chained.get("meaning") != "approved":
        raise ESIGNError(
            f"signature meaning {chained.get('meaning')!r} does not allow "
            "publishing — 'approved' required")
    if chained.get("object_hash") != gate_record_hash:
        raise ESIGNError(
            "signature does not bind the assessment being published "
            f"(signed {str(chained.get('object_hash'))[:12]}… vs assessment "
            f"{gate_record_hash[:12]}…)")
    if not chained.get("signer_id") or not chained.get("reauth_method"):
        raise ESIGNError("signature record incomplete (signer or "
                         "re-authentication evidence missing)")
    return chained
