"""audit.py — append-only, hash-chained JSONL audit trail.

One JSON record per line in ``data/audit/assessments.jsonl``. Each record
carries ``prev_hash`` (sha256 of the previous record's canonical JSON, or the
genesis sentinel) and ``record_hash`` (sha256 of this record's canonical JSON
excluding the hash fields), forming a tamper-evident chain.

The log is never rewritten: ``append()`` only ever appends; ``verify_chain()``
recomputes the chain and reports the first broken link, if any.

stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AUDIT = Path(__file__).resolve().parent.parent / "data" / "audit" / "assessments.jsonl"
GENESIS = "GENESIS"

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _hash(record: dict) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path = DEFAULT_AUDIT):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _records(self) -> list[dict]:
        if not self.path.is_file():
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def append(self, record: dict) -> dict:
        """Append one assessment record; returns it with chain fields added."""
        with _lock:
            prev = self._records()
            prev_hash = prev[-1]["record_hash"] if prev else GENESIS
            full = dict(record)
            full.setdefault("recorded_at", _now())
            full["prev_hash"] = prev_hash
            full["record_hash"] = ""  # placeholder excluded from hashing
            payload = {k: v for k, v in full.items()
                       if k not in ("record_hash",)}
            full["record_hash"] = _hash(payload)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(full, ensure_ascii=False) + "\n")
            return full

    def verify_chain(self) -> dict:
        """Recompute the chain. Returns {ok, records, first_bad_index|None}."""
        records = self._records()
        prev_hash = GENESIS
        for i, rec in enumerate(records):
            payload = {k: v for k, v in rec.items() if k != "record_hash"}
            if rec.get("prev_hash") != prev_hash or \
                    rec.get("record_hash") != _hash(payload):
                return {"ok": False, "records": len(records),
                        "first_bad_index": i}
            prev_hash = rec["record_hash"]
        return {"ok": True, "records": len(records), "first_bad_index": None}


def make_publish_record(package: str, version: str, flavor: str,
                        artifact_sha256: str, assessment_record_hash: str,
                        dependency_gaps: dict,
                        esign_record_hash: str = "",
                        esign_signer: str = "",
                        esign_signatures: list | None = None) -> dict:
    """Assemble the audit record for a repository publish. The hash chain is
    shared with assessments and signatures — publish events are links in the
    same chain, reference the gating assessment by its record_hash, and
    carry the 21 CFR Part 11 signature(s) that authorized them.
    ``esign_signatures`` is the full list of {signer_id, record_hash} (one
    entry for a single-signer publish, two or more for dual-approved
    gxp-critical publishes); ``esign_record_hash``/``esign_signer`` keep the
    first signature for backward compatibility with older readers."""
    record = {
        "record_type": "publish",
        "package": package,
        "version": version,
        "flavor": flavor,
        "artifact_sha256": artifact_sha256,
        "assessment_record_hash": assessment_record_hash,
        "esign_record_hash": esign_record_hash,
        "esign_signer": esign_signer,
        "dependency_gaps": dependency_gaps,
        "timestamp": _now(),
    }
    if esign_signatures:
        record["esign_signatures"] = [
            {"signer_id": s["signer_id"], "record_hash": s["record_hash"]}
            for s in esign_signatures]
    return record


def make_remediation_record(package: str, version: str,
                            assessment_record_hash: str, note: str,
                            actor: str | None = None) -> dict:
    """Assemble the audit record for a NO-GO remediation note: free text
    recorded against a specific NO-GO assessment (by its record_hash) so a
    later re-assessment of the same package can show what was done about the
    previous rejection. Append-only like every other record; the note is
    never edited, a corrected note is a new record."""
    return {
        "record_type": "remediation",
        "package": package,
        "version": version,
        "assessment_record_hash": assessment_record_hash,
        "note": note,
        "actor": actor,
        "timestamp": _now(),
    }


def make_assessment_record(spec: dict, ingest_result: dict,
                           score_json: dict | None, decision_obj: dict,
                           evidence: dict, actor: str | None = None,
                           classification: dict | None = None) -> dict:
    """Assemble the auditable record for one assessment run. ``actor`` is
    the authenticated user id that triggered the run (or "cli" for command-
    line runs); records written before this field existed simply lack it and
    render as "—" in the UI. ``classification`` carries the optional
    intended-use classification ({intended_use, justification}); its keys
    are added only when a classification was recorded (additive)."""
    record = {
        "record_type": "assessment",
        "actor": actor,
        "input_spec": {k: v for k, v in spec.items() if v is not None},
        "package": ingest_result.get("package"),
        "version": ingest_result.get("version"),
        "origin": ingest_result.get("origin"),
        "source_url": ingest_result.get("source_url"),
        "tarball_sha256": ingest_result.get("sha256"),
        "collection_mode": evidence.get("collection_mode"),
        "r_version": (score_json or {}).get("r_version"),
        "riskmetric_version": (score_json or {}).get("riskmetric_version"),
        "config_version": decision_obj.get("config_version"),
        "config_sha256": decision_obj.get("config_sha256"),
        "overall_score": decision_obj.get("overall_score"),
        "decision": decision_obj.get("decision"),
        "tier": decision_obj.get("tier"),
        "fired_rules": decision_obj.get("fired_rules"),
        "conditions": decision_obj.get("conditions"),
        "assessed_at": (score_json or {}).get("assessed_at"),
        "timestamp": _now(),
    }
    if classification:
        record["intended_use"] = classification.get("intended_use")
        record["justification"] = classification.get("justification")
    return record


NO_ACTOR = "—"


def package_timeline(records: list[dict], package: str) -> list[dict]:
    """Approval timeline for one package from audit-chain records, in chain
    order: assessment -> esign -> publish -> remediation events with actor,
    timestamp and record-hash prefix. Shared by the dashboard and the
    per-package report."""
    events = []
    for rec in records:
        rtype = rec.get("record_type")
        ts = rec.get("timestamp")
        h = (rec.get("record_hash") or "")[:12]
        if rtype == "assessment" and rec.get("package") == package:
            events.append({
                "event": "assessment",
                "actor": rec.get("actor") or NO_ACTOR,
                "timestamp": ts, "hash": h,
                "detail": f"{rec.get('decision') or '?'} "
                          f"(tier {rec.get('tier') or '?'}, score "
                          f"{rec.get('overall_score')})",
            })
        elif rtype == "esign" and str(rec.get("object_id") or "").startswith(
                package + " "):
            events.append({
                "event": "esign",
                "actor": rec.get("signer_id") or NO_ACTOR,
                "timestamp": ts, "hash": h,
                "detail": f"signed '{rec.get('meaning')}' for "
                          f"{rec.get('object_id')}",
            })
        elif rtype == "publish" and rec.get("package") == package:
            events.append({
                "event": "publish",
                "actor": rec.get("esign_signer") or NO_ACTOR,
                "timestamp": ts, "hash": h,
                "detail": f"{rec.get('version')} ({rec.get('flavor')})",
            })
        elif rtype == "remediation" and rec.get("package") == package:
            events.append({
                "event": "remediation",
                "actor": rec.get("actor") or NO_ACTOR,
                "timestamp": ts, "hash": h,
                "detail": f"remediation for NO-GO assessment "
                          f"{(rec.get('assessment_record_hash') or '')[:12]}…: "
                          f"{rec.get('note') or ''}",
            })
    return events
