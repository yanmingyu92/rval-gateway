"""jobs.py — in-process asynchronous assessment job registry.

POST /assess no longer blocks on the 10-60s pipeline: it validates the
request, enqueues a job here and answers 202 immediately. The pipeline runs
on a daemon thread; GET /api/jobs/<job_id> exposes the state machine
(queued -> running -> done | failed) for the polling UI.

Thread safety: the registry dict is guarded by a single lock; the audit
chain has its own append lock (audit._lock) and each run writes only under
its own data/runs/<run_id>/ directory, so concurrent workers never share
mutable state. At most MAX_CONCURRENT workers run at once; submissions
beyond the cap are refused (the route answers 429).

Job state lives in memory only: a restart loses it. The API reports unknown
ids honestly as "lost" so the UI can say "job lost, please resubmit".

stdlib only.
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

MAX_CONCURRENT = 2
MAX_RETAINED = 200

_lock = threading.Lock()
_jobs: dict[str, dict] = {}
_running = 0


class BusyError(Exception):
    """Raised when MAX_CONCURRENT jobs are already running."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def submit(spec: dict, tier: str, actor: str | None,
           classification: dict | None, pipeline_run) -> dict:
    """Enqueue one assessment. ``pipeline_run`` is pipeline.run_assessment
    (injected so tests can stub the pipeline without touching this module).
    Returns the public job dict; raises BusyError over the concurrency cap.
    """
    global _running
    with _lock:
        if _running >= MAX_CONCURRENT:
            raise BusyError(f"{MAX_CONCURRENT} assessments already running")
        _running += 1
        job_id = uuid.uuid4().hex[:16]
        _jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "submitted_at": _now(),
            "package": None,   # filled when the pipeline resolves the source
            "run_id": None,
            "error": None,
        }
        _prune_locked()
    t = threading.Thread(
        target=_worker, args=(job_id, spec, tier, actor, classification,
                              pipeline_run),
        name=f"assess-{job_id}", daemon=True)
    t.start()
    return dict(_jobs[job_id])


def _prune_locked():
    """Drop oldest terminal jobs beyond MAX_RETAINED (caller holds _lock)."""
    if len(_jobs) <= MAX_RETAINED:
        return
    terminal = [(j["submitted_at"], jid) for jid, j in _jobs.items()
                if j["status"] in ("done", "failed")]
    terminal.sort()
    for _, jid in terminal[: len(_jobs) - MAX_RETAINED]:
        del _jobs[jid]


def _worker(job_id: str, spec: dict, tier: str, actor: str | None,
            classification: dict | None, pipeline_run):
    global _running
    try:
        with _lock:
            _jobs[job_id]["status"] = "running"
        a = pipeline_run(spec, tier, actor=actor, classification=classification)
        with _lock:
            _jobs[job_id].update({
                "status": "done",
                "package": a["ingest"]["package"],
                "version": a["ingest"]["version"],
                "run_id": Path(a["run_dir"]).name,
                "record_hash": a["audit_record"]["record_hash"],
                "has_pdf": bool(a["report"]["pdf"]),
                "pdf_note": a["report"]["pdf_note"],
                "finished_at": _now(),
            })
    except Exception as e:  # noqa: BLE001 — surfaced to the UI, never hidden
        with _lock:
            _jobs[job_id].update({
                "status": "failed",
                "error": f"{type(e).__name__}: {e}",
                "finished_at": _now(),
            })
    finally:
        # the upload staging dir (if any) is disposable once ingest copied
        # the tarball into the run dir
        up = spec.get("upload_path")
        if up:
            parent = Path(up).parent
            if parent.name.startswith("rval_upload_"):
                shutil.rmtree(parent, ignore_errors=True)
        with _lock:
            _running -= 1


def status(job_id: str) -> dict | None:
    """Public job dict, or None when the id is unknown (e.g. after a
    restart — the UI renders that as 'job lost, please resubmit')."""
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None
