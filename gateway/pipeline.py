"""pipeline.py — end-to-end assessment orchestration.

Chains: ingest -> score (R subprocess) -> evidence collection -> decision ->
report -> audit record. Each stage's outputs are persisted under data/runs/
so a report is always reconstructible.

stdlib only.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import audit as audit_mod
from . import decision as decision_mod
from . import evidence as evidence_mod
from . import ingest as ingest_mod
from . import r_adapter, report as report_mod

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_assessment(spec: dict, tier: str,
                   data_dir: Path = DEFAULT_DATA_DIR,
                   config_path: str | Path | None = None,
                   skip_score: bool = False,
                   actor: str | None = None,
                   classification: dict | None = None) -> dict:
    """Run the full pipeline. Returns the assessment dict with output paths.

    skip_score=True is for tests/offline debugging only: it marks the run
    explicitly as un-scored (overall_score=None -> NO-GO) — never fabricates.
    ``actor`` is the authenticated user id recorded on the audit record
    (None for callers that predate actor plumbing). ``classification`` is the
    optional intended-use classification ({intended_use, justification});
    it is recorded on the audit record and rendered in the report.
    """
    ruleset = decision_mod.RuleSet.load(
        config_path or decision_mod.DEFAULT_CONFIG)

    ing = ingest_mod.ingest(spec, data_dir)
    ingest_d = ing.to_dict()

    run_id = f"{ing.package}_{ing.version}_{_now().replace(':', '')}"
    runs_root = data_dir / "runs"
    run_dir = runs_root / run_id
    # concurrent web jobs (or a same-second CLI rerun) must never share a
    # run dir: suffix until free. Run ids still start with "<pkg>_<ver>_"
    # and sort newest-last, so find_run_id() prefix matching is unaffected.
    n = 0
    while run_dir.exists():
        n += 1
        run_dir = runs_root / f"{run_id}_{n}"
    run_id = run_dir.name
    run_dir.mkdir(parents=True)

    score_json = None
    score_error = None
    if not skip_score:
        try:
            score_json = r_adapter.score_tarball(
                ing.tarball_path, workdir=run_dir / "score")
        except Exception as e:  # noqa: BLE001 — recorded, not hidden
            score_error = f"{type(e).__name__}: {e}"
    else:
        score_error = "scoring skipped by caller (skip_score=True)"

    if score_json is not None:
        # category subscores: additive, display-only (overall score and the
        # decision algorithm are untouched); persisted back into score.json
        cats = decision_mod.category_scores(score_json.get("metric_scores"),
                                            ruleset.category_weights)
        if cats:
            score_json["category_scores"] = cats
            json_path = score_json.get("json_path")
            if json_path:
                persisted = {k: v for k, v in score_json.items()
                             if k != "json_path"}
                Path(json_path).write_text(
                    json.dumps(persisted, indent=2, ensure_ascii=False),
                    encoding="utf-8")

    evidence = evidence_mod.collect(ing.package, ingest_d, score_json)
    ev_path = run_dir / "evidence.json"
    ev_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False),
                       encoding="utf-8")

    overall = (score_json or {}).get("overall_score")
    decision_obj = decision_mod.decide(overall, tier, evidence, ruleset)
    if score_error:
        decision_obj["score_error"] = score_error
    dec_path = run_dir / "decision.json"
    dec_path.write_text(json.dumps(decision_obj, indent=2, ensure_ascii=False),
                        encoding="utf-8")

    # audit record first: the report's approval-timeline section reads the
    # chain and must include this assessment's own event
    record = audit_mod.make_assessment_record(
        spec, ingest_d, score_json, decision_obj, evidence, actor=actor,
        classification=classification)
    if score_error:
        record["score_error"] = score_error
    log = audit_mod.AuditLog(data_dir / "audit" / "assessments.jsonl")
    record = log.append(record)
    timeline = audit_mod.package_timeline(log._records(), ing.package)

    assessment = {
        "spec": spec,
        "ingest": ingest_d,
        "score": score_json,
        "evidence": evidence,
        "decision": decision_obj,
        "classification": classification,
        "timeline": timeline,
        "generated_at": _now(),
    }
    rep = report_mod.render(assessment, run_dir / "report")

    # store run-relative paths only (no workstation-absolute paths in the log)
    record["report_html"] = str(Path(rep["html"]).relative_to(data_dir))
    if rep["pdf"]:
        record["report_pdf"] = str(Path(rep["pdf"]).relative_to(data_dir))

    assessment.update({
        "run_dir": str(run_dir),
        "evidence_path": str(ev_path),
        "decision_path": str(dec_path),
        "report": rep,
        "audit_record": record,
        "audit_log": str(log.path),
    })
    return assessment
