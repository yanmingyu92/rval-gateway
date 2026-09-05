#!/usr/bin/env python
"""run_regression.py — headless regression runner for the gateway.

Modes:
  (default)      full network mode: ingest + R scoring + evidence + decision
                 per fixture; results checked against golden files; evidence
                 and score JSON are cached for --offline replay.
  --offline      deterministic replay from tests/regression/cache/ (no
                 network, no R): the decision layer is re-run on cached
                 evidence and checked against golden files. For CI.
  --calibrate    network run that WRITES golden files from observed results
                 (band = observed +- BAND around the score). Maintainer tool;
                 review margins before committing goldens.

Stability: per run, a canonical decision core {decision, tier, tier
thresholds, config_version, config_sha256} is hashed (sha256). The runner
writes run summaries to tests/regression/runs/<timestamp>/ including per-
fixture decision JSON; two consecutive network runs must produce matching
canonical hashes (config version pinning stability). Volatile fields
(decided_at, overall_score float, evidence-derived conditions) are reported
but excluded from the canonical hash — live network metrics legitimately
drift; the PINNED elements (version, tier thresholds, config identity,
decision outcome) must not.

Usage: python tests/regression/run_regression.py [--offline|--calibrate] [--jobs N]
stdlib only. Run from the repo root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from gateway import decision as decision_mod  # noqa: E402
from gateway import pipeline  # noqa: E402

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "manifest.json"
GOLDEN_DIR = HERE / "golden"
CACHE_DIR = HERE / "cache"
DATA_DIR = HERE / "data"   # gitignored scratch (tarballs, runs, audit)
RUNS_DIR = HERE / "runs"   # gitignored run summaries

BAND = 0.15  # golden score band half-width (cranlogs/metric intermittency drift)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def canonical_core(dec: dict, ruleset: decision_mod.RuleSet) -> dict:
    """The pinned part of a decision: outcome + tier band + config identity."""
    tier = dec["tier"]
    band = ruleset.tiers[tier]
    return {
        "decision": dec["decision"],
        "tier": tier,
        "low": band.get("low"),
        "high": band.get("high"),
        "config_version": dec["config_version"],
        "config_sha256": dec["config_sha256"],
    }


def canonical_sha(dec: dict, ruleset: decision_mod.RuleSet) -> str:
    blob = json.dumps(canonical_core(dec, ruleset), sort_keys=True,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


# ---------------------------------------------------------------- network

def run_fixture_network(fx: dict, ruleset) -> dict:
    """Full pipeline for one fixture. Returns the per-fixture result."""
    spec = {"package": fx["package"], "version": fx["version"]}
    a = pipeline.run_assessment(spec, fx["tier"], data_dir=DATA_DIR)
    score = a.get("score") or {}
    dec = a["decision"]
    result = {
        "id": fx["id"],
        "package": a["ingest"]["package"],
        "version": a["ingest"]["version"],
        "tier": fx["tier"],
        "overall_score": dec["overall_score"],
        "decision": dec["decision"],
        "collection_mode": a["evidence"]["collection_mode"],
        "ingest_mode": a["ingest"]["collection_mode"],
        "config_version": dec["config_version"],
        "config_sha256": dec["config_sha256"],
        "canonical_sha256": canonical_sha(dec, ruleset),
        "decision_json": dec,
        "run_dir": a["run_dir"],
    }
    # cache for offline replay
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{fx['id']}.json").write_text(json.dumps({
        "id": fx["id"], "package": result["package"],
        "version": result["version"], "tier": fx["tier"],
        "score": score, "evidence": a["evidence"],
        "cached_at": _now(),
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    return result


# ---------------------------------------------------------------- offline

def run_fixture_offline(fx: dict, ruleset) -> dict:
    cache = CACHE_DIR / f"{fx['id']}.json"
    if not cache.is_file():
        raise RuntimeError(f"no cache for {fx['id']} — run network mode first")
    c = json.loads(cache.read_text(encoding="utf-8"))
    score = c["score"]
    dec = decision_mod.decide(score.get("overall_score"), c["tier"],
                              c["evidence"], ruleset)
    return {
        "id": fx["id"], "package": c["package"], "version": c["version"],
        "tier": c["tier"], "overall_score": dec["overall_score"],
        "decision": dec["decision"],
        "collection_mode": "offline-replay",
        "config_version": dec["config_version"],
        "config_sha256": dec["config_sha256"],
        "canonical_sha256": canonical_sha(dec, ruleset),
        "decision_json": dec,
    }


# ---------------------------------------------------------------- golden

def golden_path(fx_id: str) -> Path:
    return GOLDEN_DIR / f"{fx_id}.json"


def write_golden(result: dict) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    s = result["overall_score"]
    golden = {
        "id": result["id"], "package": result["package"],
        "version": result["version"], "tier": result["tier"],
        "score_min": round(s - BAND, 4) if s is not None else None,
        "score_max": round(s + BAND, 4) if s is not None else None,
        "observed_score": s,
        "expected_decision": result["decision"],
        "calibrated_at": _now(),
        "config_version": result["config_version"],
    }
    golden_path(result["id"]).write_text(
        json.dumps(golden, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")


def check_against_golden(result: dict) -> list[str]:
    errs = []
    g = json.loads(golden_path(result["id"]).read_text(encoding="utf-8"))
    if result["version"] != g["version"]:
        errs.append(f"version: resolved {result['version']} != golden {g['version']}")
    s = result["overall_score"]
    if s is None:
        errs.append("overall_score is None (scoring failed)")
    elif not (g["score_min"] <= s <= g["score_max"]):
        errs.append(f"score {s} outside golden band "
                    f"[{g['score_min']}, {g['score_max']}]")
    if result["decision"] != g["expected_decision"]:
        errs.append(f"decision {result['decision']} != golden "
                    f"{g['expected_decision']}")
    return errs


# ---------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="gateway regression runner")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true")
    mode.add_argument("--calibrate", action="store_true")
    ap.add_argument("--jobs", type=int, default=3)
    args = ap.parse_args(argv)

    manifest = load_manifest()
    fixtures = manifest["fixtures"]
    ruleset = decision_mod.RuleSet.load(REPO / manifest["config"])
    print(f"[regression] {len(fixtures)} fixtures, config v{ruleset.version} "
          f"sha256 {ruleset.sha256[:12]}…, mode="
          f"{'offline' if args.offline else 'calibrate' if args.calibrate else 'network'}")

    runner = run_fixture_offline if args.offline else run_fixture_network
    results, failures = [], {}
    if args.offline or args.jobs <= 1:
        for fx in fixtures:
            try:
                results.append(runner(fx, ruleset))
            except Exception as e:  # noqa: BLE001
                failures[fx["id"]] = f"{type(e).__name__}: {e}"
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(runner, fx, ruleset): fx for fx in fixtures}
            for fut, fx in futs.items():
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    failures[fx["id"]] = f"{type(e).__name__}: {e}"

    results.sort(key=lambda r: r["id"])
    check_fails = {}
    if not args.calibrate:
        for r in results:
            errs = check_against_golden(r)
            if errs:
                check_fails[r["id"]] = errs
    else:
        for r in results:
            write_golden(r)

    # run summary (run summaries and full decision JSONs are scratch output)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _now().replace(":", "")
    run_dir = RUNS_DIR / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    for r in results:
        (run_dir / f"{r['id']}_decision.json").write_text(
            json.dumps(r["decision_json"], indent=2, ensure_ascii=False),
            encoding="utf-8")
    summary = {
        "mode": "offline" if args.offline else
                "calibrate" if args.calibrate else "network",
        "started_at": stamp, "config_version": ruleset.version,
        "config_sha256": ruleset.sha256,
        "results": [{k: v for k, v in r.items() if k != "decision_json"}
                    for r in results],
        "pipeline_failures": failures,
        "golden_mismatches": check_fails,
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[regression] {'id':<10} {'version':<10} {'tier':<13} {'score':>7}  "
          f"{'decision':<19} canon-sha")
    for r in results:
        s = f"{r['overall_score']:.4f}" if r["overall_score"] is not None else "None"
        mark = ""
        if r["id"] in failures:
            mark = " PIPELINE-FAIL"
        elif r["id"] in check_fails:
            mark = " MISMATCH"
        print(f"[regression] {r['id']:<10} {r['version']:<10} {r['tier']:<13} "
              f"{s:>7}  {r['decision']:<19} {r['canonical_sha256'][:12]}{mark}")
    for fid, err in failures.items():
        print(f"[regression] FAIL {fid}: {err}")
    for fid, errs in check_fails.items():
        for e in errs:
            print(f"[regression] MISMATCH {fid}: {e}")
    n_bad = len(failures) + len(check_fails)
    print(f"[regression] {len(results) - len(check_fails)}/{len(fixtures)} "
          f"fixtures ok, {len(failures)} pipeline failures, "
          f"{len(check_fails)} golden mismatches -> {run_dir}")
    return 1 if (failures or check_fails or len(results) != len(fixtures)) else 0


if __name__ == "__main__":
    sys.exit(main())
