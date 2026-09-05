"""r_adapter.py — scoring-adapter interface over {riskmetric} via two Rscript processes.

Why two processes: running pkg_assess() (network) and pkg_score() in a single
Rscript process intermittently segfaults on this platform. Process A
(score_assess.R) assesses and saves an RDS; process B (score_summarize.R)
loads the RDS, scores, and writes JSON to a file. Results are always read from
files, never from stdout. R scripts cat() progress markers.

This module is the ONLY coupling between the gateway and {riskmetric}, so a
future engine ({val.meter} at CRAN release) can replace it without touching
the decision engine (market_scan §2.5 mitigation).

R is invoked with --vanilla; the Rscript path defaults to the local install
and is overridable via the RSCRIPT environment variable.

stdlib only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASSESS_R = HERE / "score_assess.R"
SUMMARIZE_R = HERE / "score_summarize.R"

DEFAULT_RSCRIPT = shutil.which("Rscript") or "Rscript"
TIMEOUT_S = 900  # pkg_assess does network calls; cranlogs can be slow


class RAdapterError(RuntimeError):
    pass


def rscript_path() -> str:
    return os.environ.get("RSCRIPT", DEFAULT_RSCRIPT)


def _run_rscript(script: Path, args: list[str], label: str) -> None:
    exe = rscript_path()
    if not Path(exe).is_file():
        raise RAdapterError(
            f"Rscript not found at {exe!r} (override with RSCRIPT env var)")
    cmd = [exe, "--vanilla", str(script), *args]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=TIMEOUT_S,
    )
    if proc.returncode != 0:
        raise RAdapterError(
            f"{label} failed (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[-2000:]}")
    if "DONE" not in (proc.stdout or ""):
        raise RAdapterError(
            f"{label} did not emit completion marker; stdout tail: "
            f"{(proc.stdout or '').strip()[-500:]}")


def score_tarball(tarball_path: str | Path, workdir: str | Path | None = None) -> dict:
    """Run the two-process scoring pipeline on a package source tarball.

    Returns the parsed JSON dict written by process B.
    Raises RAdapterError on any failure — never fabricates a score.
    """
    tarball = Path(tarball_path)
    if not tarball.is_file():
        raise RAdapterError(f"tarball not found: {tarball}")
    if workdir is not None:
        tmp = Path(workdir)
        tmp.mkdir(parents=True, exist_ok=True)
        return _score_in_dir(tarball, tmp)
    with tempfile.TemporaryDirectory(prefix="rval_score_") as td:
        return _score_in_dir(tarball, Path(td))


def _score_in_dir(tarball: Path, tmp: Path) -> dict:
    rds_path = tmp / "assessed.rds"
    json_path = tmp / "score.json"
    # Process A: assess -> RDS
    _run_rscript(ASSESS_R, [str(tarball), str(rds_path)], "score_assess.R")
    if not rds_path.is_file():
        raise RAdapterError(f"process A did not produce {rds_path}")
    # Process B: RDS -> score -> JSON
    _run_rscript(SUMMARIZE_R, [str(rds_path), str(json_path)],
                 "score_summarize.R")
    if not json_path.is_file():
        raise RAdapterError(f"process B did not produce {json_path}")
    result = json.loads(json_path.read_text(encoding="utf-8"))
    result["json_path"] = str(json_path)
    return result


def environment_info() -> dict:
    """R and riskmetric versions without running an assessment (for /health)."""
    exe = rscript_path()
    if not Path(exe).is_file():
        return {"r_version": None, "riskmetric_version": None,
                "error": f"Rscript not found at {exe!r}"}
    code = (
        "cat(R.version.string, '|', "
        "as.character(packageVersion('riskmetric')), '\\n', sep='')"
    )
    try:
        proc = subprocess.run(
            [exe, "--vanilla", "-e", code],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            raise RAdapterError(proc.stderr.strip()[-500:])
        r_ver, rm_ver = proc.stdout.strip().split("|")
        return {"r_version": r_ver, "riskmetric_version": rm_ver}
    except Exception as e:  # noqa: BLE001
        return {"r_version": None, "riskmetric_version": None,
                "error": f"{type(e).__name__}: {e}"}
