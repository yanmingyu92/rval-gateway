"""repo.py — approved-package whitelist repository (the "PPM + validation" piece).

The gateway doubles as a CRAN-like package repository that serves ONLY
packages whose assessment passed. Platform image builds point ``repos`` at it
→ unapproved packages physically cannot be installed.

Layout under ``data/repo/``::

    src/contrib/{pkg}_{version}.tar.gz   artifacts (source or binary flavor)
    src/contrib/PACKAGES                 package index (regenerated per publish)
    src/contrib/PACKAGES.gz              gzipped index
    manifest.json                        per-artifact provenance + deps

Publish gating: ``publish()`` is allowed ONLY when the audit log contains an
assessment for that exact package+version whose decision is GO or
GO-WITH-CONDITIONS AND whose recorded tarball sha256 matches the pinned
tarball on disk. NO-GO or no assessment → refused with the reason. Every
publish appends an audit record of type ``publish`` referencing the
assessment's ``record_hash`` (the hash chain continues). Dual approval:
publishing an assessment gated at tier ``gxp-critical`` requires valid
signatures from two distinct signers; other tiers publish with one.

Binary flavor: the platform's R images install Posit Package Manager (P3M)
Linux binaries; P3M serves noble binaries through the src/contrib path when
the User-Agent looks like R on Linux. With ``binary=True`` that artifact is
tried first (snapshot date configurable); on failure the source tarball is
published instead and the fallback is recorded in the manifest. If neither is
available (offline) → clear error; nothing is fabricated.

Dependency gating: Depends/Imports/LinkingTo from the DESCRIPTION are
resolved against the repo manifest plus the configurable platform baseline
(``config/platform_baseline.json``). The publish result lists covered vs
missing deps (each missing dep needs its own assess+publish — chain gating).
Dependencies are NEVER auto-published.

stdlib only.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import audit as audit_mod
from . import esign as esign_mod
from . import ingest as ingest_mod

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
BASELINE_PATH = Path(__file__).resolve().parent.parent / "config" / "platform_baseline.json"

DEFAULT_P3M_SNAPSHOT = "2026-08-01"  # matches the platform image build arg
P3M_NOBLE = "https://packagemanager.posit.co/cran/__linux__/noble/{snap}/src/contrib/{pkg}_{ver}.tar.gz"
# P3M serves the Linux binary build only when the User-Agent matches R's own
# HTTPUserAgent format: "R (<ver> <arch> <arch> linux-gnu)". Verified live
# 2026-09-03: this UA returns the binary (Meta/ + Built: field); a bare
# "R 4.5.3 x86_64-pc-linux-gnu" gets the source tarball instead.
R_LINUX_UA = "R (4.5.3 x86_64-pc-linux-gnu x86_64 linux-gnu)"
TIMEOUT_S = 60

REPO_FIELDS = ("Package", "Version", "Depends", "Imports", "LinkingTo",
               "License", "NeedsCompilation", "Built")


class RepoError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_dir(data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    return Path(data_dir) / "repo"


def contrib_dir(data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    return repo_dir(data_dir) / "src" / "contrib"


def load_manifest(data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    p = repo_dir(data_dir) / "manifest.json"
    if not p.is_file():
        return {"schema": "rval-gateway repo manifest v1", "artifacts": []}
    return json.loads(p.read_text(encoding="utf-8"))


def _save_manifest(manifest: dict, data_dir: Path) -> None:
    p = repo_dir(data_dir) / "manifest.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                 encoding="utf-8")


def load_baseline(path: Path = BASELINE_PATH) -> set[str]:
    """Configurable platform baseline: packages the platform image already
    installs (they need no gateway publish to be present at runtime)."""
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    return {str(x) for x in d.get("packages", [])}


# R itself and the base packages ship with R — never dependency gaps.
_R_BASE = {"R", "base", "compiler", "datasets", "grDevices", "graphics",
           "grid", "methods", "parallel", "splines", "stats", "stats4",
           "tcltk", "tools", "utils"}


def parse_dep_fields(description: dict) -> list[str]:
    """Depends/Imports/LinkingTo package names (constraints, R and base
    packages dropped — base packages ship with R and are never gaps)."""
    out = []
    for field in ("Depends", "Imports", "LinkingTo"):
        raw = description.get(field)
        if not raw:
            continue
        for item in raw.split(","):
            name = item.strip().split("(")[0].strip()
            if name and name not in _R_BASE:
                out.append(name)
    return sorted(set(out))


def dependency_gaps(description: dict, data_dir: Path = DEFAULT_DATA_DIR,
                    baseline: set[str] | None = None) -> dict:
    """Split a package's deps into covered (repo or baseline) vs missing."""
    deps = parse_dep_fields(description)
    baseline = load_baseline() if baseline is None else baseline
    published = {a["package"] for a in load_manifest(data_dir)["artifacts"]}
    covered = sorted(d for d in deps if d in published or d in baseline)
    missing = sorted(d for d in deps if d not in published and d not in baseline)
    return {"dependencies": deps, "covered": covered, "missing": missing}


def regenerate_indexes(data_dir: Path = DEFAULT_DATA_DIR) -> int:
    """Rebuild PACKAGES / PACKAGES.gz from the tarballs in src/contrib.
    Returns the number of stanzas written."""
    contrib = contrib_dir(data_dir)
    contrib.mkdir(parents=True, exist_ok=True)
    stanzas = []
    for tb in sorted(contrib.glob("*.tar.gz")):
        desc = ingest_mod.read_description_from_tarball(tb)
        lines = []
        for f in REPO_FIELDS:
            if desc.get(f):
                lines.append(f"{f}: {desc[f]}")
        stanzas.append("\n".join(lines))
    body = "\n\n".join(stanzas) + ("\n" if stanzas else "")
    (contrib / "PACKAGES").write_text(body, encoding="utf-8")
    (contrib / "PACKAGES.gz").write_bytes(gzip.compress(body.encode()))
    return len(stanzas)


def _gate_status(package: str, version: str, sha256: str,
                 data_dir: Path) -> tuple[dict | None, bool, bool]:
    """Scan the audit log: returns (newest passing assessment | None,
    saw_same_bytes_with_failing_decision, saw_sha_mismatch)."""
    log = audit_mod.AuditLog(Path(data_dir) / "audit" / "assessments.jsonl")
    passing = None
    same_bytes_failing = sha_mismatch = False
    if log.path.is_file():
        for line in log.path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (rec.get("record_type") != "assessment"
                    or rec.get("package") != package
                    or rec.get("version") != version):
                continue
            if rec.get("tarball_sha256") == sha256:
                if rec.get("decision") in ("GO", "GO-WITH-CONDITIONS"):
                    passing = rec  # later records win (newest passing)
                else:
                    same_bytes_failing = True
            else:
                sha_mismatch = True
    return passing, same_bytes_failing, sha_mismatch


def publish(package: str, version: str, binary: bool = False,
            data_dir: Path = DEFAULT_DATA_DIR,
            snapshot: str = DEFAULT_P3M_SNAPSHOT,
            signer_id: str | None = None,
            signer_password: str | None = None,
            api_url: str | None = None,
            signers: list | None = None) -> dict:
    """Publish an assessed package into the whitelist repository.

    Refuses (RepoError) unless the audit log holds a GO/GO-WITH-CONDITIONS
    assessment for this exact package+version whose tarball sha256 matches
    the pinned tarball in the store, AND the caller supplies valid 21 CFR
    Part 11 electronic signature(s) — each signer is re-authenticated
    against the platform login API at signing time; session cookies are
    never sufficient. Every signature binds the gating assessment's
    ``record_hash`` and joins the same hash chain.

    Signatures are supplied either as ``signers`` — a list of
    ``(signer_id, password)`` pairs — or via the legacy single-signer
    ``signer_id`` + ``signer_password`` pair. Dual approval: when the gating
    assessment's tier is ``gxp-critical``, signatures from at least TWO
    DISTINCT signers are required; other tiers publish with one."""
    data_dir = Path(data_dir)
    store = data_dir / "tarballs" / package / version
    tarballs = sorted(store.glob("*.tar.gz")) if store.is_dir() else []
    if not tarballs:
        raise RepoError(f"no pinned tarball for {package} {version} — "
                        "run an assessment first")
    src_tarball = tarballs[0]
    src_sha = _sha256(src_tarball)

    # gating: only a passing assessment for these exact bytes unlocks publish
    gate, same_bytes_failing, sha_mismatch = _gate_status(
        package, version, src_sha, data_dir)
    if gate is None:
        if sha_mismatch and not same_bytes_failing:
            raise RepoError(
                f"publish refused: pinned tarball sha256 {src_sha[:12]}… does "
                f"not match any assessment record for {package} {version} — "
                "re-assess the current tarball")
        raise RepoError(
            f"publish refused: no GO / GO-WITH-CONDITIONS assessment on "
            f"record for {package} {version} (sha256 {src_sha[:12]}…). "
            "NO-GO outcomes and unassessed packages cannot be published — "
            "a NO-GO escalates to Tier 2 full validation instead.")

    log = audit_mod.AuditLog(data_dir / "audit" / "assessments.jsonl")

    # 21 CFR Part 11: publish requires signature events made with fresh
    # credentials (re-authentication), bound to the gating assessment
    if signers is None:
        signers = [(signer_id, signer_password)] if signer_id else []
    signers = [(str(s), p) for s, p in signers if s]
    if not signers:
        raise RepoError(
            "publish refused: electronic signature required (21 CFR Part 11) "
            "— provide signer credentials (signer_id + signer_password); a "
            "login session alone is not sufficient for signing")
    distinct = {s for s, _ in signers}
    if len(distinct) != len(signers):
        raise RepoError(
            "publish refused: duplicate signer — each signature must come "
            "from a distinct signer (segregation of duties)")
    if gate.get("tier") == "gxp-critical" and len(distinct) < 2:
        raise RepoError(
            "publish refused: tier gxp-critical requires dual approval — "
            f"valid electronic signatures from at least 2 distinct signers "
            f"(got {len(distinct)}); a single sign-off is not sufficient on "
            "the critical path")

    esign_recs = []
    for sid, pw in signers:
        if pw is None:
            raise RepoError(
                f"publish refused: missing signature password for signer "
                f"{sid} — re-authentication is mandatory for every signer")
        try:
            rec = esign_mod.sign(
                log, meaning="approved", signer_id=sid,
                password=pw,
                api_url=api_url or os.environ.get("RVAL_PLATFORM_API_URL", ""),
                object_type="assessment",
                object_id=f"{package} {version}",
                object_hash=gate["record_hash"])
        except esign_mod.ESIGNError as e:
            raise RepoError(f"publish refused: {e}") from e
        esign_recs.append(rec)

    # validate every signature against the chain (existing esign
    # validation: chained, meaning 'approved', binds the gating assessment,
    # produced through re-authentication)
    records = log._records()
    sig_payload = []
    for rec in esign_recs:
        chained = esign_mod.validate_for_publish(records, rec,
                                                 gate["record_hash"])
        sig_payload.append({"signer_id": chained["signer_id"],
                            "record_hash": chained["record_hash"]})
    if len({s["signer_id"] for s in sig_payload}) != len(sig_payload):
        raise RepoError(
            "publish refused: signatures resolve to the same signer "
            "identity — dual approval requires two distinct people")

    description = ingest_mod.read_description_from_tarball(src_tarball)
    gaps = dependency_gaps(description, data_dir)

    # artifact selection: binary flavor first when requested
    flavor = "source"
    artifact_bytes = None
    binary_error = None
    origin_url = f"local pinned tarball (assessment {gate['record_hash'][:12]}…)"
    if binary:
        url = P3M_NOBLE.format(snap=snapshot, pkg=package, ver=version)
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": R_LINUX_UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                artifact_bytes = resp.read()
            flavor = "binary-noble"
            origin_url = url
        except Exception as e:  # noqa: BLE001 — fall back to source
            binary_error = f"{type(e).__name__}: {e}"
    if artifact_bytes is None:
        artifact_bytes = src_tarball.read_bytes()

    contrib = contrib_dir(data_dir)
    contrib.mkdir(parents=True, exist_ok=True)
    dest = contrib / f"{package}_{version}.tar.gz"
    dest.write_bytes(artifact_bytes)
    artifact_sha = _sha256(dest)
    n = regenerate_indexes(data_dir)

    manifest = load_manifest(data_dir)
    manifest["artifacts"] = [a for a in manifest["artifacts"]
                             if not (a["package"] == package
                                     and a["version"] == version)]
    entry = {
        "package": package, "version": version, "flavor": flavor,
        "sha256": artifact_sha, "origin_url": origin_url,
        "assessment_record_hash": gate["record_hash"],
        "assessment_decision": gate["decision"],
        "assessment_tier": gate.get("tier"),
        "esign_record_hash": sig_payload[0]["record_hash"],
        "esign_signer": sig_payload[0]["signer_id"],
        "esign_meaning": esign_recs[0]["meaning"],
        "esign_signatures": sig_payload,
        "published_at": _now(),
        "dependency_gaps": gaps,
    }
    if binary and binary_error:
        entry["binary_fallback"] = (
            f"P3M noble binary fetch failed ({binary_error}); published the "
            "source tarball instead")
    manifest["artifacts"].append(entry)
    _save_manifest(manifest, data_dir)

    record = log.append(audit_mod.make_publish_record(
        package=package, version=version, flavor=flavor,
        artifact_sha256=artifact_sha,
        assessment_record_hash=gate["record_hash"],
        dependency_gaps=gaps,
        esign_record_hash=sig_payload[0]["record_hash"],
        esign_signer=sig_payload[0]["signer_id"],
        esign_signatures=sig_payload))

    return {"published": True, "package": package, "version": version,
            "flavor": flavor, "sha256": artifact_sha,
            "binary_fallback": entry.get("binary_fallback"),
            "dependency_gaps": gaps, "index_stanzas": n,
            "audit_record_hash": record["record_hash"],
            "esign_record_hash": sig_payload[0]["record_hash"],
            "esign_signer": sig_payload[0]["signer_id"],
            "esign_meaning": esign_recs[0]["meaning"],
            "esign_signatures": sig_payload,
            "repo_dir": str(repo_dir(data_dir))}


def list_repo(data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    m = load_manifest(data_dir)
    m["repo_dir"] = str(repo_dir(data_dir))
    return m


def export_repo(dest: str | Path, data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    """Write a static snapshot of the repo (for air-gapped image builds)."""
    dest = Path(dest)
    src = repo_dir(data_dir)
    if not src.is_dir():
        raise RepoError("repository is empty — nothing to export")
    if dest.resolve() == src.resolve() or src in dest.resolve().parents:
        raise RepoError("export destination must be outside the live repo")
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in sorted(src.rglob("*")):
        if f.is_file():
            target = dest / f.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(f.read_bytes())
            n += 1
    return {"exported_files": n, "dest": str(dest)}
