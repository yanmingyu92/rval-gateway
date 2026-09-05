# Changelog

All notable changes to the R Package Validation Gateway. Semver; decision
config (`config/decision_rules.yml`) is versioned independently
(`config_version`, currently 1.0.0).

## 0.3.0 — 2026-09-02 (platform deployment + approved-package repository)

Added:
- `gateway/repo.py`: CRAN-like whitelist repository under `data/repo/`
  (`src/contrib/` + `PACKAGES`/`PACKAGES.gz` regenerated per publish +
  `manifest.json` with per-artifact flavor/sha256/origin/gating-assessment
  hash). Publish gating: only exact package+version+sha256 with a GO /
  GO-WITH-CONDITIONS audit record can be published; NO-GO/absent/mismatched
  → refused with reason. Optional P3M noble binary flavor (snapshot default
  2026-08-01) with recorded source fallback. Dependency-gap reporting against
  the repo + `config/platform_baseline.json` (seeded from the platform R
  image); dependencies are never auto-published. Publish events join the
  audit hash chain as `publish` records referencing the assessment's
  `record_hash`.
- CLI: `--publish --pkg X --version V [--binary] [--snapshot DATE]`,
  `--repo-list`, `--repo-export DIR` (air-gapped snapshot).
- `gateway/platform_auth.py` (stdlib-only): platform session auth on all
  paths except `/health` and `/repo/` — Bearer/`?token=` via `/api/session`
  (60s cache), `cv_session` cookie via `/api/verify-session`; then
  `access_control.json` `user_rules` whitelist authorization (re-read per
  request). Fail-closed 503 when the platform API is unreachable; auth
  disabled with a loud startup warning when the platform-API-URL environment
  variable (see `gateway/platform_auth.py`) is unset (local dev). `/repo/`
  is intentionally unauthenticated (image builds
  cannot perform SSO; approved artifacts only; localhost-bound).
- `GATEWAY_BASE_PATH` support: all generated URLs are prefixed so the UI
  works behind the prefix-stripping proxy.
- Server: `/repo-view` (manifest + dependency gaps), `POST /publish`,
  publish action on the report page when the decision permits, `/repo/*`
  read-only static serving.
- The "PPM + validation" consumption
  contract for the platform R image (live mode, air-gapped mode, dependency
  closure rule, R 4.6.0-vs-4.5.3 caveat) — kept as internal integration
  notes, not part of the open-source tree.
- Tests: auth (mocked platform API), repository (index generation incl. an R
  `available.packages()` round-trip, publish gating, gaps, export),
  base-path URL generation. 101 tests total.

## 0.2.0 — 2026-09-02 (Phase 3 reference testing + Phase 4 production readiness)

Added:
- Vendor-report structure benchmark: sanitized `docs/reference_test_report.md`;
  raw alignment in gitignored `internal_reference/` (internal-only).
- Public regression suite: `tests/regression/` (11 pinned CRAN fixtures,
  golden score bands + decisions, `--offline` deterministic replay from
  committed cache, `--calibrate` maintainer mode).
- Edge-case tests: Archive-path ingest, 404 clean failure, per-collector
  degradation, minimal-evidence decisions, huge-dependency rendering.
- Container artifacts: `Dockerfile` (rocker/r-ver:4.6.0, PPM snapshot
  2026-04-15 pinned riskmetric 0.2.7, non-root, HEALTHCHECK),
  `docker-compose.yml` (localhost port mapping, `gateway_data` volume),
  `.dockerignore`, `docs/container_verification.md`. NOT build-verified on
  the authoring workstation (no Docker) — verification checklist provided.
- CI: `.github/workflows/ci.yml` (unit tests, offline regression, vendored
  red-line scan, compileall; container job experimental).
  `tools/redline_scan.sh` vendored for self-containment.
- SOP + walkthrough docs: `docs/intake_sop_usage.md`,
  `docs/walkthrough_deck.md`.
- Server bind via `GATEWAY_HOST` / `GATEWAY_PORT` env vars (default stays
  127.0.0.1; 0.0.0.0 prints an exposure warning).
- Optional `GITHUB_TOKEN` env passthrough for the GitHub evidence collector
  (never stored, never logged).

Fixed:
- Evidence sources, report footer, and audit record no longer embed
  workstation-absolute paths (red-line hygiene for generated artifacts).
- Empty crandb responses no longer fabricate `cran.imports_count: 0`.
- `environment_info()` R quoting fixed for Windows command lines.
- `low_downloads` / `no_source_control` decision rules re-keyed to
  deterministic evidence (riskmetric 0.2.7 `downloads_1yr` scoring is
  monotone-increasing in downloads — upstream quirk; `pkg_source` refs
  cannot see source-control state).

## 0.1.0 — 2026-09-02 (Phase 2 prototype)

Initial build: ingest shim (CRAN name+version / GitHub URL / uploaded
tarball, pinned store + provenance, offline fallback), two-process
{riskmetric} R adapter (code-executing metrics excluded), deterministic
evidence collectors with evidence IDs, config-driven tiered decision engine
(GO / GO-WITH-CONDITIONS / NO-GO), evidence-linked HTML+PDF report with
no-evidence suppression, append-only hash-chained audit trail, stdlib
http.server web UI + `/health`, `run.py` CLI, 56-test unittest suite.
