# Architecture — R Package Validation Gateway

Tier-1 screening gateway over {riskmetric} scores: name/URL/tarball in, an
evidence-linked GO / GO-WITH-CONDITIONS / NO-GO decision out, with an
append-only audit trail. All facts in the report carry evidence IDs. Since
0.3.0 the gateway also serves an **approved-package repository** (whitelist
repo) and gates all non-public endpoints behind platform authentication when
deployed on the platform.

## Component diagram

```
                 +--------------------------------------------------+
  user ----------|  run.py (CLI)   OR   server.py (http.server,     |
  (browser/      |                   127.0.0.1 only, /health)       |
   shell)        +-----------------------+--------------------------+
                                       |
                                       v
                          +------------------------+
                          |  pipeline.py           |  orchestration
                          +----+------+------+-----+
                               |      |      |
              +----------------+      |      +------------------+
              v                       v                         v
     +----------------+    +-------------------+     +----------------------+
     | ingest.py      |    | r_adapter.py      |     | evidence.py          |
     | CRAN name+ver  |    |  (Python wrapper) |     | crandb / cranlogs /  |
     | GitHub URL+ref |    +----+---------+----+     | GitHub API / local   |
     | upload tarball |         |         |          | DESCRIPTION+sha256   |
     | -> pinned tar- |  process A   process B       | + riskmetric metrics |
     |    ball +      |  score_      score_          | -> EV-001... register|
     |    provenance  |  assess.R    summarize.R     +----------------------+
     +-------+--------+  (pkg_       (readRDS->             |
             |          assess->      pkg_score->           |
             |          saveRDS)      JSON file)            |
             v              |               |               v
     data/tarballs/         v               v      +----------------------+
     <pkg>/<ver>/    Rscript --vanilla (x2,         | decision.py          |
     provenance.json  separate processes)           | YAML rules x tier    |
                                                    | -> GO / CONDITIONS / |
                                                    |    NO-GO + every     |
                                                    |    rule evaluated    |
                                                    +----------+-----------+
                                                               |
                                          +--------------------+--------------------+
                                          v                                         v
                                +---------------------+                  +---------------------+
                                | report.py           |                  | audit.py            |
                                | templates/report.   |                  | data/audit/         |
                                |   {html,tex}        |                  |   assessments.jsonl |
                                | -> report.html +    |                  | append-only,        |
                                |    report.pdf       |                  | sha256 prev/record  |
                                |    (pdflatex)       |                  | hash chain (both    |
                                +---------------------+                  | assessment+publish) |
                                                                       +----------+----------+
                                                                                  |
   +-------------------------------+                        +---------------------v----------+
   | platform_auth.py              |                        | repo.py                        |
   | all paths except /health and  |                        | publish() gated on a passing   |
   | /repo/*: Bearer/?token= ->    |                        | assessment (pkg+ver+sha256     |
   | /api/session; cv_session      |                        | match); writes data/repo/      |
   | cookie -> /api/verify-session;|                        | src/contrib + PACKAGES[.gz] +  |
   | then access_control.json      |                        | manifest.json; P3M noble       |
   | whitelist (re-read/req).      |                        | binary flavor optional; dep    |
   | Fail closed (503) when API    |                        | gap list vs baseline; never    |
   | unreachable; dev mode when    |                        | auto-publishes deps. Served    |
   | the API-URL env var is unset. |                        | read-only, unauthenticated, at |
   +-------------------------------+                        | /repo/ (builds cannot SSO).    |
                                                           +--------------------------------+

Config: config/decision_rules.yml (parsed by gateway/miniyaml.py — stdlib has
no YAML). Versioned (config_version semver); sha256 recorded per decision.
Server URL generation honors GATEWAY_BASE_PATH (prefix-stripped proxy).
```

## Data flow

1. **Ingest** (`ingest.py`): resolve the input to a pinned tarball stored at
   `data/tarballs/<pkg>/<version>/` with `provenance.json` (sha256, source
   URL, resolved version, origin). CRAN current version is resolved from the
   PACKAGES index; archived versions from `src/contrib/Archive/`. GitHub URLs
   fetch the codeload tarball and read name/version from DESCRIPTION. On
   network failure an exact package+version cache hit is used and marked
   `collection_mode=offline-fallback`; otherwise ingest fails cleanly —
   metadata is never fabricated.
2. **Score** (`r_adapter.py` + two R scripts): builds a `pkg_source` ref from
   the *extracted* tarball (riskmetric 0.2.7 requires a source directory —
   `verify_pkg_source` checks `dir.exists`, a tarball path degrades to
   `pkg_missing`) and returns overall + per-metric scores as JSON.
3. **Evidence** (`evidence.py`): deterministic collectors (adapted from the
   E2 prototype's `s1_collect.py`) — crandb, cranlogs, GitHub API, local
   DESCRIPTION/sha256, plus the riskmetric metrics themselves. Every fact
   gets an `EV-NNN` id; per-source failures degrade silently and are listed
   under `network_sources_failed`.
4. **Decide** (`decision.py`): tier x thresholds x per-metric rules; output
   lists every rule evaluated with inputs and thresholds.
5. **Report** (`report.py`): one-page HTML (inline CSS) + PDF via pdflatex;
   sections lacking evidence render `[NO EVIDENCE - SECTION SUPPRESSED]`;
   classification/sign-off slots render "PENDING HUMAN REVIEW".
6. **Audit** (`audit.py`): one JSONL record per assessment, hash-chained
   (`prev_hash`/`record_hash`), append-only, `verify_chain()` for integrity.

## The two-R-process rationale

Running `pkg_assess()` (network-heavy) and `pkg_score()` in a single Rscript
process intermittently **segfaults** on this workstation (R 4.6.0, riskmetric
0.2.7). The mandatory pattern is therefore:

- **Process A** (`score_assess.R`): `pkg_assess()` with an explicit
  `assessments=` list, then `saveRDS()`.
- **Process B** (`score_summarize.R`): `readRDS()` → `pkg_score()` →
  `summarize_scores()` + per-metric scores → JSON written **to a file**.

Results are never read from stdout (only files); both scripts `cat()`
progress markers and the Python wrapper requires the `DONE` marker.

## Security posture

- **Assessed package code is never executed.** The code-executing metrics
  (`assess_covr_coverage`, `assess_r_cmd_check` — they run tests/checks on
  source refs) are excluded from the `assessments=` list, and both R scripts
  hard-stop if those columns ever appear in the assessment output.
- **Platform auth, fail closed**: on the platform, every path except
  `/health` and `/repo/*` requires a validated session (Bearer/`?token=` →
  `/api/session`; `cv_session` cookie → `/api/verify-session`), followed by
  `access_control.json` whitelist authorization (re-read per request). When
  the platform API is configured but unreachable → 503, never silent allow.
  Auth is disabled only when the platform-API-URL environment variable (see
  `gateway/platform_auth.py`) is unset (local dev, loud
  startup warning). `/repo/` is deliberately unauthenticated: image builds
  cannot perform SSO, and the repo serves approved artifacts only.
- **Publish gating**: the repository accepts only packages with a GO /
  GO-WITH-CONDITIONS assessment whose recorded tarball sha256 matches the
  pinned bytes; publish events extend the same hash chain.
- **Localhost binding only** outside containers; in-container `0.0.0.0` is
  mapped back to host-localhost by compose (and prints a warning otherwise).
- **Hash-chained audit trail**: appending is the only write operation;
  tampering with any earlier record breaks the chain verifiably.
- **Pinned artifacts**: every assessment is anchored to a sha256 of the exact
  tarball assessed.

## Config model

`config/decision_rules.yml` adopts the {riskassessment} db-config pattern —
score-range rules per decision category plus per-metric expression rules —
extended with intended-use tiers (`exploratory` / `gxp-support` /
`gxp-critical`) and condition strings. Parsed by `gateway/miniyaml.py`, a
documented YAML subset (nested maps by indentation, `- ` lists, scalars,
comments, quoted strings). `config_version` is semver; the sha256 of the file
is embedded in every decision, report, and audit record.

## Phase 4 roadmap note

Containerization is planned for Phase 4 (Dockerfile + compose following the
target platform's localhost-bound, single-reverse-proxy conventions). It
**cannot be locally verified**: the build workstation has no Docker
(build/run verification is performed on a Docker host — done 2026-09-05,
see `docs/container_verification.md`). Phase 4 acceptance therefore splits into
static verification (Dockerfile lint, compose config validation) locally and
build/run verification on a Docker-equipped runner. The scoring adapter
(`r_adapter.py`) is the deliberate isolation seam for the future migration
from {riskmetric} (maintenance-only upstream) to {val.meter} at its CRAN
release, and for re-enabling code-executing metrics inside a sandboxed
container.
