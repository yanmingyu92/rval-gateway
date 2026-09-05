# rval-gateway — R Package Validation Gateway (Tier-1, open source)

**rval-gateway** screens third-party R packages for regulated clinical
workflows. It combines [{riskmetric}](https://github.com/pharmaR/riskmetric)
risk scores with deterministic evidence collection and a config-driven
decision engine, and produces an auditable **GO / GO-WITH-CONDITIONS /
NO-GO** verdict — with every fact linked to an evidence ID and every event
appended to a hash-chained audit log.

This repository is the open-source **Tier-1** core of a two-tier validation
strategy:

| | What it does | License |
|---|---|---|
| **Tier 1** (this repo) | Risk screening: riskmetric scoring, decision engine, evidence-linked reports (HTML + PDF), audit chain, approved-package repository with Part 11 e-signatures | **MIT — free, self-host, no strings** |
| **Tier 2** (commercial) | Spec-driven deep validation: sandboxed execution engines, IQ/OQ/PQ reports, requirements-to-test traceability matrix, mutation testing, daily canary self-qualification | **Not in this repo.** Real Tier-2 product samples are exhibited in [`showcase/`](showcase/); the engine itself is licensed commercially (see [Commercial Tier-2](#commercial-tier-2)) |

## Why a gateway

Clinical teams use CRAN packages every day, but GxP accountability requires
a defensible answer to *"may we use this package, at this version, for this
intended use?"* Tier-1 answers that question with a reproducible, fully
evidenced screening decision; Tier-2 escalates high-stakes packages to
vendor-style qualification depth.

## Features

- **Risk scoring via R** — {riskmetric} overall + per-metric scores computed
  by R subprocesses (Python never computes or adjusts a score).
- **Deterministic evidence collection** — crandb, cranlogs, GitHub API and
  local DESCRIPTION/sha256; per-source network failures degrade visibly,
  offline runs are marked as such; nothing is fabricated.
- **Config-driven decisions** — thresholds and per-metric rules live in
  `config/decision_rules.yml` (versioned, sha256-pinned into every decision
  and audit record); three intended-use tiers (`exploratory`,
  `gxp-support`, `gxp-critical` — the critical tier never auto-GOs).
- **Evidence-linked reports** — one-page HTML + PDF where every fact carries
  an evidence ID; sections lacking required evidence render
  `[NO EVIDENCE - SECTION SUPPRESSED]`.
- **Hash-chained audit log** — append-only, tamper-evident
  (`data/audit/assessments.jsonl`), covering assessments, e-signatures,
  publishes, and remediation notes.
- **Approved-package repository** — serves ONLY packages whose assessment
  passed; publishing requires a 21 CFR Part 11 e-signature re-authenticated
  at signing time, with **dual approval** (two distinct signers) for
  `gxp-critical` gates. Point your platform image builds at it and
  unapproved packages physically cannot be installed.
- **Honesty layering** — the tool never signs or classifies: sign-off always
  renders `PENDING HUMAN REVIEW`; every rule is listed with its inputs,
  fired or not; code-executing riskmetric metrics are excluded by design.

## Quickstart — container

```
docker compose up -d          # serves on 127.0.0.1:8010
```

Open http://127.0.0.1:8010 — submit a package (CRAN name, GitHub URL, or a
source tarball) and watch the assessment run. Or run one from the CLI:

```
docker compose exec gateway \
  python3 run.py --pkg digest --tier exploratory --actor qa.reviewer
```

Exit codes: `0` = GO / GO-WITH-CONDITIONS, `2` = NO-GO, `1` = pipeline
error. Reports land in the `gateway_data` volume
(`/app/data/runs/<run_id>/report/report.html|.pdf` inside the container) and
are served from the web UI. The image is `rocker/r-ver` + Debian python3 +
riskmetric 0.2.7 pinned to a CRAN snapshot + minimal TeX for the PDF path.

## Quickstart — local (no Docker)

Requirements: Python ≥ 3.11 (stdlib only, no pip installs), R with
{riskmetric}, `pdflatex` optional (PDF degrades gracefully to HTML-only).

```
python -m gateway.server --port 8788        # web UI on localhost
python run.py --pkg glue --version 1.8.1 --tier gxp-support
python run.py --github https://github.com/owner/repo --ref v1.0
python run.py --tarball path/to/pkg_1.0.tar.gz --tier gxp-critical
```

Approved-package repository operations:

```
python run.py --publish --pkg glue --version 1.7.0 --signer qa.user
python run.py --repo-list            # manifest + dependency gaps
python run.py --repo-export <dir>    # static snapshot for air-gapped builds
```

## Tests & CI

```
python -m unittest discover -s tests                  # offline-capable
python tests/regression/run_regression.py --offline   # 11 pinned CRAN fixtures
```

CI (`.github/workflows/`) runs unit tests, the offline regression, a
compileall syntax check, an experimental in-container job, and a red-line
confidentiality scan (`tools/redline_scan.sh`) that fails the build on any
configured pattern hit or IP literal in md/txt/html/tex content.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — design, data flow, and
  explicitly out-of-scope areas
- [`docs/walkthrough_deck.md`](docs/walkthrough_deck.md) — 30-minute guided
  walkthrough
- [`docs/intake_sop_usage.md`](docs/intake_sop_usage.md) — how an intake SOP
  maps onto the tool (requester / reviewer / operator roles)
- [`docs/reference_test_report.md`](docs/reference_test_report.md) — how the
  report structure was benchmarked against anonymized vendor validation
  reports
- [`docs/container_verification.md`](docs/container_verification.md) —
  image build/run verification checklist
- [`CHANGELOG.md`](CHANGELOG.md)

## Showcase

The [`showcase/`](showcase/) directory is a **precomputed, static exhibit**
(no executable entry — by design):

- **Tier-1 reports** for public CRAN packages (`digest`, `glue`, `jsonlite`,
  `yaml`, `abind`), regenerated from a clean run with a synthetic reviewer
  actor — real HTML/PDF artifacts exactly as the tool produces them.
- **Tier-2 exhibit** — requirements-to-test traceability matrix samples,
  mutation-score comparisons, a real silent-truncation finding
  (`jsonlite::toJSON` default `digits=4`), and the daily canary
  self-qualification methodology. Products only: the Tier-2 engine is not
  in this repository.

## Commercial Tier-2

Tier-2 deep validation — sandboxed multi-engine execution, validation-spec
authoring, IQ/OQ/PQ reporting, traceability matrices, mutation testing, and
continuous/canary monitoring — is available as a commercial license and
consulting engagement (on-prem deployment supported). The exhibits in
[`showcase/tier2/`](showcase/tier2/) show the product output; they are not
accompanied by Tier-2 source code.

- **License of this repository:** MIT (see [`LICENSE`](LICENSE)) — applies
  to the Tier-1 core only.
- **Tier-2 / continuous validation / on-prem deployment:** please open a
  GitHub issue with the `commercial` label, or contact the maintainer via
  the GitHub profile. We respond to qualified inquiries.

## Status

Tier-1 core v0.3.0 — production-hardened, 208 offline-capable unit tests,
11-fixture offline regression, container-verified. Development continues on
the commercial Tier-2 track; this repository receives Tier-1 fixes and
hardening.
