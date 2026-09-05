# Container Verification Checklist (Phase 4)

**Status: build + run verification EXECUTED 2026-09-05 on a Docker host.**
Verified: image build from this Dockerfile (steps 1), in-container unit
suite + offline regression 11/11 (step 2), compose serve + `/health` on an
alternate host port (step 3), and five end-to-end CLI assessments through
the real network pipeline producing HTML + PDF reports (step 4, tiers
`exploratory` / `gxp-support` / `gxp-critical`, the last one exercising the
NO-GO path). Steps 5 (restart persistence) and 6 (slim-image PDF
degradation) remain spot-check items. The original static review is kept
below for reference.

## Static review already performed (authoring workstation)

- Base image tag `rocker/r-ver:4.5.3` (originally authored for 4.6.0;
  switched because the pinned 2026-04-15 snapshot's Rcpp does not compile
  against R 4.6 headers — see the Dockerfile comments for the verified
  details).
- Snapshot `https://packagemanager.posit.co/cran/2026-04-15` confirmed to
  serve `riskmetric_0.2.7.tar.gz` (HTTP 200) and to list `Version: 0.2.7` in
  its package index (2026-09-02). The build fails hard if the installed
  version differs from 0.2.7 (drift guard in the install RUN).
- Every `COPY` source path exists in the repo: `gateway/`, `config/`,
  `run.py`, `README.md`, `tests/`, `tools/`.
- `.dockerignore` excludes `.git`, `data/`, `internal_reference/`,
  regression scratch dirs, and stray tarballs; `tests/regression/cache/` and
  `golden/` are intentionally included so `--offline` regression runs
  in-container with no network and no extra setup.
- Application bind semantics: default `127.0.0.1` outside containers;
  in-container `GATEWAY_HOST=0.0.0.0` (required for the port mapping) with
  host-side `127.0.0.1:8788:8788` keeping the service localhost-only.
- Non-root user (`gateway`, uid 10001); `/app/data` owned by that user and
  volume-mounted. No secrets in the image; `GITHUB_TOKEN` is run-time
  passthrough only.
- TeX packages cover every `\usepackage` in `gateway/templates/report.tex`
  (geometry, booktabs, longtable, array, xcolor, fancyhdr ⊆
  texlive-latex-base + texlive-latex-recommended).

## Execution checklist (run on a Docker host)

1. **Build**
   ```
   docker build -t rval-gateway:0.3.0 .
   ```
   Expect: apt installs python3 + texlive; riskmetric installs from the
   2026-04-15 snapshot; build FAILS if riskmetric resolves to ≠ 0.2.7.
2. **In-image self-test (no network needed beyond build):**
   ```
   docker run --rm rval-gateway:0.3.0 python3 -m unittest discover -s tests
   docker run --rm rval-gateway:0.3.0 python3 tests/regression/run_regression.py --offline
   ```
   Expect: unit suite OK (network tests skip), offline regression 11/11.
3. **Serve + health**
   ```
   docker compose up -d
   curl http://127.0.0.1:8010/health
   ```
   Expect JSON: status ok; tool_version 0.3.0; r_version; riskmetric_version
   "0.2.7"; config_version "1.0.0".
4. **One real assessment (network):**
   ```
   docker exec rval-gateway python3 run.py --pkg abind --version 1.4-8 --tier gxp-critical
   ```
   Expect: decision printed, report.html + report.pdf generated under
   `data/runs/…` (pdflatex path exercised in-container).
5. **Audit persistence across restart:**
   ```
   docker exec rval-gateway python3 -c \
     "from gateway.audit import AuditLog; print(AuditLog().verify_chain())"
   docker compose restart
   # repeat the verify_chain call — record count must not decrease and
   # ok must stay True (data/ is on the gateway_data volume).
   ```
6. **PDF degradation check (optional):** build a slim variant without the two
   texlive packages; repeat step 4 — expect HTML report produced,
   `pdf not generated` note, no crash.

## Known unverifiable-here items

- Image size (texlive adds several hundred MB; slimming = drop texlive, PDF
  degrades gracefully).
- HEALTHCHECK timing on first boot under load.
- Whether Ubuntu noble's `python3` (3.12) behaves identically on all paths —
  mitigated by step 2 running the full unit + offline regression suite
  in-container.
