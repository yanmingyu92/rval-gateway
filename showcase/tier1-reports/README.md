# Tier-1 assessment reports — precomputed exhibit

Real reports produced by this repository's Tier-1 pipeline, running in the
published container image. Each assessment was executed against live public
sources (CRAN / crandb / cranlogs / GitHub API) in a clean, one-off
environment with a **synthetic reviewer actor** (`qa.reviewer`) — no
production data, no real user accounts.

| Package | Version | Intended-use tier | Overall risk score | Decision |
|---|---|---|---|---|
| [yaml](yaml/report.html) | 2.3.12 | exploratory | 0.191 | **GO** |
| [glue](glue/report.html) | 1.8.1 | gxp-support | 0.210 | **GO-WITH-CONDITIONS** |
| [jsonlite](jsonlite/report.html) | 2.0.0 | gxp-support | 0.283 | **GO-WITH-CONDITIONS** |
| [digest](digest/report.html) | 0.6.39 | exploratory | 0.377 | **GO-WITH-CONDITIONS** |
| [abind](abind/report.html) | 1.4-8 | gxp-critical | 0.621 | **NO-GO** |

Notes on reading the reports:

- Every fact carries an **evidence ID**; every decision rule is listed with
  its input value and threshold, fired or not.
- Classification and sign-off render as `PENDING HUMAN REVIEW` — the tool
  screens, humans decide.
- `abind` at `gxp-critical` demonstrates the strictest tier: a mid-range
  risk score that would pass elsewhere is NO-GO'd for critical-path use,
  escalating to full Tier-2 validation.
- Each directory also contains the `report.pdf` (same content, print path)
  and the machine-readable `decision.json`.

Scores are point-in-time (cranlogs-driven metrics drift between days); the
decision logic itself is pinned by `config/decision_rules.yml`, whose
sha256 is embedded in every decision and audit record.

A matching sample of the hash-chained audit log produced by these runs is
in [`../audit-chain-sample/`](../audit-chain-sample/).
