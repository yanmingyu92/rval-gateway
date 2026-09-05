# Walkthrough Deck — R Package Validation Gateway (30 minutes)

Slide-per-section outline. Speaker notes in italics. Demo commands reference
real entry points in this repo.

---

## Slide 1 — Title

- R Package Validation Gateway — Tier-1 screening, evidence-linked
- Phase 2 prototype → Phase 4 production-ready
- Presenter / date

*Set the frame: this is about making intake decisions defensible, not about
replacing qualification.*

## Slide 2 — The problem

- R package intake today: ad-hoc, unreviewed, unreproducible
- GxP context demands: pinned versions, documented risk rationale, audit trail
- Commercial qualification exists but is heavy for every package request

*Ask: "who here has installed a CRAN package into a GxP-adjacent workflow
without a formal review?"*

## Slide 3 — Two-tier strategy

- Tier 1 (this tool): fast, free, internal screening — GO / CONDITIONS / NO-GO
- Tier 2: full vendor-style qualification — purchased/triggered, not default
- The screening decision IS the Tier-2 purchase trigger

*Key economics: screening is cheap; qualification is bought only on trigger.*

## Slide 4 — What the gateway does (pipeline on one slide)

- In: CRAN name+version | GitHub URL | tarball upload; intended-use tier
- Pinned tarball + sha256 → {riskmetric} score (R subprocess, two processes)
- Deterministic evidence collectors → evidence IDs
- Config-driven decision engine → decision + conditions
- One-page evidence-linked report (HTML+PDF) + append-only audit record

## Slide 5 — Live demo part 1: exploratory screening

```
python run.py --pkg glue --version 1.7.0 --tier exploratory
```

- Point at: resolved version + sha256, overall score, decision banner
- Show the rules table: every rule, its input, fired or not

*Regression fixture outcome: glue 1.7.0 scores ~0.21 → GO at exploratory.*

## Slide 6 — Live demo part 2: escalation

```
python run.py --pkg abind --version 1.4-8 --tier gxp-support
```

- Same package class, stricter tier → NO-GO → Tier-2 escalation condition
- Show the conditions list and the escalation line

*Observed: abind 1.4-8 scores ~0.62 → NO-GO at gxp-support. Emphasize: the
decision changed with the TIER, not just the package.*

## Slide 7 — Decision transparency (no black box)

- Thresholds per tier live in `config/decision_rules.yml` (versioned)
- Report shows EVERY rule evaluated: input value, threshold, fired?
- gxp-critical NEVER auto-GOs — human gate is structural, not a convention

*Open config/decision_rules.yml on screen; show one metric rule end to end.*

## Slide 8 — Evidence register

- Every fact carries an EV-NNN id + source URL + collection timestamp
- No evidence → section suppressed ("[NO EVIDENCE - SECTION SUPPRESSED]")
- Degraded/offline runs say so (collection_mode)

*Scroll to the register in the generated report.html.*

## Slide 9 — Audit trail

- Append-only JSONL: one record per assessment
- sha256 hash chain (prev_hash/record_hash) — tamper-evident
- Records: input, pinned version, tarball sha256, R/riskmetric/config
  versions + config sha256, decision, fired rules, timestamp

*Mention verify_chain() — one line of Python to audit the log's integrity.*

## Slide 10 — Ops in one slide

- `python -m gateway.server` → UI on 127.0.0.1:8788, `/health` for monitoring
- Container artifacts exist (Phase 4); build verification on a Docker host
  per `docs/container_verification.md`
- Yearly re-screening hook; regression suite guards upgrades
  (`tests/regression/run_regression.py`)

## Slide 11 — What Tier 1 is NOT

- Not proof of correctness — metrics inform a qualified human
- Not code execution: the package's tests/checks are never run in v1
  (covr/R-CMD-check metrics disabled by policy)
- Not a signature: classification/sign-off stay PENDING HUMAN REVIEW
- Not Tier 2: no validated-environment statement, no coverage annex

## Slide 12 — The Tier-2 trigger

- NO-GO at your tier, or any gxp-critical intended use → escalate
- Gateway report + audit record = the escalation evidence package
- Vendor qualification then happens on the pinned artifact

## Slide 13 — Close

- Intake in minutes, decision you can defend line by line
- SOP: `docs/intake_sop_usage.md`
- Q&A

*End with the honesty rule: the tool never signs; humans do.*
