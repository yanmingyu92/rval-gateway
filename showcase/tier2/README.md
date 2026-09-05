# Tier-2 deep validation — product exhibit (no executable entry)

Tier-2 is the commercial layer of the gateway: **spec-driven, sandboxed deep
validation** of packages that Tier-1 flags for escalation. This directory is
an online museum, not an online service — for cost, abuse-resistance, and
GxP-propriety reasons there is deliberately nothing here to run. What you
see are **real product artifacts**; what you cannot see is the Tier-2 engine
itself, which is not part of this repository.

## Provenance

The artifacts below were regenerated end-to-end in an isolated environment
from this exact pipeline: Tier-1 assessment → spec approval under a
synthetic e-signature (`qa.reviewer`, mock re-authentication — never a real
account) → sandboxed execution engines → automated verdicts → report
rendering. The audit hash chain for these runs is in
[`../audit-chain-sample/tier2.audit.jsonl`](../audit-chain-sample/tier2.audit.jsonl).

## Exhibits

| Package | Spec | Requirements | OQ golden cases | Mutation score | Report |
|---|---|---|---|---|---|
| [jsonlite 2.0.0](jsonlite/report.html) | v0.1.2, approved | 4/4 pass | 5/5 pass | 4/20 killed (0.20) | HTML + [PDF](jsonlite/report.pdf) |
| [digest 0.6.39](digest/report.html) | v0.1.0, approved | 2/2 pass | 6/6 pass | 0/10 killed (0.00) | HTML + [PDF](digest/report.pdf) |

Each exhibit directory contains:

- `report.html` / `report.pdf` — the full validation report: IQ/OQ/PQ
  structure, the **requirements-to-test traceability matrix** (REQ × case ×
  verdict × detail), the mutation-testing block, and the honesty note.
- `validation.json` — machine-readable verdicts per requirement, per OQ
  case, and the mutation survivor list.
- `sandbox-battery.json` — the raw sandboxed engine battery: R CMD check,
  testthat counts, per-file coverage percentages.

## What the numbers mean

- **Traceability matrix** — every requirement in the approved validation
  spec is bound to executable cases whose verdicts are recorded verbatim;
  nothing in the report exists without a case behind it.
- **Mutation scores quantify the test suite, not the package.** `digest`
  scoring 0/10 means its own test suite failed to kill any injected defect:
  the spec's golden masters — not the package's tests — are what carried the
  validation. `jsonlite`'s 4/20 shows a stronger suite with substantial
  survival remaining. Both scores are upper-biased estimates (finite
  operator set), as the report's honesty note states.
- **A real finding from this framework (production pilot, jsonlite):** the
  OQ golden-master engine caught `jsonlite::toJSON()` silently truncating
  double precision at the default `digits = 4` — a numeric-integrity defect
  invisible to "package loads and examples run" checking, and exactly the
  class of risk Tier-2 exists to surface for clinical data paths.
- **Human review stays mandatory.** Automated verdicts are decision-support
  evidence; the specification workflow (draft → machine capture of golden
  values → human e-signed approval → execution → human adjudication of
  diffs) keeps qualified people at every gate.

## Daily canary self-qualification

In production deployments the framework re-qualifies **itself** daily: four
deliberately-injected defects must be caught by exactly the intended cases,
and a clean package must produce zero false positives, before the day's
runs are trusted. The canary run writes a `framework_qualification` record
into the same audit chain as every assessment — the validator is subject to
its own standard. (This once caught a comparison bug in the engine itself:
an NA-handling defect in the golden-diff comparator, found by the canary
before any package validation was affected.)
