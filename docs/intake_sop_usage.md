# Intake SOP — Using the R Package Validation Gateway

**Scope:** Tier-1 screening of third-party R packages requested for use.
**Roles (generic):** *Requester* (needs the package), *Reviewer* (qualified
person per the QC framework — owns classification and sign-off),
*Tool Operator* (runs/maintains the gateway; may be the Reviewer).

## Intake flow

1. **Request.** The Requester states: package name (CRAN) or GitHub URL or a
   source tarball, the exact version if pinning matters, and the **intended-use
   tier**:
   - `exploratory` — research/non-GxP use; output does not feed decisions.
   - `gxp-support` — package output feeds GxP workflows but is not itself the
     record of truth.
   - `gxp-critical` — package is on the critical path of a regulated decision.
2. **Assess.** Run the gateway:
   ```
   python run.py --pkg <name> --version <ver> --tier <tier>
   # or the web UI: python -m gateway.server  →  http://127.0.0.1:8788
   ```
   The gateway resolves and pins the exact tarball (sha256), scores it with
   {riskmetric} (code-executing metrics disabled — the package's code is never
   run), collects deterministic evidence, applies the versioned decision
   rules, and writes the report + audit record.
3. **Read the decision.** GO / GO-WITH-CONDITIONS / NO-GO is shown with every
   rule evaluated and its inputs. There is no black box: if you cannot see
   why, escalate to the Tool Operator rather than trusting the banner.
4. **File the report.** Save `report.html`/`report.pdf` from the run
   directory into the intake record. The audit trail entry (append-only,
   hash-chained) is the system of record; the report is its human-readable
   rendering.

## Decision handling

- **GO** (exploratory/gxp-support only): use permitted at the stated tier.
  The pinned version is the assessed version — upgrades re-enter intake.
- **GO-WITH-CONDITIONS**: use permitted at the stated tier **after** each
  listed condition is satisfied and noted in the intake record (e.g. "pin
  version and re-check on update"). Conditions are mandatory, not advisory.
- **gxp-critical outcomes**: the gateway never auto-GOs at this tier. Best
  case is GO-WITH-CONDITIONS, and the mandatory human-gate conditions apply:
  independent verification by a qualified reviewer, and double programming or
  an equivalent independent check of package outputs that feed the regulated
  decision.
- **NO-GO** (any tier) or **any gxp-critical intended use** → **Tier 2
  trigger**: escalate to full vendor-style qualification (purchase/trigger
  per the two-tier strategy). The gateway report + audit record are the
  escalation evidence package.

## Periodic re-screening

- **Yearly hook:** re-run every approved package through the gateway on the
  annual quality calendar (same pinned version; score drift is itself a
  signal). Also re-run on any version upgrade request and on material changes
  to the decision config (threshold/policy changes - review `config/decision_rules.yml`
  and its versioned sha256 pinning in every audit record).

## Honesty rules (non-negotiable)

- The tool **never signs**. Classification and sign-off slots render
  `PENDING HUMAN REVIEW`; the Reviewer signs in the intake record.
- Every statement in the report carries an evidence ID; sections without
  evidence are suppressed, never drafted. If a section you need is
  suppressed, that means "we don't know" — treat it as a finding.
- An offline or degraded run says so (`collection_mode`); never present a
  degraded run as a full-evidence run.
