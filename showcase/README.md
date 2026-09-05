# Showcase — precomputed evidence exhibit

This directory is a **static, precomputed exhibit** of the gateway's output:
real reports and audit records, regenerated in an isolated environment with
synthetic identities. There is deliberately no executable entry point —
clone the repo and run Tier-1 yourself (see the main
[README](../README.md#quickstart--container)); Tier-2 is commercial (see
[Commercial Tier-2](../README.md#commercial-tier-2)).

| Directory | What it shows |
|---|---|
| [`tier1-reports/`](tier1-reports/) | Five full Tier-1 screening reports (HTML + PDF) across all three intended-use tiers, including a `gxp-critical` NO-GO |
| [`tier2/`](tier2/) | Tier-2 spec-driven deep-validation products: IQ/OQ/PQ reports, traceability matrices, mutation scores — the engine itself is not in this repo |
| [`audit-chain-sample/`](audit-chain-sample/) | The complete hash-chained audit logs of the runs behind both exhibits |

**Provenance:** all artifacts were produced by the code in this repository
(Tier-1) and by the commercial Tier-2 engine (exhibited via products only),
running against public CRAN packages with live public sources, in one-off
environments with synthetic actors (`qa.reviewer`). No production data,
credentials, or internal systems were involved.
