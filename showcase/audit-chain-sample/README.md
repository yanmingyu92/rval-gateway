# Audit chain samples

The gateway keeps an append-only, hash-chained audit log
(`data/audit/assessments.jsonl`): every record carries the sha256 of the
previous record, so any retroactive edit breaks verification
(`gateway.audit.AuditLog.verify_chain()`).

These are the complete chains of the isolated showcase runs — synthetic
identities only (`qa.reviewer`, dev-mode marker), no production data:

- [`tier1.audit.jsonl`](tier1.audit.jsonl) — five Tier-1 assessments
  (see [`../tier1-reports/`](../tier1-reports/)); every record embeds the
  decision-config version + sha256 and the evidence bundle hash.
- [`tier2.audit.jsonl`](tier2.audit.jsonl) — the Tier-2 sequence (see
  [`../tier2/`](../tier2/)): Tier-1 assessments → sandboxed executions →
  synthetic e-signature approving each validation spec (21 CFR Part 11-style
  record: signer, role, meaning, re-authentication method, timestamp) →
  spec-driven validation verdicts, each binding the exact spec sha256 it
  was executed against.

To verify a chain in your own deployment:

```
python3 -c "from gateway.audit import AuditLog; print(AuditLog(data_dir='data').verify_chain())"
```
