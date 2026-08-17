---
name: pulse-report
description: Fetch and interpret owner-scoped Pulse web measurement reports from an Agentics assembly-line station using federated workload credentials. Use when a station needs uptime, HTTP errors, TTFB, cache behavior, scan coverage, performance evidence, or data-quality warnings for a weekly report or operational assessment.
---

# Pulse report

Use the `pulse` CLI. It exchanges the current Agentics runner job identity for a short-lived Pulse token; never read, print, copy, or manually forward `AGENTICS_TOKEN`.

## Fetch the report

1. Read `.agentics/pulse.json` when it exists. It contains the owner, measurement, and default period selected by the assembly-line owner.
2. Otherwise use explicit values from the task or prompt. Do not guess an owner or measurement ID.
3. Run:

```bash
pulse report --owner <owner> --measurement <measurement> --days <days>
```

4. Treat `dataQuality` and `latestBatch.coveragePct` as correctness gates:
   - Do not claim improvement from lower issue counts when batch coverage fell.
   - Name 5xx responses, timeouts, cache changes, and TTFB regressions separately from SEO/content changes.
   - State when the baseline or sample count is insufficient.
5. Cite the measurement period and sample count in the resulting report.

Read [references/report-contract.md](references/report-contract.md) when mapping fields into a report or diagnosing authorization failures.

## Boundaries

- Pulse evidence describes externally observed behavior; it does not identify who deployed or cleared a cache.
- A Lighthouse score is a lab signal, not field Core Web Vitals.
- Never mutate measurement or trust configuration from an ordinary reporting station.
