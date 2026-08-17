# Pulse report contract

## Station configuration

`.agentics/pulse.json`:

```json
{
  "owner": "museliving",
  "measurement": "website",
  "days": 7
}
```

## Important report fields

- `from`, `to`, `samples`: measurement period and evidence volume.
- `availabilityPct`, `serverErrors`, `timeouts`, `statusCounts`: availability.
- `ttfbMedianMs`, `ttfbP90Ms`, `slowest`: server response performance.
- `cacheHits`, `cacheMisses`, `cacheUnknown`: observed cache behavior.
- `affectedUrls`: URLs with transport errors or 5xx responses.
- `latestBatch.expectedCount`, `observedCount`, `coveragePct`: latest imported scan completeness.
- `dataQuality`: warnings that constrain conclusions.
- `executiveSummary`: deterministic summary; verify it against the structured fields before quoting it.

## Federated authorization

The CLI requires `PULSE_URL`, `AGENTICS_BASE_URL`, `AGENTICS_TOKEN`, `AGENTICS_JOB_ID`, `AGENTICS_OWNER`, and `AGENTICS_PROJECT_NAME`. The runner supplies the Agentics variables. The CLI requests only `pulse:reports:read` for the current job.

Pulse validates the Agentics signature, audience, expiry, source owner/project, assembly-line ID, station ID, measurement ID, and requested scope against the target Pulse owner's trust bindings.

Authorization errors are configuration failures. Report the source assembly line, station, target owner, and measurement to the operator; never work around them with a static token.
