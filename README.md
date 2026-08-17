# pks-agent-pulse

Kanariefugl Pulse runs small, repeated active measurements for owners and makes the resulting evidence available to humans and Agentics assembly lines. The first component is `web`: availability, HTTP failures, TTFB, cache behaviour, scan coverage and imported SEO scan batches.

Museliving is an owner with a `website` measurement. It is configuration, not a product fork.

## Why

The first Museliving weekly scan appeared to improve four SEO counts, but nine of 62 pages had returned `504`. The missing pages had simply disappeared from the counts. Pulse retains both the operational signal and batch coverage, so a report cannot call incomplete data an improvement.

## Run locally

```bash
go test ./...
go run . serve --data ./data
```

Configure the service with:

| Variable | Purpose |
| --- | --- |
| `PULSE_ADMIN_TOKEN` | Admin API bearer token. Required for configuration, manual runs and batch ingestion. |
| `PULSE_OWNERS` | Comma-separated owners whose enabled measurements the scheduler starts. |
| `PULSE_WORKLOAD_ISSUER` | Agentics issuer, normally `https://agentics.dk`. |
| `PULSE_WORKLOAD_JWKS_URL` | Agentics workload JWKS endpoint. |
| `PULSE_AUDIENCE` | Exact public Pulse URL expected in workload tokens. |
| `USER_DATA_DIR` | Folder-backed state, default `/data`. |

Then configure a measurement and its assembly-line trust:

```bash
export PULSE_URL=http://localhost:8090 PULSE_ADMIN_TOKEN=dev-secret
pulse measurement put --owner museliving --id website --file examples/museliving/measurement.json
pulse trust put --owner museliving --file examples/museliving/trust.example.json
pulse run --owner museliving --measurement website
```

## Federated assembly-line access

An assembly-line runner already possesses `AGENTICS_TOKEN` and `AGENTICS_JOB_ID`. `pulse report` sends those to Agentics, which verifies that the runner owns an active job and mints a five-minute EdDSA JWT containing owner, project, assembly line, station, task, job and run. Pulse validates Agentics' JWKS and a per-owner trust binding. No long-lived Pulse secret enters the station container.

```bash
pulse report --owner museliving --measurement website --days 7
```

The `claude-plugin/skills/pulse-report` skill teaches a reporting station to treat coverage warnings as correctness gates.

## Storage

State is ordinary files under `USER_DATA_DIR`: measurement and trust JSON, daily append-only observation JSONL and source batch JSON. Mount the directory as persistent storage and back it up like any other folder.

## Scope boundaries

Pulse is active, periodic measurement infrastructure. It is not logs, traces, application instrumentation or infrastructure APM. `pks-agent-ops` owns those signals; `pks-agent-domain` owns DNS, mail and TLS posture.

