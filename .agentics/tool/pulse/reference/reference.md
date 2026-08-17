---
title: "Pulse reference"
description: "Pulse commands, configuration and workload federation."
tags: [reference, cli, federation]
category: agents
status: beta
type: cli
---

# Pulse reference

```text
pulse serve [--addr :8090] [--data /data]
pulse measurement put --owner OWNER --id ID --file measurement.json
pulse trust put --owner OWNER --file trust.json
pulse run --owner OWNER --measurement ID
pulse ingest seo --owner OWNER --measurement ID --file pages.jsonl --expected N
pulse report --owner OWNER --measurement ID [--days 7]
```

Reporting stations need `PULSE_URL`, `AGENTICS_BASE_URL`, `AGENTICS_OWNER`, `AGENTICS_PROJECT_NAME`, `AGENTICS_JOB_ID` and the runner-provided `AGENTICS_TOKEN`. The CLI handles exchange and never prints the runner token.

