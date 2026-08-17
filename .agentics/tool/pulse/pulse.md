---
title: "Pulse"
description: "Owner-scoped active web measurements and trustworthy report data for Agentics assembly lines."
tags: [monitoring, web, performance, assembly-line]
category: agents
status: beta
type: cli
icon: activity
author: Poul Kjeldager
component: pulse
usage: "pulse <command> [options]"
examples:
  - command: "pulse report --owner museliving --measurement website --days 7"
    description: "Fetch a federated seven-day website report from an Agentics job"
---

# Pulse

Pulse runs periodic outside-in measurements and turns them into report-ready JSON. Measurements belong to an owner, so one service can monitor Museliving and other owners without product forks.

The reporting command uses the current Agentics runner job identity to mint a five-minute workload token. It does not require a static Pulse secret in the station.

```bash
curl -fsSL https://agentics.dk/install/pulse.sh | bash
pulse report --owner museliving --measurement website --days 7
```

Important report fields are `availabilityPct`, `timeouts`, `serverErrors`, `ttfbMedianMs`, `ttfbP90Ms`, cache counts, `latestBatch.coveragePct` and `dataQuality`. A coverage warning means lower issue counts may be measurement artefacts.

