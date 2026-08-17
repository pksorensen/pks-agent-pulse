# Product brief: pks-agent-pulse

## Promise

Keep a trustworthy pulse on things an owner cares about, and make the evidence safe for automated reports to consume.

## First user and job

Museliving needs a weekly SEO report that can distinguish real content changes from failed or incomplete scans. Pulse must continuously observe representative web pages and accept the full SEO scan as a measured batch.

## V1

- Owner-scoped measurements; Museliving is an owner, not custom code.
- Web probes for HTTP status, timeout, TTFB, total time, bytes and cache headers.
- Imported SEO batches with expected count and coverage.
- Seven-day report JSON with availability, 5xx, timeouts, median/p90 TTFB, cache hit/miss, affected URLs and data-quality warnings.
- CLI and `pulse-report` skill for assembly-line stations.
- Five-minute Agentics federated workload tokens, bound to an active job and trusted assembly line/station.
- Folder-backed persistence, OCI image and multi-platform CLI release.

## Not V1

Browser-rendered Lighthouse/Core Web Vitals, alert delivery, dashboards, logs/traces/APM, automatic remediation or arbitrary private-network probing.

