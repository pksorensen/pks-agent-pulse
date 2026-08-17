# PRD: Pulse v1

## Problem

Periodic reports often compare counts without proving that both measurements covered the same population. On 2026-08-16 Museliving returned nine `504` responses; four SEO issue counts looked lower only because those pages vanished from the scan. Cache misses simultaneously rose and median TTFB moved from 107 ms to 2143 ms.

## Outcomes

1. A report station obtains Pulse data without a stored Pulse credential.
2. An owner can trust an exact Agentics project, assembly line and optionally station for exact measurements and scopes.
3. The weekly report always names its period and sample count and blocks improvement claims when coverage falls.
4. Museliving has a repeatable `website` measurement covering representative page types plus imported whole-site SEO batches.

## API

- `PUT /v1/admin/owners/{owner}/measurements/{id}`
- `PUT /v1/admin/owners/{owner}/trust`
- `POST /v1/admin/owners/{owner}/measurements/{id}/run`
- `POST /v1/admin/owners/{owner}/measurements/{id}/batches`
- `GET /v1/owners/{owner}/measurements`
- `GET /v1/owners/{owner}/measurements/{id}/report`

Management uses a service admin token. Reads use Agentics workload identity and owner trust bindings.

## Security

- Token issuer and Ed25519 signature are verified against Agentics JWKS.
- Audience must equal the deployed Pulse origin.
- Tokens expire after five minutes and carry only requested allowlisted scopes.
- Agentics mints only for a runner that owns a `claimed` or `in_progress` job.
- Pulse binds source owner/project + assembly line/station to destination owner/measurement/scope.
- Measurement URLs allow public HTTP(S) only; runtime DNS resolution rejects private, local, link-local and multicast addresses.

## Acceptance

- Unit tests prove batch artefact warnings, store windows, JWT checks and trust matching.
- Agentics route tests prove active-job ownership, audience allowlisting and station claims.
- A production assembly-line job exchanges its runner identity, fetches `museliving/website`, and cites the result in the weekly report.

