# Developer quota, usage, and service reporting

## Purpose and existing boundary

Milestone 4 adds predictable admission and reporting around the implemented
managed-search API. This slice does not change the search request contract:
`SearchCreateRequest` already accepts a bounded Cartesian batch of up to 100
usernames, 64 sites, and 512 target pairs. Search polling, ordered SSE, exact
idempotent creation, consent, coalescing, and signed-worker execution remain
the boundaries documented in [Private search API](search-api.md) and
[Managed probe jobs](managed-jobs.md).

The new boundary supplies:

- transactionally enforced tenant and API-key daily target-pair quotas;
- one target-free append-only usage record per newly admitted search;
- a scoped Developer report containing current quota, aggregate usage,
  unfinished backlog, and fixed search-service objectives;
- bounded physical expiry for usage records.

It does not create a hosted service, product plan, price, bill, entitlement,
production SLA, or production capacity claim.

## Quota model

The quota meter is `search_target_admitted`. Its quantity is the validated
Cartesian `usernames × site_ids` target-pair count. Counting target pairs
instead of HTTP requests prevents a maximum-size batch and a one-target search
from consuming the same capacity.

Every workspace has one operator-controlled software policy:

- tenant daily target-pair limit;
- per-API-key daily target-pair limit.

The initial safe defaults are 10,000 target pairs per UTC day for a tenant and
2,000 per API key, with the key limit no greater than the tenant limit.
Operator values are bounded from 1 through 1,000,000. These are deployment
guardrails, not commercial plan entitlements. The implemented entitlement
boundary determines whether a new managed search may reach quota admission but
does not select, replace, or bypass either limit; neither concern enters the
measurement engine.

Database time defines half-open UTC periods `[00:00, next 00:00)`. Search
creation calls a tenant-setting-checked definer function that locks the exact
tenant policy without granting the application table UPDATE, then reads
committed usage for the tenant and authenticated key and either admits the
entire batch or admits none of it. There is no partial search and no
client-time input.

Quota admission occurs only after request, site, consent, and idempotency
validation:

- a new exact request consumes its target-pair quantity once;
- an exact idempotency replay returns the original search and consumes zero
  additional units;
- conflicting replay, invalid request, forbidden consent, unknown site, and
  storage failure consume zero units;
- exceeding either boundary rolls back search, targets, started event, and
  usage together.

Quota exhaustion returns HTTP 429 `quota_exceeded` with a positive
`retry_after_ms` calculated from database time to the next UTC period. It is an
admission result, never a target observation, absence verdict, or site
rate-limit measurement.

## Usage records and retention

Each admitted search writes one immutable
`search_target_admitted` record in the same transaction as its search, targets,
and `started` event. It contains only tenant, authenticated API-key and search
relations, the integer target-pair quantity, database occurrence time, and a
fixed 400-day retention deadline. It has no username, site, region, consent
identifier, idempotency digest, source URL, result, destination, or body.

The public API never lists individual records. Reports aggregate them under
forced tenant RLS. Product reads ignore records at or after their database
deadline. A separate worker-only bounded retention function deletes at most
1–1,000 due rows per invocation with `FOR UPDATE SKIP LOCKED`; its operable
command emits only the deleted count. Production scheduling and retained run
history remain external evidence.

Target/contributor deletion already hides and redacts the related search.
Because usage contains no selector or result and is exposed only as an
aggregate, deleting a target does not rewrite historical target-pair capacity
consumption. The search relation remains internal and inaccessible through the
report. Tenant deletion remains the controller-wide removal boundary.

## Developer report

```http
GET /v1/developer/report?window=24h
Authorization: Bearer snk_v1_<prefix>_<secret>
```

The independent `usage:read` scope grants only this target-free aggregate.
Closed windows are `24h`, `7d`, and `30d`; unknown or duplicate query fields
are rejected. One PostgreSQL statement uses one database snapshot and
evaluation time for:

- the current UTC quota period, tenant/key limits, used units, remaining
  units, and reset time;
- searches and target pairs admitted inside the selected report window;
- current accepted/running search counts, active searches with no result, and
  oldest active-search age;
- completed-versus-failed terminal search success;
- accepted-to-first-result discrete p95 latency;
- accepted-to-completed-or-failed discrete p95 latency.

Cancelled searches remain visible in usage but are excluded from success and
latency objectives because cancellation is caller intent. Accepted/running
searches remain explicit backlog and never enter a terminal-success
denominator. First-result samples include definitive, uncertain, and
operational result events because all three are meaningful partial progress;
`started`, assertion updates, and `finished` are not first results.

Fixed software objectives are:

| Objective | Target |
| --- | --- |
| terminal search success | at least 99.0% completed among completed/failed |
| accepted-to-first-result p95 | at most 30 seconds |
| accepted-to-terminal p95 | at most 5 minutes |

Each objective is exactly `no_data`, `meeting`, or `breached`. `no_data` is
never serialized as 100% success. The report is a current repository-derived
software view, not historical uptime telemetry, contractual SLA evidence, or
proof that discovery-only sites are runnable.

## Operator boundary

Quota changes use the schema-owner database URL and an active
owner/administrator identity:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://SCHEMA_OWNER:...@HOST/DATABASE"
$env:SOCIALNAME_WORKSPACE_ID = "<workspace UUID>"
$env:SOCIALNAME_MEMBERSHIP_ID = "<operator membership UUID>"
$env:SOCIALNAME_DAILY_TARGET_LIMIT = "10000"
$env:SOCIALNAME_API_KEY_DAILY_TARGET_LIMIT = "2000"
cargo run --locked -p socialname-server -- set-developer-quota
```

The transaction updates one policy and writes a bounded audit event only when
the values change. Output contains workspace ID and numeric limits, never a
target, API key, credential, consent, or database URL.

Usage expiry is a non-network worker unit:

```console
socialname-worker enforce-usage-retention --batch-limit 128 --allow-live
```

`--allow-live` acknowledges irreversible database deletion. The worker role
receives execute permission only on the bounded retention function and no
direct update/delete privilege on usage or quota policy rows.

## Verification and remaining work

Deterministic protocol tests reject changed targets, relabelled
objectives, impossible quota arithmetic, timestamp inconsistency, unexpected
fields, and unsafe JSON integers. Server tests keep query parsing and quota
errors closed and target-free.

The real PostgreSQL 18 gate proves:

- default and operator-updated policies;
- tenant and API-key quota enforcement under concurrent serialization;
- exact replay without double usage and whole-batch rollback on rejection;
- append-only usage and least-privilege forced-RLS isolation;
- target-free report shape, scope separation, window bounds, and database
  time;
- backlog, success, first-result, and terminal-latency cohort separation;
- deadline hiding and bounded worker-only physical expiry.

Search-completion webhooks are implemented as the adjacent, separately
versioned binding and delivery boundary; see
[Search-completion webhooks](search-completion-webhooks.md).
Plan admission is implemented separately in
[Plan entitlements and billing boundary](plan-entitlements-billing.md).
Payment-provider integration, hosted origin, endpoint ownership, production
retention scheduling, alert ownership, and elapsed SLA evidence remain
external or later gates.
