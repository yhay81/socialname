# Private search API and ordered event stream

The managed search boundary accepts a consented private or shared search,
persists its exact request and target set, exposes polling, and replays ordered
partial results through Server-Sent Events (SSE). Eligible searches can now be
expanded into fenced PostgreSQL jobs and completed by the signed-rule worker.
Discovery-only or region-unhealthy rules remain safely unexecutable.

## HTTP surface and scopes

```http
POST   /v1/searches
GET    /v1/searches/{search_id}
GET    /v1/searches/{search_id}/events
DELETE /v1/searches/{search_id}
```

`POST` and `DELETE` require `search:write`. Polling and SSE require
`search:read`. Every operation authenticates first and then rechecks the active
key, exact scope, expiry, active tenant, and tenant ID inside its own
transaction-local forced-RLS transaction. A valid search UUID from another
tenant is indistinguishable from a missing search.

## Managed request and consent boundary

The shared `SearchCreateRequest` also serves local clients, but the managed
endpoint is narrower:

- mode must be `remote` or `hybrid`;
- `sync=never` is rejected because sending a target to this endpoint already
  moves it off the device;
- `sync=private` requires an active `private_history` consent grant;
- `sync=shared` requires an active `shared_observation` consent grant;
- the grant must be an account grant for the membership that created the
  authenticated API key;
- withdrawn, expired, future-dated, wrong-purpose, cross-tenant, and
  wrong-subject grants are uniformly `forbidden`;
- every requested site must exist in the site registry.

Authentication or a broad API-key scope never substitutes for purpose-specific
consent. Accepting a discovery-only site records requested work but does not
authorize a probe; the later worker must still require a signed, region-accepted
rule and return an operational failure when execution is unavailable.

The request contains only protocol-bounded usernames, sites, mode, sync policy,
grant ID, maximum age, and coarse region classes. No target, grant ID, or
idempotency key enters URI/query fields, request tracing, or fixed error text.

## Idempotent creation

`POST` requires exactly one `Idempotency-Key` header containing 1–128 ASCII
letters, digits, hyphens, or underscores. The server stores only its SHA-256
digest under the tenant-scoped unique constraint.

Creation is one PostgreSQL transaction:

1. recheck `search:write`, tenant, sites, and consent;
2. insert the search using `ON CONFLICT (tenant_id, idempotency_key_hash) DO
   NOTHING`;
3. insert the Cartesian target set with stable zero-based ordinals;
4. for a new search, lock its tenant quota policy, admit the whole target-pair
   quantity, and append one target-free usage record;
5. insert sequence 1, a validated `started` event;
6. reconstruct and validate the public `SearchResource`;
7. commit.

A new request returns HTTP 201 and `Location:
/v1/searches/{search_id}`. A concurrent or later replay with the same key and
exact validated request returns HTTP 200 and the original resource. Reusing the
key with any different request field returns nonretryable
`idempotency_conflict` (HTTP 409). `ON CONFLICT` makes concurrent first use
converge without an aborted transaction or duplicate target/event rows.
An exact replay never re-enters quota admission. Exceeding either the tenant or
API-key UTC-day target-pair limit returns HTTP 429 `quota_exceeded` with a
database-time `retry_after_ms`, while rolling back the search, targets, usage,
and event together. See
[Developer quota, usage, and service reporting](developer-usage-reporting.md).

`search_targets.requested_username` preserves the exact validated request.
`normalized_username` is nullable and remains unset until a later signed-rule
worker applies that site's explicit identity policy. The API process has no
permission to update it.

## Polling and cancellation

`GET /v1/searches/{search_id}` reconstructs the original request and derives
progress from target-bound result events:

- `definitive_result`;
- `uncertain_result`;
- `operational_failure`.

The protocol validator requires `total_targets` to equal the Cartesian request
size and requires completed searches to account for every target. Corrupt or
inconsistent persistence becomes retryable `unavailable`, never a fabricated
account verdict.

`DELETE` is cancellation, not data deletion. It locks the search row, changes
an `accepted` or `running` search to `cancelled`, cancels incomplete targets,
and appends one `finished/cancelled` event in the same transaction. Repeating
the operation returns the same terminal resource without another terminal
event. Product-data erasure uses the separate implemented lineage-aware
workflow in [Lineage-backed deletion workflows](deletion-workflows.md).

## Private history and export

`GET /v1/searches` requires `search:read` and returns a tenant-local,
creation-ordered page of complete search resources. `GET
/v1/searches/{search_id}/export` independently requires `data:export` and
returns the immutable ordered event history of a terminal search in bounded
pages. Active export is a conflict, and any lineage-hidden target or event
hides the whole search from both surfaces rather than returning a partial
history. See
[Private search history and export](private-search-history-export.md).

## Append-only event storage

Migration `0003_search_event_stream.sql` adds tenant-RLS table
`search_events`. PostgreSQL enforces:

- a positive sequence unique within one tenant/search;
- one globally unique event UUID;
- at most one `started` and one `finished` event per search (creation writes the
  former atomically, and public terminal reads require the latter);
- at most one result event for each search target;
- target IDs from the same tenant and search;
- a closed event type;
- a maximum 128 KiB JSON payload;
- equality between relational event/search IDs, sequence, type, and the
  serialized `SearchEvent`;
- an update-rejecting append-only trigger.

The API inserts `started` and cancellation `finished` events. `JobStore`
validates every worker-created protocol object and atomically appends result
and terminal events with observation, job, target, search, and lineage changes.

## SSE wire and resumption

Every persisted protocol event is emitted as:

```text
id: <event UUID>
event: search_event
retry: 1000
data: <one complete SearchEvent JSON object>
```

Events are queried by relational sequence and emitted strictly in ascending
order. The `id` field becomes the client's last event ID; the HTML living
standard defines `Last-Event-ID` as the reconnect header for that state
([WHATWG Server-Sent Events](https://html.spec.whatwg.org/multipage/server-sent-events.html)).
Axum's SSE event API maps the same `id`, named event, retry hint, and keep-alive
concepts ([Axum SSE](https://docs.rs/axum/0.8.9/axum/response/sse/)).
The generated machine-readable form is
[`contracts/api/v1/sse.json`](../contracts/api/v1/sse.json), linked from the
published OpenAPI operation.

The endpoint accepts zero or one strict UUID `Last-Event-ID`. It resolves that
ID only inside the requested tenant/search and emits events after its sequence.
Malformed, duplicate, foreign, or unknown cursors never cause a broader replay.
Clients should persist the last fully processed event ID; replay is
at-least-once across a disconnect and consumers deduplicate by event UUID.

Each query reads at most 128 events. An SSE response lasts at most 30 seconds,
polls PostgreSQL every 250 milliseconds when idle, and sends a comment
keep-alive every 10 seconds. Ending the response is a normal reconnect point.
The number of open SSE bodies is bounded by the configured maximum in-flight
count; excess connections receive retryable HTTP 503 before streaming begins.
Each poll rechecks key state and `search:read`, so revocation takes effect on an
existing stream.

If storage or authorization fails after HTTP 200 has started, the stream emits
one unpersisted named `stream_error` containing the closed
`ApiErrorResponse`, without an SSE ID, and ends. It is not a target result and
cannot deserialize as `not_found`. A client may consult readiness, renew
credentials when appropriate, and resume from its last persisted event ID.

## Completion webhooks

Clients may bind one existing active webhook endpoint through
`POST /v1/searches/{search_id}/completion-webhook`, inspect it with `GET`, and
cancel it with `DELETE`. This leaves `SearchCreateRequest` stable and keeps
destination provisioning outside the search body. Completed and failed
searches enqueue one target-free signed wake-up signal; cancelled searches do
not. Registration and terminal updates converge in either commit order. See
[Search-completion webhooks](search-completion-webhooks.md) for payload,
retry, cancellation, and external ownership gates.

## Runtime database privileges

In addition to the authenticated-workspace grants, the API role needs:

```sql
GRANT SELECT ON
    sites, consent_grants, searches, search_targets, search_events,
    developer_quota_policies, developer_usage_records,
    notification_endpoints, notification_deliveries,
    search_completion_webhooks
    TO socialname_app;
GRANT INSERT ON
    searches, search_targets, search_events, developer_usage_records,
    search_completion_webhooks
    TO socialname_app;
GRANT UPDATE (state, updated_at, completed_at) ON searches
    TO socialname_app;
GRANT UPDATE (state, completed_at) ON search_targets
    TO socialname_app;
GRANT UPDATE (state, cancelled_at) ON search_completion_webhooks
    TO socialname_app;
GRANT UPDATE (
    state, next_attempt_at, delivered_at, last_error_code,
    lease_owner, lease_started_at, lease_expires_at
) ON notification_deliveries TO socialname_app;
GRANT EXECUTE ON FUNCTION socialname_lock_developer_quota(uuid)
    TO socialname_app;
```

It receives no update permission for the idempotency digest, request policy,
requested/normalized username, event payload, event sequence, or event
identity. It receives no Developer policy UPDATE, usage UPDATE/DELETE, or
retention-function permission.

## Verification and remaining gate

The PostgreSQL 18 integration test resets its disposable fixture database so
back-to-back runs cover replay-safe migrations, 52 product tables, 40
forced-RLS policies, exact and conflicting idempotency replay,
read-only/write scope separation, required consent purpose, unknown sites,
target-free errors, two-tenant isolation, digest-only idempotency storage,
polling, three ordered partial/terminal events, `Last-Event-ID` resumption,
append-only rejection, idempotent cancellation, terminal-event uniqueness,
least-privilege columns, bounded SSE connection recovery, job coalescing,
claim/reclaim fencing, retry exhaustion, observation/event idempotency,
multi-search and watch fan-out, watch freshness reuse and byte reservation,
global/regional assertion support and lineage, regional event projection,
invalid-target handling, and cancellation, consent-withdrawal, and rule-health
races. It additionally proves stable history pagination, independent export
scope, terminal-only Event ID export traversal, cross-tenant hiding, and
deletion-tombstone exclusion. It also proves exact replay is charged once,
concurrent same-tenant admission is serialized, quota rejection is whole-batch
and target-free, and rejected work leaves no search row. Search-completion
coverage also proves exact/conflicting registration replay, read/write scope
separation,
two-tenant hiding, both terminal/registration commit orders, one logical
delivery under repeated updates, cancellation and endpoint-disable behavior,
target-free signed worker output, and search-to-delivery lineage.

The API process still initiates no network request and cannot normalize a
target. A separate signed worker performs those operations only for an exact
promoted, active, fresh healthy rule/pack/region binding. Search and watch
consumers now coalesce only across the same consent/visibility work scope and
receive the transactionally recomputed current assertion. External live
acceptance remains required before representative discovery rules can execute.
See [Managed probe jobs and observation ingestion](managed-jobs.md) and
[Assertion recomputation and transition persistence](assertion-recomputation.md).
