# Private search API and ordered event stream

The first managed search slice accepts a consented private search, persists its
exact request and target set, exposes polling, and replays ordered partial
results through Server-Sent Events (SSE). It deliberately does not execute a
probe. Signed-rule worker execution, job claims, retries, and observation
ingestion remain closed for their ordered roadmap slices.

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
4. insert sequence 1, a validated `started` event;
5. reconstruct and validate the public `SearchResource`;
6. commit.

A new request returns HTTP 201 and `Location:
/v1/searches/{search_id}`. A concurrent or later replay with the same key and
exact validated request returns HTTP 200 and the original resource. Reusing the
key with any different request field returns nonretryable
`idempotency_conflict` (HTTP 409). `ON CONFLICT` makes concurrent first use
converge without an aborted transaction or duplicate target/event rows.

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
event. Product-data erasure remains the separate lineage-aware deletion
workflow.

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

The API inserts only `started` and cancellation `finished` events. Later
workers must validate the protocol object before atomically appending result
and terminal events with their target/search state changes.

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

## Runtime database privileges

In addition to the authenticated-workspace grants, the API role needs:

```sql
GRANT SELECT ON sites, consent_grants, searches, search_targets, search_events
    TO socialname_app;
GRANT INSERT ON searches, search_targets, search_events
    TO socialname_app;
GRANT UPDATE (state, updated_at, completed_at) ON searches
    TO socialname_app;
GRANT UPDATE (state, completed_at) ON search_targets
    TO socialname_app;
```

It receives no update permission for the idempotency digest, request policy,
requested/normalized username, event payload, event sequence, or event
identity, and no delete privilege on these tables.

## Verification and remaining gate

The PostgreSQL 18 integration test resets its disposable fixture database so
back-to-back runs cover replay-safe migrations, 31 product tables, 26
forced-RLS policies, exact and conflicting idempotency replay,
read-only/write scope separation, required consent purpose, unknown sites,
target-free errors, two-tenant isolation, digest-only idempotency storage,
polling, three ordered partial/terminal events, `Last-Event-ID` resumption,
append-only rejection, idempotent cancellation, terminal-event uniqueness,
least-privilege columns, and bounded SSE connection recovery.

The remaining next gate is the signed-rule-only worker with managed-probe
SSRF/DNS-rebinding defenses. Until that passes, a newly accepted search remains
accepted unless explicitly cancelled or test/operator evidence is appended; no
network request is initiated by this API slice.
