# Public protocol v1

`socialname-protocol` owns the wire contract shared by the future server,
managed worker boundary, API clients, and generated interface descriptions. It
does not perform probes, derive assertions, persist data, authenticate callers,
or authorize network destinations. Those responsibilities remain in the
domain, engine, server, and worker layers.

## Version and compatibility

Every top-level JSON document carries:

```json
{"schema":"socialname.dev/api/v1"}
```

The REST route version and this schema marker evolve independently from Site
Rule v1, rule-pack versions, and `assertion/v1`. JSON field names and enum values
use `snake_case`. Request and response structs reject unknown fields. Changing
an existing field, enum, or tagged-union shape therefore requires a new public
API schema version; it is not silently treated as an additive v1 change.

`api_v1_schemas()` exposes Draft 2020-12 JSON Schema roots for:

- search creation, search resources, and ordered search events;
- predictable API errors;
- watch creation, revision-checked patching, watch resources, and bounded
  monitoring pages;
- transitions;
- notification endpoint creation/resources and delivery state;
- purpose-specific consent creation, resources, bounded lists, and
  withdrawals;
- bounded Evidence Capsule resources;
- contributor deletion creation and target-free request resources;
- authenticated private-workspace resources and API-key scope metadata.

Runtime `Validate` checks supplement JSON Schema where a rule relates multiple
fields, such as freshness classification, progress totals, consent, transition
confirmation, or delivery state.

## Identifiers and sensitive values

Opaque resource and event IDs accept 1-128 ASCII letters, digits, hyphens, or
underscores. Site IDs, coarse region classes, SHA-256 rule/evidence digests,
HTTPS URLs, email destinations, and usernames use their own bounded types and
validate during deserialization. `IdempotencyKey` is the strict redacted value
accepted by the implemented `POST /v1/searches` header boundary; it is not a
body or resource field.

Usernames, profile/webhook URLs, email addresses, and installation IDs serialize
for their named API purpose but use redacted `Debug` implementations.
Idempotency keys are also redacted. Validation and API errors report a field
plus a closed code without echoing the rejected value. The protocol contains no
complete HTTP body, cookie,
credential, response excerpt, network-group identifier, or unrelated profile
data.

The protocol intentionally contains no API-key bearer token or secret digest.
Workspace resources expose only the authenticated key's opaque ID, public
prefix, closed scopes, state, and optional expiry.

HTTPS parsing proves only bounded syntax, a host, and the absence of embedded
credentials. It does not authorize a webhook or profile destination. The server
must separately enforce destination policy and perform DNS/redirect protections
before any outbound request.

## Search request and source policy

`SearchCreateRequest` contains:

- a nonempty, deduplicated username/site selection;
- `local`, `cache`, `remote`, or `hybrid` requested mode;
- independent `never`, `private`, or `shared` synchronization policy;
- a bounded maximum age and one to eight coarse region classes;
- a purpose-specific consent-grant ID for `private` or `shared` sync.

Selections permit at most 100 usernames, 64 sites, and 512 username/site pairs.
`sync=never` rejects a consent grant instead of implying synchronization;
`private` and `shared` require one. The authenticated server must still verify
that the referenced grant belongs to the caller, is active, and has the exact
requested purpose. Authentication, payment, or `hybrid` never substitutes for
that check.

Actual result source is distinct from requested mode:

- `local_cache`
- `local_probe`
- `private_cloud`
- `shared_assertion`
- `managed_probe`

`Freshness` records observed, expiry, evaluation, and maximum-age timestamps.
Its `current`, `stale`, or `expired` state is derived from those values and
validation rejects relabelling.

## Authenticated workspace

`WorkspaceResource` is the response contract for `GET /v1/workspace`. It
contains the workspace's opaque ID, bounded slug/display name, state, and one
`AuthenticatedApiKeyResource`. API-key scopes are a closed enum covering
workspace, search, watch, and consent read/write plus the planned notification,
export, and deletion capabilities. The resource rejects empty or duplicate
scope sets and invalid public prefixes.

This DTO represents an already authenticated principal; it does not parse a
bearer token or grant access. The server separately verifies the token digest,
active/nonexpired key state, active key-creating membership, exact route
scope, active tenant, and transaction-local tenant RLS. A scope whose route has
not been implemented does not create that capability.

## Consent grants

`ConsentGrantCreateRequest` binds one account or installation subject to one of
`private_history`, `shared_observation`, or `shared_research`, plus the closed
`profile-v1` and `notice-v1` contract. An installation ID is present only for
an installation subject and is redacted from `Debug`. Resources expose the
server-derived source and active, expired, or withdrawn state with explicit
timestamps.

`ConsentGrantListPage` contains at most 50 grants and binds a next cursor to
the final returned ID. `ConsentWithdrawalRequest` is a versioned request, not a
delete claim. Server ownership, digest persistence, replay, withdrawal
locking, and error behavior are specified in
[Purpose-specific consent grant lifecycle](consent-api.md).

## Deletion requests

`ContributorDeletionCreateRequest` contains only the API schema and an owned
consent-grant ID. It carries no username, installation identifier, or
free-form selector. `DeletionRequestResource` exposes a closed contributor or
target scope, monotonic state, the exact hide/support/primary/rebuild/backup
deadlines, bounded matched/hidden counts, and ordered optional completion
times.

Validation rejects deadline reversal, impossible state/progress combinations,
and counts above one million. Unknown fields are rejected so a selector cannot
accidentally enter a receipt. `DeletionReceiptResource` contains exactly one
primary, derived, and backup entry, relates completion times to state, and
derives remaining backup time from the evaluation timestamp. HTTP ownership,
HMAC suppression, verified target-person intake, physical deletion, and
external evidence gates are
specified in [Lineage-backed deletion workflows](deletion-workflows.md).

## Ordered search events

`SearchEvent` carries an opaque event ID, search ID, strictly positive sequence,
emission time, and one tagged payload. This supports SSE resumption and
database-backed replay without making transport ordering implicit.

The managed endpoint emits each complete JSON object as a named `search_event`,
uses the event ID as the SSE `id`, and accepts that UUID through
`Last-Event-ID`. Transport `stream_error` frames contain `ApiErrorResponse` and
have no persisted ID; they are not `SearchEvent` or a target outcome. The exact
idempotency, consent, cancellation, and bounded reconnect behavior is specified
in [Private search API and ordered event stream](search-api.md).

The result variants deliberately remain separate:

- `definitive_result` carries only `found` or `not_found`, evidence, source,
  health, freshness, region, and rule identity;
- `uncertain_result` carries a classification uncertainty such as conflicting
  evidence or a changed site;
- `operational_failure` carries retryable transport, access, rule, or capacity
  failure, plus nonretryable `invalid_target` when the exact signed site's
  username policy rejects the request. It has no verdict or uncertainty field;
- `assertion_updated` carries the replaceable current interpretation plus its
  support, conflicts, and independently validated per-region projections.
  New worker events always include the projection; absence is accepted only
  for backward-compatible decoding of historical stored events;
- `finished` records a terminal state and self-consistent totals.

An invalid target or any other operational failure therefore cannot
deserialize as `not_found`, and a conflict cannot be collapsed into a
definitive observation. Cached and shared results retain their actual source
and freshness rather than appearing live.

## Evidence Capsules

`EvidenceCapsuleResource` is the exact authenticated inspection contract for
`socialname.dev/evidence-capsule/v1`. It binds one observation and target to a
typed outcome, exact signed rule/pack/engine provenance, coarse vantage,
evidence identity, at most 32 sanitized probe summaries, and at most 128
bounded matcher traces. The serialized resource is limited to 64 KiB.

There is no field for a complete body, arbitrary headers, cookies, credentials,
client IP, or unrelated profile data. HTTPS evidence URLs reject credentials
and are capped at 2 KiB. Latency is bucketed. A separately redacted
shared-research excerpt is capped at 2 KiB and 30 days. Runtime validation binds
private retention to at most 730 days and shared structure to exactly 400 days.
The read requires the independent `evidence:read` scope. See
[Bounded Evidence Capsule v1](evidence-capsule-v1.md).

## Watches

`WatchCreateRequest` requires exact targets, regions, freshness, a
private-history consent grant, at least one notification endpoint, retention,
and bounded execution policy:

- interval: 5 minutes through 31 days;
- jitter: 0 through 20 percent;
- maximum 256 probes and 64 MiB inspected bytes per run;
- retention: 30 through 730 days.

The probe maximum must cover the complete
`usernames × sites × region_classes` run. This relation is checked before a
watch can reach storage, so scheduling cannot silently truncate the requested
set to fit a smaller budget.

The schedule is an interval rather than arbitrary cron or executable code.
`WatchPatchRequest` requires an expected nonzero revision and at least one real
change. The authenticated server implements optimistic concurrency with that
revision: active watches require a future next-run time, while paused and
deleting watches cannot claim one. Creation and mutation require `watch:write`;
single-resource reads require `watch:read`. The server additionally verifies
active private-history consent, tenant-local endpoints, and known sites.
Scheduling, freshness reuse, and worker coalescing are specified in
[Freshness-aware watch scheduling](watch-scheduling.md).

`WatchListPage` and `WatchTransitionPage` are read resources for the monitoring
console. Each contains at most 50 items and an optional opaque keyset cursor
that, when present, must equal the final returned resource ID. Duplicate IDs,
cross-watch transitions, delivery/transition mismatches, deliveries from
nonconfirmed transitions, and more than 16 deliveries for one transition fail
validation. The server validates every supplied cursor in the same
tenant-scoped forced-RLS transaction before continuing the ordering.

## Transitions and notifications

`TransitionChange` is a closed tagged union:

- `account_state` moves only between `found` and `not_found`;
- `measurement_health` moves among healthy, degraded, quarantined, recovering,
  and unavailable for an exact region and rule hash.

There is no account-state `inconclusive` transition. Conflicts and rule/site
degradation remain measurement facts rather than account removal. Both a
previous and next account state are required, so an initial watch baseline
cannot be serialized as a transition or notification.

Account transitions require one or more supporting observation IDs.
Measurement-health transitions may omit them when the evidence is an
operational probe failure rather than an observation; generic lineage then
binds the probe job to the transition without fabricating an account verdict.

`TransitionConfirmation` records one of:

- pending managed verification;
- confirmed with a closed evidence basis;
- suppressed with a closed reason.

Confirmation validation enforces different bases for appearance,
disappearance, and measurement events. Shared-only absence is represented only
as suppressed and `permits_delivery()` is false. The notification delivery
constructor accepts a validated transition only when it is confirmed, so
pending, conflicted, deleted-support, or shared-only-absence transitions cannot
cross that boundary.

Endpoint creation accepts a redacted email or HTTPS webhook destination.
Endpoint resources intentionally return only ID, channel, verification state,
and timestamps; they do not echo the destination. Delivery records contain a
logical notification key for deduplication, endpoint and transition lineage,
confirmation basis, attempt state, retry time, and a bounded error code rather
than response content.

`WebhookNotification` is the stable signed body. It contains the API schema,
one stable delivery ID, and the complete typed confirmed transition. Its
constructor repeats the confirmation admission check, so pending or suppressed
transitions cannot be serialized for delivery. Retries reuse the same delivery
ID and body. HTTP transport is at least once; receivers deduplicate the
`socialname-webhook-id` header instead of treating a successful response as an
exactly-once guarantee. Signature input, outbound network policy, retries,
fencing, and audit are specified in
[Signed webhook delivery](webhook-delivery.md).

## Predictable errors

`ApiErrorResponse` contains a request ID and a closed error code:

- invalid request, authentication/authorization, not found, conflict, and
  idempotency conflict;
- rate limit and quota exhaustion;
- unavailable and internal failure.

Retryability and `retry_after_ms` must agree with the code. Field violations
contain only bounded field paths and validation codes. Arbitrary debug messages,
raw values, response bodies, and stack traces are outside the public contract.

## Verification

```console
cargo test --locked -p socialname-protocol
cargo clippy --locked -p socialname-protocol --all-targets --all-features -- -D warnings
```

Unit and public integration tests cover exact v1 JSON, schema roots, unknown
field rejection, redaction, selection and execution bounds, consent relations,
freshness relabelling, result/failure separation, progress consistency, watch
revision and schedule rules, transition confirmation, shared-only absence,
write-only notification destinations, delivery state consistency, bounded
webhook construction, workspace metadata, closed unique API-key scopes,
absence of key secret/digest fields, exact account/installation consent wire
shapes and redaction, exact accepted private-search resources, Cartesian
target/progress consistency, consent and monitoring page bounds, cursor
relations, and transition/delivery ownership.
