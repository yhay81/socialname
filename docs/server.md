# Modular-monolith server shell

`socialname-server` is the operable Axum/Tower process boundary for the managed
SocialName product. It embeds forward-only PostgreSQL migrations, provides
explicit workspace/API-key, signed rule-pack, and verified target-deletion
operator commands, exposes authenticated private workspace/search/watch,
consent, evidence, and contributor-deletion resources, bounded monitoring
pages, and ordered SSE replay. Notification endpoint administration and other
product routes remain
closed until their ordered roadmap slices add authorization, storage use,
lineage, and failure behavior end to end. Managed network execution remains in
the separate signed worker.

The server depends on `socialname-protocol`; it does not make the protocol,
domain, or engine depend on HTTP or persistence.

## Runtime configuration

The serving binary reads six environment variables:

| Variable | Default | Accepted range |
| --- | --- | --- |
| `SOCIALNAME_SERVER_BIND` | `127.0.0.1:8080` | A concrete socket address |
| `SOCIALNAME_SERVER_REQUEST_TIMEOUT_MS` | `30000` | 100 to 120000 whole milliseconds |
| `SOCIALNAME_SERVER_MAXIMUM_BODY_BYTES` | `262144` | 1024 to 1048576 bytes |
| `SOCIALNAME_SERVER_MAXIMUM_IN_FLIGHT` | `128` | 1 to 1024 requests |
| `SOCIALNAME_SERVER_DATABASE_URL` | none | A PostgreSQL URL for a non-owner runtime role |
| `SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX` | none | Exactly 64 lowercase hexadecimal characters |
| `SOCIALNAME_EXPECTED_RESTORE_LEDGER_ID` | none | Optional canonical UUID that keeps a restored runtime unready until exact ledger replay |

The default is loopback-only. Binding a non-loopback address requires an
explicit value; it does not imply that TLS, authentication, abuse controls, or
production ingress are ready. Invalid and non-Unicode configuration is rejected
before bind. Errors name the variable and constraint but omit its supplied
value.

PowerShell development start:

```powershell
$env:SOCIALNAME_SERVER_BIND = "127.0.0.1:8080"
$env:SOCIALNAME_SERVER_DATABASE_URL = "postgres://SOCIALNAME_APP:...@HOST/DATABASE"
$env:SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX = "<persistent 256-bit secret>"
cargo run --locked -p socialname-server
```

No SocialName service is started by ordinary CLI or desktop execution. The
server is a separate explicit binary.

## Database migration command

Migration is an explicit operator action:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://USER:PASSWORD@HOST:5432/DATABASE"
cargo run --locked -p socialname-server -- migrate
```

There is no database URL default. Connection and migration work is bounded,
uses one connection, and returns fixed error classes that do not echo the URL
or credentials. The schema, RLS application contract, migration ownership, and
PostgreSQL 18 integration gate are documented in
[PostgreSQL schema and migration boundary](postgresql-schema.md).

Workspace bootstrap, one-time API-key issuance, revocation, runtime role
grants, token handling, and the protected route are documented in
[Authenticated private workspaces and API keys](authenticated-workspaces.md).
Initial trust pinning and transactional `apply-rule-pack` operation are
documented in
[Signed Rule-Pack Distribution v1](rule-pack-distribution-v1.md).
The suppression key is mandatory because consent creation and managed
ingestion must honor prior deletion suppression. It must remain stable for
every unexpired token; fingerprint mismatch fails closed. Contributor and
verified target workflows are documented in
[Lineage-backed deletion workflows](deletion-workflows.md).

## Current HTTP surface

The server exposes:

```http
GET /health/live
GET /health/ready
GET /v1/workspace
POST /v1/searches
GET /v1/searches/{search_id}
GET /v1/searches/{search_id}/events
DELETE /v1/searches/{search_id}
POST /v1/watches
GET /v1/watches
GET /v1/watches/{watch_id}
PATCH /v1/watches/{watch_id}
DELETE /v1/watches/{watch_id}
GET /v1/watches/{watch_id}/transitions
POST /v1/consent-grants
GET /v1/consent-grants
GET /v1/consent-grants/{consent_grant_id}
POST /v1/consent-grants/{consent_grant_id}/withdrawals
GET /v1/observations/{observation_id}/evidence-capsule
POST /v1/deletion-requests/contributor
GET /v1/deletion-requests/{deletion_request_id}
GET /v1/deletion-requests/{deletion_request_id}/receipt
```

The two health endpoints return a small `socialname.dev/api/v1` JSON document
with service name, crate version, and health status. When
`SOCIALNAME_EXPECTED_RESTORE_LEDGER_ID` is set, readiness additionally requires
that exact authenticated restore-ledger replay to have committed. Liveness is
dependency-free. Readiness probes PostgreSQL with a deadline shorter than the
outer request deadline and returns HTTP 503 `not_ready` when storage is
unavailable.

`GET /v1/workspace` requires one valid bearer API key with
`workspace:read`. It authenticates through the restricted credential lookup,
rechecks key, key-creating membership, and workspace state under forced
transaction-local tenant RLS, and returns only that private workspace plus
nonsecret key metadata. Missing,
unknown, malformed, revoked, and expired credentials are uniformly
`unauthenticated`; insufficient scope is `forbidden`; database failure is
`unavailable`.

The search endpoints require `search:write` for idempotent creation and
cancellation or `search:read` for polling and SSE. They require an active
purpose-specific consent grant, keep cross-tenant IDs indistinguishable from
missing resources, and never start a network probe in the API process.
PostgreSQL-backed events provide ordered `Last-Event-ID` replay. SSE bodies,
polling windows, batches, keep-alives, and open connection count are bounded.
The complete contract is in
[Private search API and ordered event stream](search-api.md).

Watch creation, patching, and deletion require `watch:write`; single-resource,
bounded watch-list, and transition/delivery timeline reads require
`watch:read`. Creation verifies active private-history consent, known sites,
and active tenant-local notification endpoints. Revision-checked patches
prevent last-writer-wins schedule loss, while pause/delete atomically cancel
older pending runs. List and timeline pages use tenant-validated UUID keyset
cursors, cap results at 50, and expose typed public resources without endpoint
destinations, signatures, request digests, worker labels, or audit details.
The API process stores policy but performs no probe. See
[Freshness-aware watch scheduling](watch-scheduling.md) and
[Minimal monitoring console](monitoring-console.md).

Consent creation and withdrawal require `consent:write`; bounded list and
single-resource reads require `consent:read`. The API derives account identity
from the active key membership, hashes installation identifiers with tenant
separation, rejects membership override, and commits each grant/withdrawal
with an immutable event under forced RLS. See
[Purpose-specific consent grant lifecycle](consent-api.md).

`GET /v1/observations/{observation_id}/evidence-capsule` requires
`evidence:read`. It returns only an unexpired, unpurged, validated Capsule under
forced tenant RLS; unknown, foreign, expired, and physically purged resources
are uniformly `not_found`. A research excerpt is projected only before its
independent database deadline. See
[Bounded Evidence Capsule v1 and retention enforcement](evidence-capsule-v1.md).

Contributor deletion creation and owner-only status/receipt reads require
`data:delete`. Creation is replay-safe, immediately withdraws all matching
subject/purpose grants, materializes lineage-backed hide tombstones, cancels
and redacts active work, and creates primary/derived/backup tasks with exact
deadlines. The public receipt keeps pending backup time distinct from verified
completion. The cross-tenant target-person path is deliberately an
externally-verified stdin operator command, not a public HTTP route. See
[Lineage-backed deletion workflows](deletion-workflows.md).

Every other path returns a protocol `not_found` response. Unsupported methods
return a protocol `invalid_request` response. Notification endpoint management,
worker control, and HTTP key-administration routes do not exist yet, so
authentication cannot accidentally make later product capabilities available.
The separate one-shot signed worker does not share the server's HTTP router or
database pool.

## Request boundary

The Tower stack is ordered so one outer request guard:

1. accepts only a syntactically bounded `x-request-id` or generates a server ID;
2. rejects invalid or oversized declared content lengths;
3. applies the configured handler deadline;
4. adds `cache-control: no-store`, `x-content-type-options: nosniff`, and the
   request ID to every response.

A Tower concurrency layer bounds in-flight handler work. Axum's default body
limit is set to the same configured maximum for body-consuming extractors.
Search, watch, consent, and deletion JSON routes map extractor rejections into the closed
protocol envelope; each future JSON route must do the same and must not bypass
the body limit by polling raw frames.

Missing routes, method errors, declared-body overflow, invalid content length,
and deadline failure remain JSON protocol errors. They do not return framework
debug text, a stack trace, the rejected value, or the request URI. Operational
deadline failure is `unavailable`, not `not_found` or an account verdict.

## Logging and sensitive data

Request spans contain only request ID and HTTP method. Completion records add
status and elapsed milliseconds. The URI, query, headers, request body,
username, public identifier, notification destination, and protocol DTO are not
logged by the shell.

That exclusion includes the `Authorization` header, API-key prefix/secret/hash,
workspace name, membership subject, and database URL. Authentication errors use
fixed protocol categories and never log or reflect a credential.

Future route work must preserve that boundary. Targets belong in validated JSON
bodies, not path or query fields that infrastructure commonly records. Error
mapping must use field/code information without rejected values.

## Shutdown

The binary uses `axum::serve` with graceful shutdown. Ctrl-C is supported on all
platforms and SIGTERM is also handled on Unix. Registration failure is logged
without pretending that a graceful signal was received. The library accepts an
injected shutdown future so drain behavior is deterministic in tests.

## Verification

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-server
cargo clippy --locked -p socialname-server --all-targets --all-features -- -D warnings
cargo build --locked -p socialname-server
# With the documented owner, runtime, and test database URLs set:
cargo run --locked -p socialname-server -- migrate
```

The deterministic tests cover default and explicit configuration, secret-free
configuration errors, every resource bound, hardened/versioned health,
request-ID regeneration, closed 404/405 errors, typed content-length rejection,
deadline failure, closed unimplemented routes, API-key parsing/redaction,
managed-search validation/header parsing, operator configuration, and graceful
shutdown. PostgreSQL CI additionally covers migration replay, schema inventory,
forced RLS, non-owner authentication, workspace/search/watch isolation, key
expiry/revocation/scope, consent, exact/conflicting idempotency, ordered SSE
replay, watch revision/cancellation, bounded stream capacity, readiness,
operator lifecycle, evidence/event immutability, notification safety, and
lineage-backed contributor and verified-target deletion. It also proves
immediate hiding, future reingestion suppression, remaining-support
recomputation, primary purge, private-target preservation, and persisted
rule-pack replay protection,
staged/general trust rotation, exact worker binding, signed rollback,
monitoring read scope, tenant/cursor
isolation, account-versus-measurement timelines, delivery retry/dead-letter
state, and the absence of delivery secrets from public pages.
