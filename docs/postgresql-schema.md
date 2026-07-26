# PostgreSQL schema and migration boundary

The managed SocialName data model starts as one PostgreSQL source of truth.
Migration `0001_initial.sql` creates the storage needed by the ordered
Milestone 2 monitoring loop. Migration `0002_api_key_authentication.sql` adds
the restricted credential lookup needed by the authenticated private-workspace
slice. Migration `0003_search_event_stream.sql` separates requested from
site-normalized usernames and adds append-only ordered search events.
Database-backed job claims and worker invocation, assertion recomputation, and
delivery workers remain closed for their own vertical slices.

PostgreSQL 18 is the development and CI baseline. SQLx embeds the migrations in
`socialname-server`, records their checksums in `_sqlx_migrations`, and refuses
to reinterpret an already-applied version with different contents.

## Running migrations

The migration command is deliberately separate from the HTTP process:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://USER:PASSWORD@HOST:5432/DATABASE"
cargo run --locked -p socialname-server -- migrate
```

`SOCIALNAME_DATABASE_URL` has no default. The command bounds initial connection
establishment to 10 seconds and one connection, bounds migration execution to
60 seconds, and closes the pool afterward. Missing, malformed, unreachable, and
migration-failure paths return a fixed diagnostic class without reflecting the
URL or credentials. Unknown or additional command-line arguments are likewise
rejected without reflection.

Migrations run under a dedicated schema-owner credential in deployment. That
credential must not be used by request handlers or workers. This initial
migration is forward-only; destructive rollback is an explicit reviewed
migration plus restore plan, not an automatic down script.

## Product tables

The migrations create 31 product tables:

| Boundary | Tables |
| --- | --- |
| Tenant and credentials | `tenants`, `memberships`, `api_keys`, `api_key_credentials`, `clients` |
| Site and rules | `sites`, `rule_packs`, `rule_versions`, `rule_health_records` |
| Consent | `consent_grants`, `consent_events` |
| Interactive work | `searches`, `search_targets`, `search_events` |
| Monitoring and execution | `watches`, `watch_targets`, `probe_jobs`, `probe_job_consumers` |
| Evidence and interpretation | `observations`, `assertions`, `assertion_support` |
| Change and notification | `transitions`, `transition_basis`, `notification_endpoints`, `notification_deliveries` |
| Audit and governance | `audit_events`, `data_lineage_edges`, `deletion_requests`, `deletion_tasks`, `deletion_receipts`, `suppression_tokens` |

Time partitioning is intentionally absent. PostgreSQL remains the source of
truth, and partitioning is admitted only after observed volume justifies its
operational cost.

## Tenant isolation contract

Twenty-six tenant-owned tables have row-level security both enabled and
forced. Their `tenant_isolation` policies compare `tenant_id` with
`socialname_current_tenant_id()`; the `tenants` policy compares its `id`.
Global site and rule-pack tables are outside tenant RLS.

RLS is defense in depth, not authentication. Every application
transaction must:

1. authenticate and authorize the caller before database access;
2. use a non-owner role without `BYPASSRLS`;
3. set `socialname.tenant_id` locally for that transaction;
4. keep all tenant work inside the same transaction and connection.

Connection-level tenant state must never be allowed to leak through a pool.
The authenticated workspace and search routes implement this contract. Their
integration test uses a real `LOGIN NOSUPERUSER NOBYPASSRLS` non-owner role and
proves that one tenant cannot read or insert another tenant row or observe a
foreign search/event cursor.

Tenant-owned relationships use composite `(tenant_id, id)` foreign keys where
the referenced resource is tenant-scoped. This prevents a globally unique UUID
from being used to smuggle a cross-tenant relationship past RLS.

## Credential lookup boundary

Authentication starts before the tenant ID is known, so
`api_key_credentials` is intentionally outside tenant RLS. It stores only a
64-bit public prefix, a SHA-256 digest of an independently generated 256-bit
secret, and the tenant/key IDs. It contains no presented key, scope, target, or
workspace display data.

All `PUBLIC` table privileges are revoked. The runtime role has no direct
access. A `SECURITY DEFINER` function with a fixed `pg_catalog` search path and
qualified table reference performs exact prefix/digest comparison and returns
only tenant/key IDs. `PUBLIC` execution is also revoked; deployment grants only
that function to the non-owner runtime role. Active tenant, key state, expiry,
and scopes are then rechecked in an ordinary transaction under forced tenant
RLS. See [Authenticated private workspaces and API keys](authenticated-workspaces.md)
for the complete request and operator contract.

## Trust and privacy constraints

- API credentials store a bounded public prefix plus a 32-byte secret digest
  separately from tenant-RLS metadata, never the presented key.
- Notification destinations store ciphertext, a destination hash, and an
  encryption-key identifier. No plaintext destination column exists.
- Search sync outside `never` requires an explicit consent grant. Consent
  events are immutable history.
- Search events are append-only, have a positive per-search sequence, one
  possible started/finished boundary, at most one result per target, a
  relational/JSON identity check, and a 128 KiB payload ceiling. The API
  requires a finished event before returning terminal state.
- Search targets preserve `requested_username`; nullable
  `normalized_username` is reserved for the next database job slice to populate
  through the signed worker's explicit per-site identity policy.
- Operational probe failure remains job state. `observations` contain only a
  definitive `found`/`not_found` result or bounded uncertainty, and observation
  rows reject updates.
- Assertion and transition support are explicit join records. Generic lineage
  preserves withdrawal and recomputation ancestry across later derived data.
- Account-appearance, account-disappearance, and measurement-health
  confirmation bases are constrained separately. Shared-only absence can only
  be a suppressed disappearance.
- A database trigger permits a notification delivery only when it copies the
  exact basis of a confirmed transition and references an active endpoint.
  Measurement degradation remains distinct from account-state change.
- Evidence digests and suppression tokens are fixed-size hashes. Normal
  evidence has no complete response-body, cookie, credential, or unrelated
  profile-data column.

Application services still have to validate the full protocol and domain
semantics. Database constraints are the last defensive boundary for closed
states and relationships, not a replacement for typed construction.

## Deletion and recomputation

Deletion requests carry ordered deadlines for hiding, support withdrawal,
primary deletion, derived rebuild, and backup expiry. Per-store tasks make
partial failure and retry explicit. Receipts record completed stores and backup
expiry, while lineage edges identify downstream material that must be
withdrawn or recomputed. HMAC suppression tokens prevent deleted target or
contributor identifiers from being silently reingested without retaining their
plaintext value.

This schema makes the workflow representable; the later deletion-worker slice
must implement the deadlines, restore-ledger replay, and production evidence.
No external deletion or backup-expiry evidence is claimed here.

## Verification

The integration test runs against a real `postgres:18-alpine` service in CI:

```console
cargo run --locked -p socialname-server -- migrate
cargo test --locked -p socialname-server --all-targets
```

It applies the embedded migrations twice, inventories all 31 tables and 26
forced-RLS policies, and verifies restricted credential privileges, closed
unique scopes, non-owner authentication and tenant isolation, idempotent search
creation, consent, ordered/immutable event replay, composite cross-tenant
foreign keys, immutable observations, transition confirmation bases,
shared-only notification suppression, valid confirmed delivery, ordered
deletion deadlines, receipts, and lineage. Tests skip only when
`SOCIALNAME_TEST_DATABASE_URL` is absent; the CI job always supplies it. The
value must identify a disposable test database: the integration test truncates
product tables and resets its runtime-role grants before installing fixtures so
the same database can be verified repeatedly.

The HTTP process uses the separate `SOCIALNAME_SERVER_DATABASE_URL` runtime
credential. Startup requires a database connection, readiness is
PostgreSQL-aware, and every private workspace/search operation authenticates
and sets a transaction-local tenant before product access. The schema-owner
`SOCIALNAME_DATABASE_URL` remains limited to migration and explicit
workspace/key operator commands.
