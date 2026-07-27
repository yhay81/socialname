# PostgreSQL schema and migration boundary

The managed SocialName data model starts as one PostgreSQL source of truth.
Migration `0001_initial.sql` creates the storage needed by the ordered
Milestone 2 monitoring loop. Migration `0002_api_key_authentication.sql` adds
the restricted credential lookup needed by the authenticated private-workspace
slice. Migration `0003_search_event_stream.sql` separates requested from
site-normalized usernames and adds append-only ordered search events.
Migration `0004_managed_probe_jobs.sql` adds consent/visibility-scoped active
work, fenced claims, narrow worker coordinator functions, and the final
consent-lock boundary used by atomic observation/event ingestion. Migration
`0005_watch_scheduling.sql` adds revisioned watch endpoint links, immutable
runs and run targets, freshness reuse, bounded scheduling coordination, and
search/watch consumers. Migration `0006_assertion_recomputation.sql` adds the
per-watch account baseline and indexes for durable account candidates and
regional measurement state. Migration `0007_webhook_delivery.sql` adds fenced
webhook leases, append-only attempt history, bounded retry/dead-letter state,
and a narrow cross-tenant claim coordinator. Migration
`0008_regional_assertion_escalation.sql` adds immutable regional assertion and
support projections plus a generated probe-priority reason for conflict and
account-confirmation work. Migration `0009_rule_pack_distribution.sql` adds
durable signed trust roots, staged/active metadata, embedded promotion
bindings, global and per-site anti-replay state, exact worker metadata
resolution, and continuous version availability checks. Migration
`0010_consent_grant_lifecycle.sql` closes the accepted consent versions,
installation ownership, immutable history, and one-way withdrawal boundary.
Migration `0011_evidence_capsule_retention.sql` adds atomic closed Evidence
Capsules, independent database-time deadlines, payload-free purge receipts,
and a bounded retention-enforcement function. Migration
`0012_lineage_backed_deletion.sql` adds immutable resource-match tombstones,
exact software deadlines and monotonic progress, target/job redaction,
suppression-key identity, and a fenced cross-tenant deletion claim. Migration
`0013_deletion_receipts_and_restore.sql` adds fixed-shape completion receipts,
backup-expiry evidence, and restore-ledger readiness. Migration
`0014_notification_acknowledgements.sql` adds one delivered-only append-only
operator receipt. Migration `0015_email_delivery.sql` adds a channel-isolated
email claim coordinator over the same fenced delivery and attempt state.
Migration `0016_operational_reporting.sql` adds the closed `operations:read`
scope and tenant/time indexes for watch-run and notification-delivery report
cohorts. It adds no product table or RLS policy. Migration
`0017_developer_usage_reporting.sql` adds the closed `usage:read` scope,
tenant and API-key quota policies, immutable target-free usage records,
tenant-checked admission locking, and bounded 400-day physical expiry.
Migration `0018_search_completion_webhooks.sql` adds one tenant-RLS binding per
search, generalizes delivery origin to a closed transition/search kind, and
converges terminal-search and binding-insert order through one deduplicating
enqueue function.

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

The migrations create 52 product tables:

| Boundary | Tables |
| --- | --- |
| Tenant and credentials | `tenants`, `memberships`, `api_keys`, `api_key_credentials`, `clients` |
| Site and rules | `sites`, `rule_packs`, `rule_versions`, `rule_health_records`, `rule_pack_trust_roots`, `rule_pack_metadata`, `rule_pack_promotions`, `rule_pack_registry`, `rule_site_promotion_high_water` |
| Consent | `consent_grants`, `consent_events` |
| Interactive work | `searches`, `search_targets`, `search_events` |
| Developer capacity | `developer_quota_policies`, `developer_usage_records` |
| Monitoring and execution | `watches`, `watch_targets`, `watch_notification_endpoints`, `watch_runs`, `watch_run_targets`, `probe_jobs`, `probe_job_consumers` |
| Evidence and interpretation | `observations`, `evidence_capsules`, `evidence_retention_receipts`, `assertions`, `assertion_support`, `regional_assertions`, `regional_assertion_support` |
| Change and notification | `transitions`, `transition_basis`, `notification_endpoints`, `search_completion_webhooks`, `notification_deliveries`, `notification_delivery_attempts`, `notification_acknowledgements` |
| Audit and governance | `audit_events`, `data_lineage_edges`, `deletion_requests`, `deletion_tasks`, `deletion_receipts`, `deletion_resource_matches`, `deletion_backup_verifications`, `deletion_restore_runs`, `deletion_restore_request_links`, `suppression_tokens` |

Time partitioning is intentionally absent. PostgreSQL remains the source of
truth, and partitioning is admitted only after observed volume justifies its
operational cost.

## Tenant isolation contract

Forty tenant-owned tables have row-level security both enabled and
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
The authenticated workspace, consent, search, watch, and evidence routes
implement this contract. Their integration test uses a real
`LOGIN NOSUPERUSER NOBYPASSRLS` non-owner role and proves that one tenant
cannot read or insert another tenant row or observe a foreign consent,
search/event, or monitoring cursor.

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

## Managed worker coordinator boundary

The worker is also a non-owner `NOSUPERUSER NOBYPASSRLS` role, but it must
select the next tenant before it can set transaction-local RLS. Migrations
`0004_managed_probe_jobs.sql`, `0005_watch_scheduling.sql`, and
`0007_webhook_delivery.sql`, `0009_rule_pack_distribution.sql`,
`0011_evidence_capsule_retention.sql`, `0012_lineage_backed_deletion.sql`, and
`0015_email_delivery.sql` and `0017_developer_usage_reporting.sql` therefore
provide thirteen fixed-search-path
`SECURITY DEFINER` functions. They can resolve
an exact eligible signed rule including metadata and promotion identity,
recheck that one rule version is still active, lock one eligible search
target, lock one due watch, lock one eligible watch-run target, claim one job
with an incremented attempt fence, lock the consent attached to an exact
current lease, claim one due webhook or one due email with an incremented
channel-specific attempt fence,
enforce a bounded due-evidence batch, redact exactly one tenant/request's
matched job targets, claim one due deletion request with an incremented
attempt fence, or delete one bounded batch of expired target-free Developer
usage. They return only opaque IDs, an attempt number, a boolean, payload-free
counts, or no value. A separate tenant-checked definer function locks exactly
one Developer quota policy for application admission without granting the
runtime role table UPDATE.

`PUBLIC` execution is revoked. Deployment grants only these functions plus the
column-limited ordinary table access exercised by the integration fixture. The
worker has no access to `api_key_credentials`, no table ownership or
`BYPASSRLS`, and no observation/event update. Its ordinary job/retention paths
cannot delete product rows; the deletion unit receives only the reviewed
primary-resource deletes exercised by the integration fixture.
Target/consumer/observation/event/lineage work occurs only after the selected
tenant is set locally on the transaction.

The evidence-retention function is the only ordinary maintenance path allowed
to clear due Capsule payloads and delete expired retention receipts. It accepts
1–1000 rows per class, orders by database deadline and Capsule ID, locks with
`SKIP LOCKED`, and emits one idempotent payload-free receipt for each research
or structured purge. The separate deletion worker may delete only
lineage-selected Capsules and their receipts under a fenced request; ordinary
job execution and application grants cannot update Capsules or delete
receipts.

Developer usage has an independent fixed 400-day deadline. Product reports
hide expired rows even before cleanup. The worker can execute only a 1–1000-row
`SKIP LOCKED` deletion function and has no direct usage/policy read, update, or
delete privilege.

Because the tenant tables use `FORCE ROW LEVEL SECURITY`, the thirteen
coordinator functions must be owned by a dedicated `NOLOGIN BYPASSRLS` role or
an equivalently privileged migration owner. The integration test asserts that
owner capability separately from the worker's NOBYPASSRLS status. The
privileged owner is not a runtime login and must not own broader application
code paths.

The consent-lock function requires the exact `(job ID, attempt, lease owner)`
and a current lease before taking `FOR KEY SHARE` on its matching active
purpose-specific consent. A withdrawal that commits first blocks ingestion; an
ingestion transaction holding the lock commits first and makes the subsequent
withdrawal unambiguously later. See
[Managed probe jobs and observation ingestion](managed-jobs.md) and
[Freshness-aware watch scheduling](watch-scheduling.md).

## Trust and privacy constraints

- API credentials store a bounded public prefix plus a 32-byte secret digest
  separately from tenant-RLS metadata, never the presented key.
- Signed rule-pack tables store only public trust roots, bounded signed
  envelopes, exact content identities, rollout state, and replay high-water
  marks. They contain no private signing seed or target data, and all `PUBLIC`
  privileges are revoked.
- A candidate trust root remains `staged` while canary/regional metadata is
  evaluated. Only general activation or signed rollback changes the one active
  root. Global metadata sequence and every site's promotion sequence advance
  monotonically and are cross-checked against the serialized registry before
  each operator transaction.
- Rule versions are enabled only for the active unexpired `general` or
  `rollback` metadata. Worker resolution additionally binds metadata and
  promotion IDs and sequences, required region, fresh regional health, and the
  exact rule and pack hashes.
- Notification destinations store ciphertext, a destination hash, and an
  encryption-key identifier. No plaintext destination column exists.
- Search sync outside `never` requires an explicit consent grant. Consent
  events are immutable history. Migration `0010` closes new grants to the
  accepted `profile-v1`/`notice-v1` contract, permits only a one-way
  `withdrawn_at` transition, and binds installation consent ownership to one
  active membership without storing the installation ID.
- Search events are append-only, have a positive per-search sequence, one
  possible started/finished boundary, at most one result per target, a
  relational/JSON identity check, and a 128 KiB payload ceiling. The API
  requires a finished event before returning terminal state.
- Search targets preserve `requested_username`; nullable
  `normalized_username` can be populated only by the job worker through the
  exact signed rule's explicit per-site identity policy. Invalid values become
  operational `invalid_target`, never absence.
- Active jobs carry consent grant and private/shared visibility. Their partial
  uniqueness includes tenant, normalized target, site, rule version, region,
  grant, and visibility; consumers cannot cross-coalesce purpose boundaries.
- Attempt count is a lease-fencing token. Stale or expired attempts cannot
  write observations, events, or final state.
- Operational probe failure remains job state. `observations` contain only a
  definitive `found`/`not_found` result or bounded uncertainty, and observation
  rows reject updates.
- Every newly persisted managed observation atomically receives one
  at-most-64-KiB closed Evidence Capsule. Database constraints bind its
  tenant/observation IDs,
  profile, millisecond timestamps, SHA-256 digests, payload shape, and
  retention relation. The structure has no body, arbitrary-header, cookie,
  credential, or client-IP field.
- Capsule payload reads require `evidence:read` and a future database deadline.
  A trigger permits only deadline-due non-null-to-null research or structured
  purge. Receipts keep only identifiers, closed action, deadlines, and times
  for exactly three years.
- Assertion and transition support are explicit join records. Generic lineage
  preserves withdrawal and recomputation ancestry across later derived data.
- Regional assertions are immutable children of one global assertion
  generation. Their support is explicit, and lineage connects observation ->
  regional assertion -> global assertion without inferring missing historical
  regions.
- Probe priority reasons are generated from the numeric tier: routine below
  50, account confirmation from 50, and regional conflict from 100. Workers
  may raise priority only on queued or retry-wait jobs; watch budgets remain
  the authority for whether work exists.
- A watch target's account baseline is an all-null or fully populated
  state/assertion/time triple. The initial assertion establishes the baseline
  without fabricating a transition.
- Account-appearance, account-disappearance, and measurement-health
  confirmation bases are constrained separately. Shared-only absence can only
  be a suppressed disappearance.
- A database trigger permits a notification delivery only when it copies the
  exact basis of a confirmed transition and references an active endpoint.
  Measurement degradation remains distinct from account-state change.
- Logical delivery identity and transition/endpoint binding are immutable. One
  unique SHA-256 key covers each tenant/transition/endpoint, while a bounded
  lease and one-through-ten attempt counter fence stale channel workers.
- Notification attempt rows are append-only. They retain a closed event/error
  class, bounded status, request-body digest, worker label, and time, never the
  destination, signature, request body, or response body.
- Evidence digests and suppression tokens are fixed-size hashes. Normal
  evidence has no complete response-body, cookie, credential, or unrelated
  profile-data column.

Application services still have to validate the full protocol and domain
semantics. Database constraints are the last defensive boundary for closed
states and relationships, not a replacement for typed construction.

## Deletion and recomputation

Software-created deletion requests carry exact immutable deadlines for hiding,
support withdrawal, primary deletion, derived rebuild, and backup expiry.
`deletion_resource_matches` materializes target-free hide tombstones before
creation returns. Read paths exclude them immediately. A narrow redaction
function removes target-bearing queued work, and a fenced non-owner worker
withdraws support, recomputes assertions from remaining observations, and
deletes current PostgreSQL primary dependencies atomically.

HMAC-only contributor and target suppression tokens prevent reingestion
without retaining selectors. A nonsecret fingerprint binds tokens to the
persistent secret; any active legacy or mismatched key identity fails closed.
Private target observations remain outside a shared-pool request.

Primary and derived-projection tasks complete together after recomputation;
the backup task remains durable and pending with the request in `rebuilding`.
`deletion_backup_verifications` admits completion only after the deadline and
after inventory no longer reaches primary completion. The transaction creates
an append-only receipt and completes the request. `deletion_restore_runs` and
`deletion_restore_request_links` record authenticated, target-free replay;
runtime readiness can be pinned to an exact replay ID. See
[Lineage-backed deletion workflows](deletion-workflows.md).

## Verification

The integration test runs against a real `postgres:18-alpine` service in CI:

```console
cargo run --locked -p socialname-server -- migrate
cargo test --locked -p socialname-server --all-targets
```

It applies the embedded migrations twice, inventories all 52 tables and 40
forced-RLS policies, and verifies restricted credential privileges, closed
unique scopes, non-owner authentication and tenant isolation, idempotent search
creation, consent, ordered/immutable event replay, composite cross-tenant
foreign keys, immutable observations, transition confirmation bases,
shared-only notification suppression, valid confirmed delivery, delivered-only
idempotent acknowledgement, ordered
deletion deadlines, receipts, lineage, and a second real NOBYPASSRLS worker
role covering job coalescing, watch planning, freshness reuse, byte
reservation, fencing, retry, atomic observation/assertion/search/watch
ingestion, account baselines and confirmed transitions, global/regional
assertion support and lineage, regional disagreement, bounded conflict and
account-confirmation priority, atomic observation/Capsule storage, closed
payload shape, scoped and deadline-hidden Capsule reads, one-way purge,
payload-free receipts, bounded idempotent retention batches, lineage-backed
contributor/target hiding and primary purge, suppression-key mismatch
fail-closed behavior, remaining-support recomputation, private target
preservation, invalid targets,
measurement degradation, revision cancellation, consent withdrawal, regional
rule degradation, channel-separated logical webhook/email enqueue,
timeout/retry, same-ID and same-body success, permanent 4xx, lease reclamation,
stale fencing, final dead-letter state, attempt audit, lineage, secret
exclusion, and bounded watch/transition page
reads with scope, tenant, cursor, account/measurement, and secret-exclusion
checks. It also proves the target-free operational report's exact scope,
database-time windows, channel-separated outcomes and latency samples,
unknown-window rejection, identifier exclusion, and two-tenant isolation.
The Developer reporting checks cover default/operator quotas, serialized
concurrent admission, exact replay, whole-batch rollback, append-only usage,
least privilege, target-free scoped reports, no-data separation, and bounded
worker-only expiry.
The same real-database test also pins initial rule trust, applies
canary then general metadata, rejects persistent replay, stages an overlapping
key generation without replacing the active root, activates a second pack,
removes the old key through dual-threshold rollback metadata, restores the
retained version, and proves stale versus current worker binding. Tests skip
only when
`SOCIALNAME_TEST_DATABASE_URL` is
absent; the CI job always supplies it. The administrator, application, and
worker test URLs must identify the same disposable test database with their
intended roles: the integration test truncates product tables and resets
runtime-role grants before installing fixtures so the database can be verified
repeatedly.

The HTTP process uses the separate `SOCIALNAME_SERVER_DATABASE_URL` runtime
credential. Startup requires a database connection, readiness is
PostgreSQL-aware, and every private workspace/search/watch/evidence operation
authenticates and sets a transaction-local tenant before product access. The
schema-owner `SOCIALNAME_DATABASE_URL` remains limited to migration and explicit
workspace/key/rule-pack and externally verified target-deletion operator
commands. The rule-pack command and its initial out-of-band trust pin are specified in
[Signed Rule-Pack Distribution v1](rule-pack-distribution-v1.md).
