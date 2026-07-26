# Managed probe jobs and observation ingestion

This boundary connects accepted managed searches and scheduled private watches
to `socialname-worker` without giving the API process network authority or
giving the worker unrestricted cross-tenant database access. Migrations
`0004_managed_probe_jobs.sql`, `0005_watch_scheduling.sql`,
`0006_assertion_recomputation.sql`, and
`0009_rule_pack_distribution.sql`, plus `JobStore`, implement the complete
consumer-to-interpretation path:

1. select eligible accepted work;
2. normalize through the exact signed site rule;
3. expand or coalesce a job;
4. claim it with a fenced lease;
5. execute through `ManagedRule`;
6. retry operational failure or atomically persist one observation, its
   current assertion, and all consumer events and transitions.

Current repository rules remain `discovery` and have no accepted promotion
artifact. The path is operable for a promoted, active, region-healthy signed
rule, but it cannot execute the representative rules until their external live
acceptance gate passes.

## Eligibility and work identity

Expansion requires all of the following at the instant the target is locked:

- an `accepted` or `running` `remote`/`hybrid` search;
- `private` or `shared` sync and the matching active account-consent purpose;
- the requested region;
- a promoted site;
- the exact enabled rule version inside the active, published, unexpired pack;
- active, unexpired `general` or `rollback` pack metadata whose ID, sequence,
  embedded promotion ID, and promotion sequence match the worker binding;
- the latest record for that rule and region to be healthy and unexpired.

Only `ManagedRule::normalize_username` can populate
`search_targets.normalized_username`. Site-invalid values become a
nonretryable `invalid_target` operational event. They never become
`not_found`, never create a job, and complete the target and possibly its search
in the same transaction.

Active work coalesces only when these fields all match:

- tenant;
- normalized username;
- site;
- rule version;
- region;
- consent-grant ID;
- visibility.

The length-framed SHA-256 `work_key_hash` covers the same fields. The database
also has an exact partial unique index over the active scope, and each search
target can have only one job consumer. Private and shared purposes, or two
different grants with the same purpose, therefore never share work.

## Worker database boundary

The worker connects with `SOCIALNAME_WORKER_DATABASE_URL`. Its role must be a
non-owner `LOGIN NOSUPERUSER NOBYPASSRLS` role. It receives no API credential
access, table delete privilege, observation update privilege, or unrestricted
cross-tenant read.

Forced RLS means the worker cannot discover the tenant before it has selected
work. Seven fixed-search-path `SECURITY DEFINER` functions provide only the
minimum coordinator operations:

- `socialname_worker_resolve_rule` returns the exact currently eligible rule
  version ID only when site/rule/pack/region plus metadata and promotion
  identities all match the active registry;
- `socialname_worker_rule_version_available` continuously rechecks an exact
  active version, metadata stage and expiry, promotion expiry, site state, and
  regional health;
- `socialname_worker_lock_next_target` returns one eligible tenant/target ID
  while locking it with `SKIP LOCKED`;
- `socialname_worker_lock_due_watch` returns one due eligible tenant/watch ID;
- `socialname_worker_lock_next_watch_target` returns one eligible pending
  tenant/run-target ID;
- `socialname_worker_claim_job` returns one tenant/job ID and incremented
  attempt fence;
- `socialname_worker_lock_claim_consent` locks only the active consent row
  attached to an exact current job/attempt/owner lease.

`PUBLIC` execution is revoked. Because tenant tables use `FORCE ROW LEVEL
SECURITY`, these seven functions must be owned by a dedicated `NOLOGIN`
coordinator role with `BYPASSRLS` (or an equivalently privileged migration
owner). An ordinary table owner cannot cross forced RLS. That privileged role
owns only the reviewed coordinator boundary and is never a server or worker
runtime credential. After a coordinator function returns IDs, `JobStore` sets
`socialname.tenant_id` transaction-locally and all target, consumer,
observation, event, state, and lineage access proceeds under ordinary forced
RLS.

A deployment worker role needs schema usage, the column-limited table grants
exercised by `postgres_migrations.rs`, and execute only on those seven
functions. Treat that integration fixture as the executable grant manifest;
do not grant ownership or `BYPASSRLS` to make deployment easier.

## Claims, fencing, and retries

Claims use `FOR UPDATE SKIP LOCKED`, accept leases from 5 through 300 seconds,
and increment `attempt_count`. The tuple `(job_id, attempt_count, lease_owner)`
is the fencing identity. An expired lease can be reclaimed, but a stale attempt
cannot append an observation, event, or terminal state.

Operational failures retry without emitting a target event while attempts
remain. Backoff starts at 5 seconds, doubles, and caps at 5 minutes. The
operator-selected maximum is closed to 1 through 10. Exhaustion atomically:

- marks the job failed;
- appends one nonretryable operational failure for every still-live search;
- completes still-live search and watch-run targets;
- closes a search or watch run when all of its targets are accounted for.

Transport, DNS, timeout, access, size, decode, rule, and capacity failure remain
operational. Classification ambiguity remains uncertain. Only `found` and
`not_found` become definitive observations.

## Cancellation, consent, and rule health

Before network execution, and every 250 milliseconds while it is in flight,
the worker rechecks:

- the exact live lease;
- active purpose-specific consent;
- at least one live search or watch-run consumer;
- the exact active general/rollback rule-pack metadata, rule version, and
  latest fresh healthy regional record.

Shutdown, search cancellation, a stale watch revision, pause/delete, endpoint
deactivation, consent withdrawal, or rule quarantine drops the network future.
Immediately before ingestion, the transaction re-resolves the exact signed
rule and locks the leased job's consent through the narrow coordinator
function. Cancellation and live consumers are rechecked under row locks. No
observation can commit after a consent-withdrawal transaction wins that lock.

The narrow claim coordinator cancels dead watch targets and an active job that
no live search or watch still needs. A claimed job becomes ineligible before
observation, event, or watch-target creation.

## Atomic observation, assertion, and event ingestion

A successful job creates at most one immutable observation. The observation,
job terminal state, current global and regional `assertion/v1` generations and
support, per-search result and assertion events, watch-run target completions,
watch-local baseline or transition, terminal search/run states, and lineage
edges commit in one tenant transaction. A repeated completion of the same
fenced claim returns `already_final`; it cannot duplicate any derived output.

Observation persistence retains typed outcome, evidence class/digest, exact
rule/region, consent/visibility, source, and bounded freshness. The same
transaction stores a closed 64 KiB Evidence Capsule containing only sanitized
probe summaries and bounded rule-generated matcher traces. It does not retain
complete bodies, cookies, credentials, or arbitrary headers. Consumer-specific
database deadlines and the bounded purge command are specified in
[Bounded Evidence Capsule v1](evidence-capsule-v1.md). One coalesced
observation can support multiple searches and watch runs, but each search
receives its own event UUID and sequence. Lineage records:

- search target to job;
- job to observation;
- observation to Evidence Capsule;
- observation to definitive/uncertain event;
- observation to watch-run target;
- job to terminal operational-failure event.

Assertion and transition rules are specified in
[Assertion recomputation and transition persistence](assertion-recomputation.md).

## Budget-preserving verification order

Watch jobs carry a numeric priority and a database-generated reason:
`routine` (0), `account_confirmation` (50), or `regional_conflict` (100).
Expansion reads the current assertion and durable account candidate after the
watch run has reserved its ordinary probe and byte budgets. A fresh conflict
outranks a pending high-value account transition, which outranks routine work.
Interpretation can raise an already queued or retry-wait sibling but never
creates an unscheduled probe, expands a run budget, or changes a leased job.
Search jobs remain routine unless coalescing with an already authorized watch
consumer raises the shared job.

## One-job operator entry point

`process-one` plans at most one due watch, performs a bounded alternating
search/watch expansion batch, and executes at most one job.
Connections created by this command cap statement time at 10 seconds, lock wait
at 5 seconds, idle transaction time at 15 seconds, pool acquisition at 5
seconds, and initial connection establishment at 10 seconds:

```console
$env:SOCIALNAME_WORKER_DATABASE_URL = "postgres://WORKER:SECRET@HOST:5432/DB"
cargo run --locked -p socialname-worker -- process-one \
  --site <site-id> \
  --region <worker-region> \
  --rules-dir <exact-pack-directory> \
  --metadata <rule-pack-metadata.json> \
  --current-trust-file <current-trust.json> \
  --minimum-metadata-sequence-exclusive <worker-high-water> \
  --worker-id <closed-lowercase-label> \
  --lease-seconds 60 \
  --maximum-attempts 3 \
  --expansion-limit 32 \
  --allow-live
```

The command rejects `canary` and `regional` metadata for customer work.
`--allow-live` is checked before rule/trust files or the database are touched.
Expansion is bounded to 1 through 128 targets, and one invocation sends at
most one bounded external request. Ctrl-C drops that request and leaves the
fenced lease to expire safely.

Standard output is one target-free
`socialname.dev/managed-job-process/v1` object. It contains status, planned
watch-run count, expansion count, optional job ID, and optional attempt
count—never username, result, consent ID, tenant ID, or database URL. Errors
use fixed classes and likewise do not reflect target or credential material.

## Verification

The deterministic worker tests cover scope hashing, consent/visibility
isolation, retry bounds, target-free debug/output, activation, expiry, and
cancellation. The PostgreSQL 18 integration test uses real non-owner API and
worker roles and proves:

- forced-RLS isolation and no worker credential-table access;
- exact metadata/promotion/rule/pack/region eligibility and continuous
  invalidation after rollout or rollback;
- search/watch coalescing and consent isolation;
- due-run atomicity, freshness reuse, and conservative byte reservation;
- claims, expiry reclamation, and stale-fence rejection;
- bounded retry and exhaustion;
- idempotent observation/event ingestion;
- immutable regional assertion/support persistence and regional event output;
- global conflict with preserved opposing regional truths;
- budget-preserving priority 100 conflict and priority 50 account-confirmation
  follow-ups;
- multi-consumer fan-out and lineage;
- invalid-target separation;
- search cancellation, watch revision cancellation, consent withdrawal, and
  rule degradation before commit;
- persistent global and per-site replay rejection, staged trust retention,
  general trust activation, old-key removal, and signed rollback to the exact
  retained rule version.

No test claims external deployment, production signing, live-site correctness,
or multi-region evidence.

The buildable one-shot OCI unit, secret separation, shutdown behavior, and the
evidence still required for a real regional deployment are documented in
[Regional managed-worker deployment boundary](regional-worker-deployment.md).
