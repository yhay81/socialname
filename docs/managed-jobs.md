# Managed probe jobs and observation ingestion

This boundary connects accepted managed searches and scheduled private watches
to `socialname-worker` without giving the API process network authority or
giving the worker unrestricted cross-tenant database access. Migrations
`0004_managed_probe_jobs.sql`, `0005_watch_scheduling.sql`, and
`0006_assertion_recomputation.sql`, plus `JobStore`, implement the complete
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
- the exact enabled rule version inside an active, published, unexpired pack;
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
work. Six fixed-search-path `SECURITY DEFINER` functions provide only the
minimum coordinator operations:

- `socialname_worker_resolve_rule` returns the exact currently eligible rule
  version ID;
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
SECURITY`, these six functions must be owned by a dedicated `NOLOGIN`
coordinator role with `BYPASSRLS` (or an equivalently privileged migration
owner). An ordinary table owner cannot cross forced RLS. That privileged role
owns only the reviewed coordinator boundary and is never a server or worker
runtime credential. After a coordinator function returns IDs, `JobStore` sets
`socialname.tenant_id` transaction-locally and all target, consumer,
observation, event, state, and lineage access proceeds under ordinary forced
RLS.

A deployment worker role needs schema usage, the column-limited table grants
exercised by `postgres_migrations.rs`, and execute only on those six
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
- the exact promoted rule/pack and latest fresh healthy regional record.

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
job terminal state, current `assertion/v1` generation and support, per-search
result and assertion events, watch-run target completions, watch-local baseline
or transition, terminal search/run states, and lineage edges commit in one
tenant transaction. A repeated completion of the same fenced claim returns
`already_final`; it cannot duplicate any derived output.

Observation persistence retains only typed outcome, evidence class/digest,
exact rule/region, consent/visibility, source, and bounded freshness. It does
not retain complete bodies, cookies, credentials, arbitrary headers, or
matcher traces. One coalesced observation can support multiple searches and
watch runs, but each search receives its own event UUID and sequence. Lineage
records:

- search target to job;
- job to observation;
- observation to definitive/uncertain event;
- observation to watch-run target;
- job to terminal operational-failure event.

Assertion and transition rules are specified in
[Assertion recomputation and transition persistence](assertion-recomputation.md).

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
  --promotion <promotion.json> \
  --manifest-hash <sha256> \
  --engine-hash <sha256> \
  --required-region <policy-region> \
  --previous-rule-pack-hash <active-pack-sha256> \
  --minimum-sequence-exclusive <highest-seen-sequence> \
  --key-id <trusted-key-id> \
  --verifying-key-file <public-key-hex-file> \
  --worker-id <closed-lowercase-label> \
  --lease-seconds 60 \
  --maximum-attempts 3 \
  --expansion-limit 32 \
  --allow-live
```

First promotion omits `--previous-rule-pack-hash`. `--allow-live` is checked
before rule files or the database are touched. Expansion is bounded to 1
through 128 targets, and one invocation sends at most one bounded external
request. Ctrl-C drops that request and leaves the fenced lease to expire
safely.

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
- exact rule/pack/region eligibility;
- search/watch coalescing and consent isolation;
- due-run atomicity, freshness reuse, and conservative byte reservation;
- claims, expiry reclamation, and stale-fence rejection;
- bounded retry and exhaustion;
- idempotent observation/event ingestion;
- multi-consumer fan-out and lineage;
- invalid-target separation;
- search cancellation, watch revision cancellation, consent withdrawal, and
  rule degradation before commit.

No test claims external deployment, production signing, live-site correctness,
or multi-region evidence.

The buildable one-shot OCI unit, secret separation, shutdown behavior, and the
evidence still required for a real regional deployment are documented in
[Regional managed-worker deployment boundary](regional-worker-deployment.md).
