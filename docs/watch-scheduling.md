# Freshness-aware watch scheduling

This slice makes private-history watches operable without weakening the signed
managed-worker boundary. Migration `0005_watch_scheduling.sql`, the authenticated
watch routes, and `JobStore` implement the path from a revisioned watch to a
fresh observation:

1. create and validate a tenant-private watch;
2. atomically expand a due schedule into one immutable run;
3. evaluate every target and region against exact-rule fresh observations;
4. reserve bounded work only for the remaining targets;
5. coalesce that work with an equivalent search or watch job;
6. fan one successful observation out to every still-authorized consumer.

Representative site rules remain discovery-only until their external promotion
gate passes. A watch can store such a requested site, but no managed target for
it becomes eligible while the site, signed pack, regional health, or consent
gate is closed.

## Authenticated watch lifecycle

The server implements:

```text
POST   /v1/watches
GET    /v1/watches/{watch_id}
PATCH  /v1/watches/{watch_id}
DELETE /v1/watches/{watch_id}
```

Reads require `watch:read`; mutations require `watch:write`. All access uses the
same authenticated API-key and transaction-local forced-RLS boundary as private
searches.

Creation requires an active `private_history` account-consent grant belonging
to the API key's membership, known site IDs, and one or more active
tenant-local notification endpoints. The server persists the complete stable
username/site Cartesian set. Requested usernames remain immutable;
`normalized_username` stays nullable until the exact signed site rule accepts
it.

The protocol rejects a probe budget smaller than
`usernames × sites × regions`. Patches require the current revision, recheck
consent, validate any endpoint replacement, increment the revision, and reset
the next run from the updated schedule. A stale revision returns conflict.
Pausing clears `next_run_at`; deleting is idempotent, retires targets, and keeps
the governed resource in `deleting` state rather than pretending that retained
evidence was synchronously erased.

## Atomic due-run planning

`socialname_worker_lock_due_watch` returns only one tenant/watch pair eligible
for the worker's exact rule version and region, with `FOR UPDATE SKIP LOCKED`.
After setting transaction-local tenant RLS, `JobStore::plan_one_watch`:

- locks the same active revision;
- creates one `watch_runs` row for the due `scheduled_for` instant;
- creates every active `watch_target × region_class` run target;
- reserves the complete target count against the probe ceiling;
- advances `next_run_at`;
- records watch-to-run and run-to-target lineage;
- commits all of those changes together.

The `(tenant, watch, scheduled_for)` uniqueness constraint prevents duplicate
runs. The next interval is based on database time to avoid unbounded catch-up
bursts. Its offset is a deterministic SHA-256 function of watch ID, revision,
and the prior scheduled instant, and remains inside the configured
`±jitter_percent` window. No cron text or executable scheduling expression is
accepted.

## Freshness and exact-rule reuse

`socialname_worker_lock_next_watch_target` exposes one pending target only when
the watch and run revisions still agree, consent and notification endpoints
remain active, and the exact site/rule/pack/region has fresh healthy promotion
state.

The signed rule first normalizes the requested username. Rejection completes
that run target as an operational failure without creating an observation and
without converting it to `not_found`.

A stored observation satisfies the run target only when all of these fields
match:

- tenant and normalized username;
- site and exact rule-version ID;
- region;
- the same `private_history` consent-grant ID;
- private visibility;
- managed-worker source;
- green captured rule health;
- unexpired observation lifetime;
- observed time inside the watch's maximum-age window.

An eligible observation completes the target as `satisfied`, reserves zero
bytes, and records observation-to-run-target freshness lineage. Shared evidence,
a different grant, an older rule, another region, stale data, or degraded
captured health cannot be relabelled as fresh.

## Budgets and equivalent work

When no observation satisfies freshness, the worker obtains the exact compiled
rule's worst-case inspected-byte total across its single, fallback, or
parallel plan. It atomically increments the run's reserved bytes only when the
configured ceiling still covers the complete amount. A target that cannot
reserve its amount fails before job creation and before network work. Reserved
bytes never exceed the stored maximum; freshness reuse reserves none.

The remaining probe job uses the same active-work key as private searches:

- tenant;
- normalized username;
- site;
- exact rule version;
- region;
- consent-grant ID;
- private visibility.

Therefore an equivalent private search and any number of watch-run targets
share one live job and one observation. Different grants, shared visibility,
rules, sites, regions, or normalized targets remain isolated. Each run target
has one consumer link and retains its own byte reservation and lineage.

## Completion, retries, and cancellation

The existing fenced lease, retry, rule-health, and final consent-lock rules
apply unchanged. Successful ingestion writes one immutable observation, all
still-live search events, and all still-live watch target completions in one
tenant transaction. Terminal operational failure completes search consumers
with failure events and watch consumers with failed target state. A watch run
becomes:

- `completed` when every target was satisfied or completed;
- `failed` when at least one target failed;
- `cancelled` when cancellation is present and no target remains pending.

Patch, pause, and delete increment the watch revision and atomically cancel
older pending or queued run targets. Consent withdrawal, endpoint deactivation,
rule quarantine, lease loss, or revision mismatch makes an in-flight claim
unauthorized during the worker's 250 ms recheck loop. No stale watch consumer
receives the later observation. The narrow claim coordinator prunes dead watch
consumers and cancels a job when neither a live search nor a live watch still
needs it.

## Least-privilege worker boundary

Migration `0005_watch_scheduling.sql` adds two fixed-search-path
`SECURITY DEFINER` coordinator functions:

- `socialname_worker_lock_due_watch`;
- `socialname_worker_lock_next_watch_target`.

`PUBLIC` execution is revoked. As with the four existing job functions, these
functions must be owned by the dedicated `NOLOGIN BYPASSRLS` coordinator or an
equivalent migration owner. The runtime worker remains
`LOGIN NOSUPERUSER NOBYPASSRLS`, receives no credential-table access, and uses
column-limited grants after a coordinator returns opaque IDs. The PostgreSQL
integration fixture is the executable deployment-grant manifest.

## Operator and verification

`socialname-worker process-one` now plans at most one due watch, alternates
bounded search and watch expansion, and executes at most one leased job. Its
target-free JSON adds `planned_watch_runs`; it still omits usernames, tenant,
consent, result, and database values.

The PostgreSQL 18 test proves:

- scoped watch CRUD, tenant isolation, revision conflict, and idempotent delete;
- one atomic due run and deterministic bounded advancement;
- search/watch coalescing under one consent and isolation across grants;
- exact-rule observation fan-out;
- later-run freshness reuse with zero byte reservation;
- worst-case byte reservation and pre-network budget failure;
- pause/revision cancellation of run targets and orphaned jobs;
- ordinary NOBYPASSRLS worker operation through the narrow coordinator.

The test does not claim production scheduling uptime, live-site promotion,
multi-region deployment, notification delivery, shared-client reputation
admission, or external retention evidence. Assertion recomputation and
transition persistence are covered by the next vertical slice in
[Assertion recomputation and transition persistence](assertion-recomputation.md).
