# SocialName execution roadmap

Status: **Active**

Last reviewed: 2026-07-27

Authority: `docs/ultimate-goal.md`

## How to use this roadmap

This is the canonical execution order for humans and agents. Work from the
first incomplete milestone unless a prerequisite or explicit user instruction
requires otherwise. Within that milestone, take the first incomplete item whose
prerequisites are complete.

A checked item means repository evidence exists. A milestone has two distinct
gates:

- **Software gate** — code, tests, documentation, and deployable artifacts that
  an agent can complete in the repository.
- **External evidence gate** — credentials, managed deployment, elapsed live
  measurements, signing, legal review, or production decisions that must not be
  fabricated.

An external gate keeps the affected capability disabled or quarantined. It does
not prevent independent software work in the next milestone once the software
gate is complete.

## Foundation — Rust measurement core

Status: **Software gate complete**

- [x] Rust workspace and pinned toolchain.
- [x] Observation, verdict, evidence, and `assertion/v1` domain types.
- [x] Strict declarative Site Rule v1 schema and semantic compiler.
- [x] Context-safe URL rendering, HTTPS host constraints, timeouts, redirects,
      and byte budgets.
- [x] Deterministic classifier with matcher trace and evidence digest.
- [x] Ten representative site rules and 30 minimized offline fixtures.
- [x] Local CLI rule validation, fixture validation, and explicit live probing.
- [x] Tauri 2 desktop vertical slice with local streaming and research consent.
- [x] Windows and macOS native compile CI.

Evidence:

```console
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
cargo run --locked -p socialname-cli -- fixtures
cd apps/desktop
npm run check
npm run tauri -- build --debug --no-bundle --ci
```

Current baseline: 10 rules, 30 fixture cases, deterministic pack hash. All
rules remain discovery-only pending live evidence.

## Milestone 1 — Trustworthy local product

Status: **Software gate complete; external evidence pending**

Outcome: local CLI and desktop users receive fast, source-explicit,
freshness-aware results from rules whose health is measured rather than
assumed.

Next executable item: complete signed rule-pack expiry, staged-rollout,
rollback-protection, and key-rotation metadata. The repository-completable
regional worker and region-aware assertion boundaries are implemented; real
canary/worker deployment remains an external evidence gate.
Milestone 1's software gate is complete only when both 1A and 1B software gates
pass; its external evidence gate may remain pending with affected rules safely
disabled.

### 1A. Live canary software

- [x] Define typed positive/negative canary manifests separate from site rules.
- [x] Implement a bounded canary runner using the production engine.
- [x] Emit a versioned report containing rule/engine hash, declared vantage,
      precision, conclusive coverage, latency, bytes, response classes, and
      conflicts without complete bodies.
- [x] Reject duplicate, expired, malformed, or policy-incompatible reports.
- [x] Implement aggregation across runs, vantages, and the documented 24-hour
      acceptance window.
- [x] Add shadow comparison between candidate and last-known-good rules.
- [x] Add rule-health states and safe `healthy -> degraded -> quarantined ->
      recovering` transitions.
- [x] Bind an accepted report, rule-pack hash, region policy, and expiry into a
      signed promotion artifact; verify it before activation and retain a
      last-known-good rollback path.
- [x] Ensure only an acceptance report can promote a discovery rule, and that a
      failing report cannot produce an account-state notification.
- [x] Add deterministic tests for healthy, blocked, drifting, partial-region,
      rollback, and report-tampering cases.
- [x] Add manual and scheduled canary workflow templates with strict
      concurrency, request, time, and byte budgets.

Manifest-slice evidence:

```console
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
```

The independent `socialname.dev/canary-manifest/v1` validator enforces five
reviewed positive controls, five or more generated negatives, expiry, unique
normalized identifiers, HTTPS review evidence, minimum generator entropy, and
compatibility with the compiled site username policy. No production manifests
were fabricated; the external review gate remains pending.

Runner-slice evidence:

```console
cargo test --locked --workspace --all-targets
# socialname-canary: 13 passed, including completion, request/byte preflight,
# cancellation, deadline, and rule-hash mismatch cases
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cd apps/desktop
npm ci
npm run check
npm run build
```

The runner uses the production `SearchEngine`, OS-seeded negative generation,
worst-case request and inspected-byte preflight, bounded concurrency and wall
time, cancellation with explicit partial completion, and a minimized result
surface that excludes usernames, URLs, bodies, and matcher detail. Live CLI
execution requires both an accepted manifest and `--allow-live`.

Report-slice evidence:

```console
cargo test --locked --workspace --all-targets
# socialname-canary: 25 passed, including canonical metrics, privacy-field
# exclusion, content tampering, duplicate, expiry, malformed JSON, summary
# mismatch, policy mismatch, and incomplete-run rejection
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
```

`socialname.dev/canary-report/v1` binds the manifest, rule, executing-binary
engine hash, coarse vantage, and a bounded ingestion-validity window.
Precision and conclusive coverage are exact ratios; latency, completed bytes,
response classes, and conflicts are recomputed from minimized cases. The
content hash detects modification but is explicitly not producer
authentication; signing remains a later gate.

Aggregation-slice evidence:

```console
cargo test --locked --workspace --all-targets
# socialname-canary: 29 passed, including three-region acceptance, missing
# region, insufficient-run, short-interval, precision, coverage, conflict,
# latency, and duplicate-report cases
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

`socialname.dev/canary-aggregate/v1` consumes only validator-produced report
wrappers. It requires an exact 24-hour measurement window, at least three
managed regions and three runs per region, 100% conclusive precision, at least
95% conclusive coverage, zero conflicts, and the reviewed p95 latency in every
required region. Global volume cannot hide a missing or failed region.

Shadow-slice evidence:

```console
cargo test --locked --workspace --all-targets
# socialname-canary: 35 passed, including same-private-target pairing,
# accepted parity/improvement, coverage/precision/conflict regression,
# combined-budget preflight, cancellation, tampering, and duplicate rejection
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

`socialname.dev/canary-shadow/v1` runs a candidate and last-known-good rule over
one private target set. Both sides share combined request, concurrency, time,
and byte limits. The content-addressed artifact nests independently validated
Canary Report v1 evidence and rejects lower precision or coverage, new
conflicts, and formerly correct cases that become inconclusive or incorrect.
Target usernames and profile URLs are not serialized. Shadow acceptance
supplements rather than replaces the independent aggregate thresholds.

Rule-health-slice evidence:

```console
cargo test --locked --workspace --all-targets
# socialname-domain: 11 passed, including transition, recovery, replay,
# cross-region, persisted-record, and notification-boundary cases
# socialname-canary: 40 passed, including accepted, operational,
# classification, partial-region, incompatible-evidence, and replay-stable ID
# assessments
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Regional rule-health records start quarantined. Opaque aggregator output and a
validated shadow pair produce fresh, sequence-bound health evidence. Two
distinct passes move `quarantined -> recovering -> healthy`; repeated
operational failures move `healthy -> degraded -> quarantined`; classification
failure quarantines immediately. Only healthy permits definitive assertions,
and every health transition is structurally ineligible for an account-state
notification.

Promotion-slice evidence:

```console
cargo test --locked --workspace --all-targets
# socialname-canary: 45 passed, including strict Ed25519 verification,
# non-healthy/partial/stale evidence rejection, regional drift and recovery,
# pack/predecessor mismatch, replay rejection, retained LKG, and rollback
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- canaries promote --help
cargo run --locked -p socialname-cli -- canaries verify-promotion --help
```

`socialname.dev/rule-promotion/v1` binds exact accepted regional health,
candidate and pack hashes, manifest and engine identities, predecessor,
sequence, and at-most-24-hour expiry under a domain-separated Ed25519
signature. Verification pins a purpose-specific trust policy before
activation. Activation recompiles the real pack, retains the complete prior
validated pack, and preserves its sequence high-water mark across explicit
rollback. No production key or artifact was fabricated; all representative
rules remain discovery-only.

Workflow-slice evidence:

```console
cargo test --locked -p socialname-canary workflow_contract
# parses both workflow files and verifies read-only permissions, enable gates,
# secret scope, fixed budgets, concurrency, report retention, and no promotion
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Manual and 12-hour scheduled workflows require
`SOCIALNAME_CANARY_ENABLED=true`, a protected environment, an approved
base64-encoded manifest secret, and a region-labelled self-hosted Linux runner.
They hard-code request, in-flight, wall-time, byte, workflow-timeout, overlap,
and scheduled-matrix limits. Only minimized reports are retained for three
days; aggregation, health, signing, activation, and notification remain
separate. The repository supplies no enabling variable, target matrix,
production manifest, runner, or secret.

Software acceptance gate:

- The runner and aggregator reproduce the live gate in
  `docs/site-rule-v1-validation.md`.
- A synthetic multi-vantage test demonstrates promotion, regional quarantine,
  drift detection, and rollback.
- Real rules remain disabled unless real external reports satisfy the gate.

External evidence gate:

- Five reviewed positive and five valid generated-negative canaries per site.
- Three managed regions, three runs each over at least 24 hours.
- All precision, coverage, safety, latency, and shadow requirements in the
  representative validation document.
- A signed publication and last-known-good rollback exercise.

### 1B. Local cache and source policy

- [x] Add `socialname-cache` with embedded SQLite migrations.
- [x] Persist immutable local observations and cache metadata, not just the
      latest boolean result.
- [x] Key eligibility by normalized username, site, region class, rule hash,
      verdict policy, and freshness.
- [x] Implement pruning, maximum-size behavior, corruption recovery, export,
      and complete local deletion.
- [x] Add CLI `local` and `cache` modes plus independent `sync=never`.
- [x] Show source, observed time, expiry, rule hash, and refresh state in normal
      and machine-readable CLI output.
- [x] Expose the same cache/source policy through `socialname-app-core` and the
      desktop application.
- [x] Stream an eligible cached result immediately while clearly marking any
      subsequent local refresh.
- [x] Add deterministic cache-hit, stale, rule-change, negative-TTL,
      cancellation, pruning, migration, and deletion tests.

Software acceptance gate:

- The CLI and desktop work offline from eligible cached observations.
- Cached results are never represented as live.
- Default execution remains local with no network call to SocialName.
- Cache corruption or migration failure cannot silently produce a verdict.

Migration-slice evidence:

```console
cargo test --locked -p socialname-cache
# 5 passed: initialization, idempotent reopen, foreign/future/corrupt refusal,
# immutable rows, and explicit deletion
cargo clippy --locked -p socialname-cache --all-targets --all-features -- -D warnings
```

The initial cache slice embedded schema v1 and identified its database with a
dedicated SQLite application ID; schema v2 now adds desktop producer lineage.
Opening refuses foreign, future, and corrupt databases before producing a cache
handle, applies migrations idempotently, enables WAL only after
ownership/version preflight, and preserves complete immutable observation
fields separately from mutable cache metadata.

Persistence-slice evidence:

```console
cargo test --locked -p socialname-cache
# 10 passed: complete typed round trip, initial metadata, exact replay,
# immutable-ID conflict, transactional rollback, missing metadata, and the
# migration/opening cases above
cargo clippy --locked -p socialname-cache --all-targets --all-features -- -D warnings
```

`store_observation` validates typed domain values and atomically inserts the
complete immutable observation with its initial cache metadata. Exact replay is
idempotent; different content under one observation ID is an explicit conflict
that preserves the original. `get_observation` reconstructs the closed domain
types and distinguishes a real miss from incomplete or invalid stored data.
Selection and access accounting are defined by the eligibility evidence below.

Eligibility-slice evidence:

```console
cargo test --locked -p socialname-cache
# 16 passed: exact-key hit, target/site/region/rule misses, current and captured
# rule health, verdict policy, expiry, maximum age, negative TTL, access
# accounting, invalid query, and fail-closed result-set bound
cargo clippy --locked -p socialname-cache --all-targets --all-features -- -D warnings
```

`eligible_observations` requires the exact normalized target, region class,
rule hash, current healthy regional state, evaluation time, maximum age, and
verdict policy. It also requires captured green health and the observation's
own unexpired TTL. It returns the complete deterministic matching set instead
of selecting a latest boolean, updates access metadata only for successful
hits, and fails rather than truncating above 256 observations so conflicts
cannot be hidden.

Maintenance/lifecycle-slice evidence:

```console
cargo test --locked -p socialname-cache
# 30 passed: expiry-first/LRU pruning, count and logical-byte limits,
# deterministic create-new export, full integrity checks, corrupt quarantine,
# healthy/foreign/unowned/future refusal, and database/sidecar deletion
cargo clippy --locked -p socialname-cache --all-targets --all-features -- -D warnings
```

Maintenance enforces nonzero observation-count and deterministic logical
payload-byte limits, deleting expired rows before LRU capacity rows and
reporting before/after quantities. Versioned JSONL export snapshots complete
typed observations and metadata without overwriting an existing file.
Recovery never silently trusts salvage: corrupt current files are retained
under an adjacent quarantine before creating an empty cache, while healthy,
foreign, nonempty unowned, and future databases are preserved and refused.
Complete deletion closes the pool and removes journal, SHM, WAL, and main
files, reporting any partial failure.

CLI-source-slice evidence:

```console
cargo test --locked -p socialname-cli
# 6 passed: default local/never parsing, explicit cache mode, unsupported sync
# and hybrid rejection, no-engine cache hit/miss/health/promotion paths, and
# verdict TTLs
cargo clippy --locked -p socialname-cli --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- search --help
# source values: local, cache; sync values: never
cargo run --locked -p socialname-cli -- search octocat --site github \
  --source cache --sync never --cache-path <absent-path> --json
# source=cache, status=rule_not_promoted, refresh_state=not_requested;
# no cache file created and no network engine constructed
```

The default remains a local probe with `sync=never`. `cache` requires an
explicit path and never falls through to network execution. Cache reuse
requires a promoted exact rule plus a fresh matching regional health record;
all ten discovery-only repository rules remain disabled even if a health file
is supplied. Human and JSON envelopes distinguish cached observations from
live results and expose sync, status, refresh, promotion, health, rule hash,
observed time, expiry, evidence, and region. Optional local persistence uses
verdict-specific 24-hour found, 15-minute not-found, and 5-minute inconclusive
TTLs; invalid usernames are not stored.

App-core/desktop-source-slice evidence:

```console
cargo test --locked -p socialname-domain -p socialname-cache \
  -p socialname-app-core -p socialname-cli
# socialname-cache: 31 passed, including data-preserving schema-v1-to-v2
# migration and local_cli/local_desktop producer round trips
# socialname-app-core: 13 passed, including no-probe discovery status, a
# complete multi-observation offline cache hit, cached-first ordering, and
# cancellation before local refresh
cargo clippy --locked -p socialname-domain -p socialname-cache \
  -p socialname-app-core -p socialname-cli --all-targets --all-features \
  -- -D warnings
cargo test --locked -p socialname-app-core -p socialname-desktop
cd apps/desktop
npm run check
npm run build
```

`socialname-app-core` now owns the closed `local|cache` source and `sync=never`
policy types used by CLI and desktop. Its site-level result envelope keeps the
full eligible cached observation set separate from an optional live result and
reports source, status, refresh, promotion, regional health, observed time,
expiry, and exact rule identity. The Tauri shell resolves and opens a fixed
application-local cache without exposing its path or filesystem/database
capabilities to the webview. Cache initialization failure disables only cache
mode and cannot become a verdict. Local remains the default; cache never falls
through to a probe. No production promotion or health evidence is embedded, so
all repository rules remain safely `rule_not_promoted`. Schema v2 distinguishes
desktop producer lineage while preserving schema-v1 observations and metadata.

Cached-first/final software-gate evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
```

Desktop `hybrid` emits one cache phase before invoking the local executor and
then replaces it with a separately labelled local-refresh phase. The result
envelope distinguishes requested mode from each event and observation's actual
`cache` or `local` origin. A dropped event channel after the cache phase is
checked before executor invocation, so cancellation retains cached evidence
without starting a probe. Runtime cache failure is a typed non-verdict phase.
CLI `hybrid` is rejected until the CLI has a versioned event-stream contract;
its supported `local` and `cache` behavior is unchanged.

The cache suite deterministically covers exact hits, stale observations, rule
hash changes, verdict-specific negative TTL, pruning, the data-preserving
schema-v1-to-v2 migration, and complete database/sidecar deletion. App-core
adds the cache-before-local and cancellation paths. Together these satisfy the
1B software gate without weakening the still-pending external live-rule gate.

## Milestone 2 — First paid monitoring loop

Status: **Software gate complete; external evidence pending**

Outcome: a user can create a watch, the managed system observes it over time,
derives a trustworthy transition, and delivers one auditable notification.

- [x] Add `socialname-protocol` for versioned API, event, error, source,
      freshness, watch, transition, and notification DTOs.
- [x] Add a Rust modular-monolith `socialname-server` using Axum/Tower.
- [x] Add PostgreSQL migrations for tenants, credentials, sites, rule versions,
      searches, jobs, observations, assertion support, watches, transitions,
      notification endpoints, deliveries, consent, lineage, and deletion tasks.
- [x] Add authenticated private workspaces and hashed, scoped API keys.
- [x] Implement idempotent search creation and SSE partial-result streaming.
- [x] Add `socialname-worker` with signed-artifact-only execution and managed-probe
      SSRF/DNS-rebinding defenses.
- [x] Implement transactional PostgreSQL job claims, leases, retries, and
      idempotent observation ingestion.
- [x] Implement freshness-aware watch scheduling and equivalent-work
      coalescing.
- [x] Recompute `assertion/v1`, persist meaningful transitions, and distinguish
      account change from measurement degradation.
- [x] Deliver a deduplicated signed webhook with retry, dead-letter state, and
      audit history.
- [x] Add a minimal monitoring UI without weakening the API boundary.
- [x] Provide one end-to-end test: watch creation -> managed observation ->
      assertion change -> transition -> exactly-once logical notification.

Protocol-slice evidence:

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-protocol
# 30 unit tests and 7 public contract tests passed
cargo clippy --locked -p socialname-protocol --all-targets --all-features -- -D warnings
```

`socialname-protocol` owns the independent
`socialname.dev/api/v1` closed wire contract and Draft 2020-12 schema roots.
It does not serialize mutable domain or app-core types directly. Search events
separate definitive observations, uncertainty, and operational failure; actual
source and derived freshness remain explicit. Requests are bounded, reject
unknown fields, and require purpose-specific grants for private/shared sync.
Usernames and notification destinations redact `Debug`, error DTOs never echo
values or raw response data, and endpoint resources do not return destinations.
Closed transition confirmation rules keep measurement degradation outside
account state, make shared-only absence non-deliverable, and allow notification
delivery construction only from a validated confirmed transition. Watch
schedule, budget, retention, revision, and next-run relations are deterministic
and validated without arbitrary cron or code.

Server-runtime evidence:

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-server --all-targets
# 26 library, 2 binary, and 1 PostgreSQL integration test passed
cargo clippy --locked -p socialname-server --all-targets --all-features -- -D warnings
cargo build --locked -p socialname-server
```

`socialname-server` is an explicit Axum 0.8/Tower 0.5 binary with a
loopback-only default. It exposes versioned liveness, PostgreSQL-aware
readiness, authenticated workspace/search/watch resources, polling,
cancellation, and bounded ordered SSE. Webhook delivery has a separate bounded
worker entry point; notification endpoint and delivery administration HTTP
routes remain absent. Configuration bounds the handler deadline,
declared/default body size, database acquisition, ordinary in-flight work, and
open SSE bodies, and rejects invalid values without echoing them. One outer
request guard supplies a closed request ID, protocol JSON errors, no-store and
nosniff response headers, and method/status/latency-only tracing that never
logs the URI, headers, body, target, credential, or database URL. Unknown
routes, unsupported methods, body overflow, invalid content length,
authentication/consent failure, storage failure, and deadlines cannot become
account verdicts. The binary drains through injected graceful shutdown,
Ctrl-C, and Unix SIGTERM.

PostgreSQL-schema evidence:

```console
cargo fmt --all -- --check
cargo run --locked -p socialname-server -- migrate
cargo test --locked --workspace --all-targets
# socialname-server: 26 library, 2 binary, and 1 PostgreSQL integration test passed
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
```

The twelve embedded SQLx migrations create 45 bounded product tables and 35
tenant-isolation policies with forced RLS. Composite tenant foreign keys,
immutable observation and support history, closed observation outcomes,
transition-specific confirmation bases, exact confirmed-delivery checks,
encrypted notification destinations, ordered deletion deadlines, receipts,
lineage, and HMAC-only suppression tokens preserve the trust and privacy
boundaries. A separate `migrate` command requires an explicit schema-owner
database URL, uses one connection with connection/migration deadlines, and
returns fixed errors without reflecting credentials.

The CI core job runs both the operator command and an integration test against
`postgres:18-alpine`. The test reapplies all twelve migrations, inventories all
tables and forced-RLS policies, uses a real non-owner `NOBYPASSRLS` role to
prove tenant isolation, rejects cross-tenant references and observation
mutation, suppresses shared-only absence delivery, accepts an independently
confirmed delivery, and checks deletion deadlines, receipts, and lineage.

Authenticated-workspace evidence:

```console
cargo fmt --all -- --check
cargo run --locked -p socialname-server -- migrate
cargo test --locked -p socialname-protocol -p socialname-server --all-targets
# protocol: 33 unit + 7 contract; server: 26 library + 2 binary + 1 PostgreSQL
cargo clippy --locked -p socialname-protocol -p socialname-server --all-targets --all-features -- -D warnings
```

API keys have an independent 64-bit CSPRNG prefix and 256-bit CSPRNG secret.
Only a SHA-256 digest is stored in the restricted global lookup; the presented
key is one-time output and redacted from ordinary formatting and errors. A
closed, duplicate-free scope set is enforced by protocol validation and
PostgreSQL. Transactional operator commands create an owner workspace, issue
keys only for active owner/administrator memberships, revoke keys, and append
audit events without leaving partial state.

The runtime uses a separate non-owner role with no direct credential-table
access and column-limited update permission for `api_keys.last_used_at`.
Authentication performs only the prefix/digest lookup before the tenant is
known, then rechecks active tenant, key state, expiry, and exact route scope
under transaction-local forced RLS. The PostgreSQL 18 test proves two-tenant
isolation, wrong/revoked/expired uniform denial, distinct insufficient-scope
denial, digest-only persistence, privilege revocation, last-use recording, and
readiness degradation. `GET /v1/workspace` returns validated nonsecret
workspace/key metadata; later notification and governance routes remain
closed.

Private-search/SSE evidence:

```console
cargo fmt --all -- --check
cargo run --locked -p socialname-server -- migrate
cargo test --locked -p socialname-protocol -p socialname-server --all-targets
# PostgreSQL 18 covers REST creation/poll/cancel and three ordered SSE events
cargo clippy --locked -p socialname-protocol -p socialname-server --all-targets --all-features -- -D warnings
```

`POST /v1/searches` requires `search:write`, one redacted idempotency key,
`remote`/`hybrid`, and an active account consent grant with the exact
`private_history` or `shared_observation` purpose. The server rejects
`sync=never` because posting the target already leaves the device. It stores
only the tenant-scoped idempotency digest; concurrent/exact replay returns the
original search and changed content conflicts. Requested usernames remain
distinct from nullable, later site-normalized values.

Creation atomically persists search policy, stable Cartesian targets, and a
validated `started` event. `GET` polls a validated resource, while idempotent
`DELETE` cancellation appends one terminal event without pretending to erase
governed data. Append-only `search_events` enforce tenant/search sequence,
event JSON identity, target-bound result uniqueness, at most one started and
finished event, and a 128 KiB payload limit; public terminal reads require the
finished event.

The SSE endpoint orders by persisted sequence, resumes strictly after a
same-tenant/search `Last-Event-ID`, rechecks key state and `search:read` during
polling, distinguishes transport `stream_error` from target outcomes, and
bounds batch, polling, lifetime, keep-alive, and connection count. The
PostgreSQL 18 test proves exact/conflicting replay, scope and consent denial,
target-free errors, two-tenant isolation, digest-only storage, ordered partial
and terminal replay, resume, append-only rejection, cancellation uniqueness,
column-limited privileges, and connection-cap recovery. The API process itself
still performs no probe; eligible accepted searches are connected through the
separate signed worker and discovery-only rules remain quarantined.

Signed-managed-worker evidence:

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-engine -p socialname-worker --all-targets
# engine: 11; worker: 16 library + 5 binary tests
cargo clippy --locked -p socialname-engine -p socialname-worker --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-worker -- --help
# probe without --allow-live exits before reading files or stdin
```

`ManagedRule` can be constructed only from an opaque verified Ed25519
promotion and the exact compiled pack. Activation rechecks region, promotion
and evidence time, recompiles the complete pack, and binds its candidate to the
signed site/rule/pack hashes. Execution rechecks expiry and gives cancellation
priority before polling the network future. The one-shot binary requires an
explicit live acknowledgement, reads one bounded closed stdin JSON target
instead of accepting it in process arguments, and emits only a minimized
result.

The managed engine uses a separate proxy-free client and a custom Reqwest
resolver. Every new connection resolves to concrete addresses, rejects empty,
oversized, mixed, private, loopback, link-local, metadata, transition,
documentation, multicast, and reserved answers, and therefore cannot rebind
from a public answer to a forbidden destination. Initial and redirected URLs
still require HTTPS and the signed rule's exact host allowlist. Parsed header
names and values, streamed compressed bytes, decoded bytes, and inspected text
have independent rule bounds; size/decode/DNS failures remain operational and
cannot become absence.

Managed-job evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes 26 server library, 2 server binary,
# 14 worker library, and 4 worker binary tests
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# With the three documented disposable PostgreSQL test URLs:
cargo test --locked -p socialname-server --test postgres_migrations -- --nocapture
# 1 PostgreSQL 18 integration test passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
```

Migrations `0004_managed_probe_jobs.sql`, `0005_watch_scheduling.sql`,
`0006_assertion_recomputation.sql`, and `0009_rule_pack_distribution.sql`,
plus `JobStore`, bind the exact signed
metadata/promotion/site/rule/pack/region to promoted, active, fresh-healthy
registry state. A non-owner NOBYPASSRLS worker uses seven narrow managed-probe
coordinator functions, then
returns to transaction-local tenant RLS. Expansion normalizes through that
rule, keeps invalid targets outside absence, and coalesces only equal tenant,
target, rule, region, consent grant, and visibility scopes.

Claims increment an attempt fence; expired leases can be reclaimed while stale
attempts cannot commit. Operational failures use bounded exponential retry.
Execution continuously rechecks live search/watch consumers,
purpose-specific consent, watch revision/endpoints, and rule health, and final
ingestion locks consent. One transaction writes at most one immutable
observation, current assertion generation and support, per-search result and
assertion events, watch-local baseline or transition, search/watch target and
terminal state, and lineage; replay is `already_final`. The PostgreSQL 18 test
proves search/watch coalescing and purpose isolation, claim/reclaim, stale
fencing, retry exhaustion, multi-consumer fan-out, cancellation, consent
withdrawal, rule degradation, invalid targets, and least-privilege RLS.

`socialname-worker process-one` is the bounded operable entry point: it plans
at most one due watch, alternates search/watch expansion for at most 128
targets, claims and executes at most one job, requires `--allow-live` before
file/database access, and emits a target-free status object. Due runs expand
atomically with deterministic jitter and a complete probe-count reservation.
Each target reuses only exact-rule, same-consent, private, fresh healthy
evidence; otherwise it reserves the compiled rule's worst-case inspected bytes
before coalescing into an equivalent active job. Pause, delete, revision
change, consent withdrawal, endpoint deactivation, and rule quarantine prevent
stale fan-out. Representative rules still cannot execute because their
external promotion evidence is absent.

Assertion/transition evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes domain assertion replay, protocol transition validation,
# 10 worker derivation/job tests, and the PostgreSQL integration test
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# With disposable PostgreSQL 18 administrator/application/worker URLs:
cargo test --locked -p socialname-server --test postgres_migrations -- --nocapture
# 1 PostgreSQL 18 integration test passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
```

The worker serializes each tenant target with a length-framed advisory key and
derives `assertion/v1` only from current strong exact-rule observations backed
by active consent. Changed evidence creates a new current generation with
append-only support and lineage; managed searches receive the same
`assertion_updated` interpretation. A watch target's first eligible assertion
establishes its own baseline without a transition. Later account candidates
use the closed E4/E3-follow-up appearance and independent-region/time-separated
disappearance bases; shared-only absence remains suppressed.

Opposing fresh strong observations produce `conflicted` and cannot move the
account baseline. Typed uncertainty creates a distinct regional
`measurement_health` degradation, while terminal operational failure creates
`unavailable` from probe-job lineage without fabricating an observation. The
PostgreSQL 18 test proves all of these paths under the real non-owner
NOBYPASSRLS worker, including exact fresh-evidence replay and unchanged account
state through degradation. Confirmed transitions are consumed only by the
separate signed delivery boundary.

Signed-webhook evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes protocol webhook construction, managed outbound policy,
# worker crypto/retry/dedupe tests, and the PostgreSQL integration test
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# With disposable PostgreSQL 18 administrator/application/worker URLs:
cargo test --locked -p socialname-server --test postgres_migrations -- --nocapture
# 1 PostgreSQL 18 integration test passed
cargo run --locked -p socialname-cli -- rules validate
cargo run --locked -p socialname-cli -- fixtures
cd apps/desktop
npm ci
npm run check
npm run build
```

Migration `0007_webhook_delivery.sql` adds fenced one-through-ten-attempt
claims, append-only attempt history, lease-expiry reclamation, and terminal
dead-letter state under the same non-owner forced-RLS worker boundary. A
confirmed transition transaction inserts at most one SHA-256 logical delivery
per tenant/transition/endpoint; every retry reuses its stable delivery ID and
body. HTTP is intentionally at least once, so receivers deduplicate that ID
rather than relying on an impossible exactly-once transport claim.

The worker reconstructs the typed confirmed transition, signs the bounded JSON
body with versioned HMAC-SHA-256 headers, and decrypts only an
endpoint-bound XChaCha20-Poly1305 destination envelope. The proxy-free,
redirect-free managed client accepts HTTPS public destinations only, applies
the existing DNS-rebinding/SSRF rejection policy, bounds connection/request
time and headers/body, and discards response bodies. Retryable HTTP/transport
failure uses bounded exponential backoff; permanent 4xx, endpoint
deactivation, stale workers, and final lease expiry have distinct outcomes.

The PostgreSQL 18 test proves the complete managed-observation -> assertion ->
confirmed-transition -> logical-delivery path, timeout then same-ID success,
permanent 4xx, stale-lease fencing, lease-exhaustion dead letter, audit, and
delivery/attempt lineage without persisting destination or body content.
External destination ownership verification and production key management
remain pending; absent keys or an encrypted verified active endpoint keep
delivery disabled.

Monitoring-console evidence:

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-protocol -p socialname-server --all-targets
cargo clippy --locked -p socialname-protocol -p socialname-server --all-targets --all-features -- -D warnings
# With disposable PostgreSQL 18 administrator/application/worker URLs:
cargo test --locked -p socialname-server --test postgres_migrations -- --nocapture
# 1 PostgreSQL 18 integration test passed
cd apps/console
npm ci
npm test
# 2 deterministic model tests passed
npm run check
npm run build
```

Two closed API v1 pages list watches and a selected watch's transition timeline
through `watch:read`. UUID keyset cursors are validated inside the same
tenant-scoped transaction; pages are capped at 50 and keep account changes,
measurement health, confirmation, delivery retry, success, and dead letter as
distinct typed state. The PostgreSQL 18 test proves scope enforcement,
cross-tenant empty/not-found behavior, cursor continuation, and absence of
destination, signature, body digest, worker, and audit data from the response.

The React/TypeScript/Vite console consumes only same-origin `/v1` routes. It
holds a pasted scoped key only in page memory, makes no CORS/direct-database
path, creates and revision-updates watches, and presents loaded-page metrics
without claiming global totals. Topcoat 0.4.0 was evaluated at the replaceable
UI boundary and rejected for this slice because its experimental direct-data
model would duplicate the established Axum authorization/RLS boundary. Hosted
TLS, CSP, session authentication, endpoint ownership, and production
accessibility evidence remain external. See
[`docs/monitoring-console.md`](docs/monitoring-console.md).

Software acceptance gate:

- The complete loop runs locally against PostgreSQL and a controlled mock site.
- Replays, worker crashes, retries, conflicts, stale data, and rule quarantine
  do not create duplicate or false account transitions.
- Every transition and delivery is traceable to its supporting observations.
- No billing, multi-region claim, or production SLA is required for this gate.

External evidence gate:

- Managed deployment credentials and at least one approved region.
- Notification-domain configuration and destination verification.
- Production retention, abuse, acceptable-use, and incident-response review.

## Milestone 3 — Trust, governance, and multi-region operation

Status: **Current; external deployment evidence pending**

- [ ] Deploy managed canaries and workers in the required regions.
- [x] Add region-aware assertions, conflict escalation, and managed
      confirmation of high-value transitions.
- [x] Implement signed rule-pack metadata, expiry, staged rollout, rollback
      protection, and key rotation.
- [x] Implement versioned purpose-specific consent grants for private history,
      shared observation, and shared research.
- [x] Store bounded Evidence Capsules and enforce the accepted retention
      schedule.
- [x] Implement lineage-backed contributor deletion and target-person request
      workflows.
- [x] Add daily delete-through tests, deletion receipts, restore-ledger replay,
      and backup-expiry verification.
- [x] Add notification acknowledgement, email delivery, operational dashboards,
      and SLO reporting.

Regional deployment software evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes worker: 16 library + 5 binary + 3 deployment-contract tests
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
docker build --file deploy/worker/Dockerfile \
  --tag socialname-worker --build-arg VCS_REF=<source-revision> .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges=true socialname-worker --help
docker image inspect socialname-worker
```

The provider-neutral image build uses digest-pinned Dockerfile, Rust, and
Debian inputs; compiles the locked release worker; carries the exact site-rule
pack; runs as `10001:10001`; declares `SIGTERM`; and defaults to `--help`.
Hardened `--network none` smoke tests proved the binary and embedded rules are
readable as that UID and that `process-one` without `--allow-live` exits before
metadata, trust-root, or database access. Linux `SIGTERM` now cancels the same
token as Ctrl-C during managed execution, leaving a fenced lease to expire
safely.
CI builds and smoke-tests the image but has no registry login or push path.
Quality run
[`30193340211`](https://github.com/yhay81/socialname/actions/runs/30193340211)
passed Rust core, Windows/macOS desktop, monitoring console, and the new
managed-worker OCI job for commit `e2bc7fd`.

The deployment item remains unchecked: no registry artifact, approved regional
vantage, managed database credential, production-trusted rule-pack metadata,
egress policy, or live cancellation observation exists. The exact evidence
needed to close it is recorded in
[`docs/regional-worker-deployment.md`](docs/regional-worker-deployment.md).
Repository work can therefore continue independently with region-aware
assertion behavior without claiming a regional service.

Regional assertion software evidence:

```console
cargo test --locked -p socialname-domain -p socialname-protocol -p socialname-worker
# domain: 13; protocol: 33 unit + 7 contract; worker: 16 library,
# 5 binary, and 3 deployment-contract tests passed
cargo clippy --locked -p socialname-server -p socialname-worker \
  --all-targets --all-features -- -D warnings
# passed
# With disposable PostgreSQL 18 administrator/application/worker URLs:
cargo test --locked -p socialname-server --test postgres_migrations
# 1 PostgreSQL 18 integration test passed
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# all passed
```

`assertion/v1` now derives and validates a regional projection from the same
eligible exact-rule observations as the global assertion. Migration `0008`
stores immutable regional generations and support with observation ->
regional -> global lineage. A `jp` `found` and `us` `not_found` remain two
definitive regional assertions behind one globally `conflicted` result; the
watch account baseline and delivery stream do not move. New events carry the
projection while historical JSON remains readable without inferred regions.
Already-budgeted watch jobs use generated `routine` (0),
`account_confirmation` (50), and `regional_conflict` (100) priority reasons;
the worker raises only queued/retry work and never invents a probe, region, or
deployment claim. The real PostgreSQL 18 test proves both elevated paths,
their existing probe/byte reservations, forced RLS, lineage, and event output.
Quality runs
[`30193989488`](https://github.com/yhay81/socialname/actions/runs/30193989488)
and
[`30194494587`](https://github.com/yhay81/socialname/actions/runs/30194494587)
passed Rust core, Windows/macOS desktop, monitoring console, and managed-worker
OCI jobs for commits `ddd73b1` and `0761ca3`.

Signed rule-pack distribution software evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes canary: 49; server: 26 library + 2 binary;
# worker: 16 library + 5 binary + 3 deployment-contract tests
# With disposable PostgreSQL 18 administrator/application/worker URLs:
# 1 PostgreSQL 18 integration test passed
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# all passed
```

`socialname.dev/rule-pack-metadata/v1` now threshold-signs one exact pack,
predecessor, required regions, rollout stage, candidate public trust, and all
embedded site promotions with at-most-24-hour validity. The pure serializable
registry enforces global and per-site sequence floors, canary/regional
monotonic widening, general activation, retained last-known-good state, and
signed exact-predecessor rollback. Trust rotation advances exactly one
generation and requires both current and candidate thresholds; a candidate
root stays staged until general activation or rollback so active workers
remain restartable during evaluation.

The CLI prints public trust IDs and signs or independently verifies metadata
against exact local pack bytes. Migration `0009` stores public trust history,
signed metadata, site bindings, active/staged/LKG state, and both replay
floors. The transactional `apply-rule-pack` operator requires an out-of-band
initial trust pin, cross-checks redundant persisted state, and enables only
active unexpired general/rollback versions. Managed workers bind site, rule,
pack, region, metadata ID/sequence, and promotion ID/sequence, then
continuously recheck current registry authority and health.

The real PostgreSQL 18 gate applies canary and general metadata, rejects a
persisted replay, stages an overlapping trust generation without displacing
the active root, activates a replacement pack, removes the old key through a
second dual-threshold transition, signs rollback to the retained pack, rejects
the stale worker binding, and accepts the rollback binding. Synthetic keys are
test-only. Production key custody, threshold ceremony, artifact distribution,
regional observation, and rollback exercise remain external deployment
evidence and do not make any representative rule promoted.
Quality run
[`30198577351`](https://github.com/yhay81/socialname/actions/runs/30198577351)
passed Rust core, Windows/macOS desktop, monitoring console, and the corrected
managed-worker OCI metadata/trust smoke for commit `6efb5ef`.

Purpose-specific consent software evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes protocol: 36 unit + 8 wire-contract tests;
# server: 28 library + 2 binary tests;
# with disposable PostgreSQL 18 administrator/application/worker URLs:
# 1 PostgreSQL 18 integration test passed
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# all passed
```

Public API v1 now has closed `consent:read` and `consent:write` scopes and
versioned create, bounded keyset-list, read, and withdrawal resources. Each
grant binds account or installation subject, one of the three independent
purposes, `profile-v1`, and `notice-v1`. Account identity comes only from the
active API-key membership. Installation input is redacted, persisted only as
a tenant-separated SHA-256 digest, and locked to its first consent-owning
membership; even another workspace administrator cannot override it.

Migration `0010` closes the accepted contract, adds the installation owner
relation, protects every grant field except the one-way null-to-timestamp
withdrawal, and retains append-only actor events. Concurrent exact creation is
serialized and returns the same active grant; an expired or withdrawn grant is
never revived. The real PostgreSQL 18 test proves all purposes and both
subjects, tenant/owner isolation, bounded foreign-cursor rejection, exact
replay, immutable history, replacement grants, and that a managed search is
accepted immediately before withdrawal and forbidden immediately afterward.
Quality run
[`30201766719`](https://github.com/yhay81/socialname/actions/runs/30201766719)
passed Rust core with PostgreSQL migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `04f60e4`.

Withdrawal deliberately makes no prior-contribution deletion claim. The
lineage-backed deletion item remains next in its recorded order; it will add
the delete option only when the system can process and receipt the documented
deadlines. The complete boundary is in
[`docs/consent-api.md`](docs/consent-api.md).

Bounded Evidence Capsule and retention software evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes protocol: 39 unit + 9 wire-contract tests;
# server: 29 library + 2 binary tests;
# worker: 18 library + 5 binary + 3 deployment-contract tests
# with disposable PostgreSQL 18 administrator/application/worker URLs:
# 1 PostgreSQL 18 integration test passed
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- canaries validate
# validated 0 canary manifests; 10 site rules remain discovery-only
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# all passed
```

Public protocol v1 now includes the exact
`socialname.dev/evidence-capsule/v1` resource and independent `evidence:read`
scope. One successful managed observation commits atomically with a closed
64 KiB Capsule containing only typed outcome, exact signed provenance, coarse
vantage, sanitized probe summaries, and bounded rule-generated matcher traces.
There is no field for complete bodies, arbitrary headers, cookies, credentials,
client IP, or unrelated profile data.

Migration `0011` binds each Capsule one-to-one to its observation under forced
tenant RLS. Database time determines visibility and the accepted retention
deadline: private interactive 90 days, private watch 30–730 days, the longest
live coalesced consumer, or exactly 400 days for shared structure. Research
excerpt storage is capped at 2 KiB and 30 days but has no current ingestion
path. The explicit worker command clears due research and structured payloads
in bounded `SKIP LOCKED` batches, leaves payload-free three-year receipts, and
reports only counts.

The real PostgreSQL 18 test proves atomicity and lineage, signed engine
provenance, scoped and cross-tenant reads, expiry hiding before cleanup,
immutable deadlines, least privilege, one-row batching, research-before-
structure purge, payload-free receipts, and idempotent replay. Capsule expiry
does not falsely claim removal of the existing immutable observation summary
or its derived support. Those production-data guarantees remain the next
lineage-backed deletion item. Production retention scheduling, alerting, and
regional evidence remain external. The complete boundary is in
[`docs/evidence-capsule-v1.md`](docs/evidence-capsule-v1.md).
Quality run
[`30206607492`](https://github.com/yhay81/socialname/actions/runs/30206607492)
passed Rust core with PostgreSQL migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `663f04f`.

Lineage-backed deletion software evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes protocol: 41 unit + 10 contract; server: 34 library + 2 binary
# + 1 real PostgreSQL 18 integration; worker: 20 library + 5 binary
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# all passed
```

Protocol v1 now exposes a selector-free contributor request and deletion
resource with exact 5-minute, 1-hour, 24-hour, 7-day, and 35-day deadline
relations. The `data:delete` API accepts only an owned account or installation
grant, serializes exact replay, withdraws every active grant for the same
subject/purpose, materializes lineage tombstones, immediately hides reads, and
cancels/redacts active jobs and deliveries. Owner-only status reads cannot
cross a membership or tenant boundary.

Migration `0012` adds `deletion_resource_matches`, monotonic request/match
progress, target/job redaction, suppression-key fingerprinting, and a fenced
cross-tenant deletion claim. The non-owner worker removes support, recomputes
from remaining observations, withdraws sole-support assertions, deletes
current PostgreSQL primary dependencies atomically, and leaves the request
`rebuilding`. Replays are idle and target-bearing job/search fields remain
redacted receipts.

Target-person intake is an externally verified, bounded stdin schema-owner
command rather than self-asserted HTTP. It stores only a verification-reference
digest and tenant-separated HMAC identities, groups exact shared matches
across tenants, retains identical private observations for explicit controller
routing, and returns the same IDs even after primary purge. Target suppression
is checked before network, during execution, and before commit; a future shared
job creates no observation and terminates its search with a redacted `blocked`
event. Active legacy/different suppression-key fingerprints fail closed rather
than silently disabling prior erasure.

The real PostgreSQL 18 gate reapplies the migrations and inventories the
current schema. It proves immediate physical-row
hiding, exact deadlines/replay, scope isolation, support-by-support
recomputation, primary purge, shared/private target separation, future
reingestion suppression, key-mismatch refusal, least privilege, and
idempotency. The complete boundary is in
[`docs/deletion-workflows.md`](docs/deletion-workflows.md).
Quality run
[`30209676004`](https://github.com/yhay81/socialname/actions/runs/30209676004)
passed Rust core with PostgreSQL 18 migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `073e7e1`.

Delete-through, receipt, restore, and backup-expiry software evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes protocol: 42 unit + 11 contract; server: 36 library + 2 binary
# + 1 real PostgreSQL 18 integration; worker: 20 library + 5 binary
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# all passed
```

Migration `0013` brings the schema to 48 product tables and 36 forced-RLS
policies. Primary deletion now completes the current PostgreSQL derived
projection task in the same transaction. The `data:delete` receipt endpoint
returns exactly primary/derived/backup state, deadlines, completion times, and
remaining backup expiry; it cannot report final completion without an
append-only database receipt.

The backup operator rejects execution before the 35-day database deadline,
before primary/derived completion, or while the bounded inventory can still
restore data from at or before primary completion. It stores only opaque
evidence digests and creates the backup task completion, receipt, and request
completion atomically with exact replay.

The restore operator exports an HMAC-authenticated, target-free ledger and
replays suppression, contributor withdrawal, lineage hiding, and job/delivery
redaction locally before commit. A restored runtime configured with the exact
expected ledger ID remains `not_ready` until replay succeeds. Different keys,
tampering, missing tenants, excessive input, and same-ID/different-artifact
replay fail closed.

`.github/workflows/deletion-drill.yml` schedules the deterministic PostgreSQL
18 delete-through and restore drill every day and allows an explicit manual
run. Local PostgreSQL 18 proves completed receipts, premature-inventory
refusal, exact backup replay, target-free artifact shape, restored-row hiding,
exact restore replay, and readiness quarantine. Hosted schedule execution
history, production backup-provider inventory completeness, and elapsed
5-minute/1-hour/24-hour/7-day/35-day production SLA evidence remain external
gates and are not claimed by the repository.

Quality run
[`30211551484`](https://github.com/yhay81/socialname/actions/runs/30211551484)
passed Rust core with PostgreSQL 18 migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `696a248`. Manual
workflow-dispatch run
[`30211564752`](https://github.com/yhay81/socialname/actions/runs/30211564752)
passed the standalone PostgreSQL 18 delete-through and restore drill for the
same commit. Scheduled daily history and production evidence remain external.

Notification-acknowledgement slice evidence:

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-protocol
# 43 unit + 12 wire-contract tests
cargo test --locked -p socialname-server --lib
# 37 tests
cargo test --locked -p socialname-server --test postgres_migrations
# 1 real PostgreSQL 18 integration test
cd apps/console
npm test
npm run check
npm run build
# all passed
```

Migration `0014` brings the current schema to 49 product tables and 37
forced-RLS policies. A successful delivery admits at most one append-only
acknowledgement under `notification:write`; the first request returns the
database time and exact replay returns the same resource. `notification:read`
loads it independently. Queued/retrying/failed/cancelled delivery, foreign
tenant access, database time inversion, mutation, and excess application-role
privilege all fail. A companion delivery trigger prevents later state/time
updates from invalidating an acknowledgement. Membership/API-key attribution
remains private and one closed audit event records only the first insert.

The same-origin monitoring console exposes an acknowledgement action only when
the in-memory API key has `notification:write`, then projects the time and an
explicitly loaded-page count without presenting it as workspace-wide. This
narrow receipt is not email-open proof, webhook processing proof, destination
ownership verification, or the later Team review workflow. The complete
boundary is in
[`docs/notification-acknowledgement.md`](docs/notification-acknowledgement.md).
Notification acknowledgement, email delivery, and the operational
dashboard/report are now complete vertical slices; the combined software item
is closed below.

Quality run
[`30212644031`](https://github.com/yhay81/socialname/actions/runs/30212644031)
passed Rust core with PostgreSQL 18 migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `0a4f24a`.

Email-delivery slice evidence:

```console
cargo fmt --all -- --check
SOCIALNAME_TEST_DATABASE_URL=<disposable-postgresql-18> \
SOCIALNAME_TEST_APPLICATION_DATABASE_URL=<non-owner-app> \
SOCIALNAME_TEST_WORKER_DATABASE_URL=<non-owner-worker> \
  cargo test --locked --workspace --all-targets
# all passed, including the real PostgreSQL 18 boundary
# engine 12; protocol 44 unit + 13 wire; worker 22 library + 6 binary +
# 3 deployment-contract tests
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
cd ../console
npm ci
npm test
npm run check
npm run build
# both application gates passed
```

Migration `0015` makes endpoint channels immutable and adds a narrow email-only
cross-tenant claim coordinator without adding a product table or RLS policy.
Confirmed transitions now enqueue
active email and webhook endpoints with distinct logical-key and lineage
domains. The email worker decrypts only email-domain envelopes, derives one
fixed plain-text message from a confirmed `EmailNotification`, and submits a
bounded stable-ID request to an operator-configured HTTPS gateway. Managed DNS,
proxy/redirect/decompression refusal, lease fencing, retry/dead letter, and
response-body blindness match the webhook boundary.

The PostgreSQL test proves channel claim isolation, timeout then same-ID/body
success, permanent 4xx handling, append-only email attempts, complete
`email_attempt` lineage, and absence of recipient/gateway secret/body material
from persisted operational metadata. Unit tests cover the closed protocol
root, separate envelope/logical domains, redaction, and public-only gateway
policy. The operable command and remaining endpoint/sending-domain/provider
evidence gate are documented in
[`docs/email-delivery.md`](docs/email-delivery.md). Production email remains
disabled until that external evidence exists.

Quality run
[`30213884143`](https://github.com/yhay81/socialname/actions/runs/30213884143)
passed Rust core with PostgreSQL 18 migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `80c5ff0`.

Operational-reporting slice evidence:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
# includes protocol: 47 unit + 14 wire-contract tests;
# server: 38 library + 2 binary tests; console: 4 model tests
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# With disposable PostgreSQL 18 administrator/application/worker URLs:
cargo test --locked -p socialname-server --test postgres_migrations
# 1 real PostgreSQL 18 integration test passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/console
npm ci
npm test
npm run check
npm run build
# all passed; local browser verification passed at default and 375 px widths
```

Migration `0016` adds the independent `operations:read` scope and
tenant/time cohort indexes without adding a product table or RLS policy. The
closed report uses one PostgreSQL statement and database time for exact
24-hour, 7-day, or 30-day tenant snapshots. It returns no identifiers or
targets and derives non-relabellable `no_data`, `meeting`, or `breached`
status for watch-run success, channel-specific terminal delivery success,
channel-specific transition-to-delivery p95, and current deletion deadline
health. Current backlog stays separate from windowed terminal cohorts, while
paginated console metrics remain explicitly loaded-page context.

The real PostgreSQL test proves exact-scope denial, unknown-window rejection,
database-time bounds, non-owner forced-RLS access, two-tenant isolation,
channel separation, latency sampling, and identifier/secret exclusion.
Protocol and console-model tests reject partial shapes, changed targets,
relabelling, and inconsistent no-data/backlog relations. Exact definitions and
the remaining production-evidence boundary are documented in
[`docs/operational-reporting.md`](docs/operational-reporting.md). Production
multi-region, mail-provider, retained time-series, alert ownership, and elapsed
SLA evidence remain external and are not claimed by this report.

Quality run
[`30230264948`](https://github.com/yhay81/socialname/actions/runs/30230264948)
passed Rust core with PostgreSQL 18 migrations/tests, Windows/macOS desktop,
monitoring console, and managed-worker OCI for commit `c976038`.

Acceptance gate:

- Multi-region disagreement is represented, not overwritten.
- Shared-only absence cannot trigger a disappearance alert.
- Production reads hide deleted data within five minutes, assertions are
  recomputed within one hour, primary stores are cleared within 24 hours, and
  backup expiry is tracked to 35 days.

## Milestone 4 — Developer platform

Status: **Software gate complete; external commercial evidence pending**

- [x] Publish stable versioned REST/JSON and SSE contracts.
- [x] Add batch search, polling, webhooks, idempotency, quotas, usage records,
      and service-level reporting.
- [x] Implement `remote` and remote-assisted source combinations in CLI and
      desktop with visible, independent sync policies.
- [x] Add private cloud history, exports, API examples, and integration SDK
      generation only where it reduces real adoption friction.
- [x] Add plan entitlements and billing boundaries without coupling billing to
      the measurement engine.

Stable API-contract publication software evidence:

```console
cargo run --locked -p socialname-protocol --bin socialname-api-contract -- check
# verified exact committed OpenAPI, 27 JSON Schema roots, SSE, and manifest
cargo test --locked -p socialname-protocol --all-targets
# 50 unit + 14 wire-contract + 1 committed-publication tests passed
cargo test --locked -p socialname-server \
  every_published_api_operation_is_registered_by_the_router
# 1 route/scope publication boundary test passed
cargo clippy --locked -p socialname-protocol -p socialname-server \
  --all-targets --all-features -- -D warnings
# passed
```

[`contracts/api/v1`](contracts/api/v1/README.md) now contains a deterministic
OpenAPI 3.1.2 description for all 22 implemented authenticated operations,
every independent Draft 2020-12 protocol root, an exact machine-readable SSE
frame/resumption contract, and a SHA-256 drift manifest. The OpenAPI document
declares no production base URL. It contains no bearer, target, or destination
value and no example product data.

The protocol registry pins method, path, stable operation ID, request/response
root, success status, bounded parameters, and required scope. Tests reject
duplicate operations, missing schema roots, changed generated bytes,
unexpected JSON, broken OpenAPI/SSE links, missing Axum routes, public route
exposure, and differences between published and runtime scopes. Runtime
relational validation, consent, tenant RLS, egress policy, and availability
remain separate enforcement boundaries. Exact compatibility rules and
remaining hosted-distribution gates are documented in
[`docs/api-contract-publication.md`](docs/api-contract-publication.md).

Quality run
[`30231878790`](https://github.com/yhay81/socialname/actions/runs/30231878790)
passed Rust core with the exact API-contract check and PostgreSQL 18
migrations/tests, Windows/macOS desktop, monitoring console, and managed-worker
OCI for commit `8b5a4ee`.

Batch admission, quota, usage, and service-reporting partial software evidence
(the roadmap item remains open for search-completion webhooks):

```console
cargo run --locked -p socialname-protocol \
  --bin socialname-api-contract -- check
# verified exact committed OpenAPI with 23 operations, 28 JSON Schema roots,
# SSE, and manifest
cargo test --locked --workspace --all-targets
# passed, including protocol 53 unit + 14 wire + 1 publication;
# server 41 library + 2 binary + 1 PostgreSQL 18 integration;
# worker 22 library + 7 binary + 3 deployment-contract tests
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# passed
```

The existing API already admits bounded Cartesian batches, supports polling
and ordered SSE, and converges exact idempotency replay. Migration `0017` now
adds a target-pair meter with tenant and per-key UTC-day limits, one immutable
target-free usage record per newly admitted search, forced-RLS aggregate
reporting, and fixed 400-day expiry. Admission locks a tenant-checked quota
policy through a narrow definer function; a second statement obtains a fresh
committed snapshot after any lock wait. The real PostgreSQL test proves that
two concurrent same-key requests admit only one remaining unit, exact replay
does not double-charge, and quota rejection rolls back the whole batch.

`GET /v1/developer/report` independently requires `usage:read` and separates
current quota, window usage, unfinished backlog, terminal success, first-result
p95, terminal p95, and `no_data`. Owner/admin quota changes are audited and
cannot lower a limit below current usage. The worker can delete only a bounded
due-usage batch and cannot directly read or mutate policy/usage rows. Protocol
and generated contract shapes expose no target, site, search, consent,
destination, or idempotency identifier. Production scheduling, hosted
availability/SLA history, plans, and billing remain external or later gates.
Exact behavior and least-privilege grants are documented in
[`docs/developer-usage-reporting.md`](docs/developer-usage-reporting.md).

Quality run
[`30233689025`](https://github.com/yhay81/socialname/actions/runs/30233689025)
passed Rust core including API contract drift and PostgreSQL 18 quota/report
tests, Windows/macOS desktop, monitoring console, and managed-worker OCI for
commit `7d02608`.
Follow-up Quality run
[`30233865400`](https://github.com/yhay81/socialname/actions/runs/30233865400)
passed the same matrix after recording that evidence in commit `85e1d87`.

Search-completion webhook and combined-item software evidence:

```console
cargo fmt --all -- --check
# passed
cargo run --locked -p socialname-protocol \
  --bin socialname-api-contract -- check
# verified exact committed OpenAPI with 26 operations, 31 JSON Schema roots,
# SSE, and manifest
cargo test --locked --workspace --all-targets
# passed, including protocol 56 unit + 15 wire + 1 publication;
# server 42 library + 2 binary + 1 PostgreSQL 18 integration;
# worker 22 library + 7 binary + 3 deployment-contract tests
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# passed
```

Migration `0018` and three stable API operations add one immutable active
webhook-endpoint binding per search without changing `SearchCreateRequest`.
Binding-first and terminal-first transactions converge through narrow
database triggers on one logical `search_completion` delivery; only
`completed` and `failed` enqueue. Exact registration replay is idempotent,
different endpoints conflict, caller/search cancellation is explicit, and an
endpoint disabled before completion produces a visible cancelled delivery.

The existing fenced webhook worker now emits a separate signed wake-up body
containing only delivery ID, search ID, terminal outcome, and completion time.
It preserves retry/dead-letter behavior while email claims remain transition
only. Search and per-target lineage make deletion traversal reach shared
completion deliveries. The watch operational report explicitly retains its
transition-only cohort. Forced RLS protects the new binding, bringing the
schema inventory to 52 product tables and 40 tenant policies.

The PostgreSQL 18 test proves exact/conflicting replay, read/write scope
separation, two-tenant hiding, both registration/terminal commit orders,
deduplication under a repeated terminal update, search/subscription
cancellation, endpoint-disable behavior, real signed worker delivery, minimal
target-free payload/audit, and search plus target lineage. Exact public shapes
and remaining external gates are documented in
[`docs/search-completion-webhooks.md`](docs/search-completion-webhooks.md).
Production endpoint ownership, DNS/TLS operation, hosted availability,
retained successful-delivery/SLA evidence, plans, and billing remain external
or later gates and are not implied by this software completion.

Quality run
[`30235166753`](https://github.com/yhay81/socialname/actions/runs/30235166753)
passed Rust core including API contract drift and PostgreSQL 18 webhook tests,
Windows/macOS desktop, monitoring console, and managed-worker OCI for commit
`6fca1f3`.

Remote and remote-assisted client software evidence:

```console
cargo fmt --all -- --check
# passed
cargo test --locked --workspace --all-targets
# passed; app-core includes 21 policy/transport/mapping tests and CLI includes
# 6 source/output tests (the unchanged PostgreSQL test is environment-gated)
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# passed
cargo run --locked -p socialname-protocol \
  --bin socialname-api-contract -- check
# verified committed API v1 contracts without drift
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# passed; npm reported 0 vulnerabilities
```

The shared app-core policy now closes all source/sync relations without
choosing sync implicitly: `local`/`cache` require `never`, `remote` requires
`private` or `shared`, and `hybrid` retains the user's explicit choice.
`hybrid+never` remains local cache then local probe;
`hybrid+private/shared` emits the eligible local cache before one managed
search. Actual `local_cache`, `local_probe`, `private_cloud`,
`shared_assertion`, and `managed_probe` origins survive CLI JSON and desktop
IPC. Uncertainty and operational failure remain distinct from absence.

The managed client permits HTTPS plus loopback development HTTP, refuses
redirects and URL credentials, redacts API keys, bounds body/stream/time/retry
work, reuses one idempotency key after an ambiguous create, validates exact SSE
sequence and identity across `Last-Event-ID` reconnection, and requires a
validated terminal resource to confirm cancellation. Loopback integration
tests prove authenticated creation, typed terminal SSE, and cancellation
without external credentials.

CLI keys come from a named environment variable rather than argv. Desktop
source and sync controls remain visibly independent; API origin, key, consent
grant, and region stay in session memory, while `shared` adds an explicit
acknowledgement. Browser verification covered the normal layout and the
configured 920x640 minimum with no horizontal overflow or console warnings.
Exact behavior and the external hosted/TLS/credential/multi-region evidence
gates are documented in
[`docs/remote-clients.md`](docs/remote-clients.md).

Quality run
[`30237275536`](https://github.com/yhay81/socialname/actions/runs/30237275536)
passed Rust core, Windows/macOS desktop, monitoring console, and managed-worker
OCI for commit `c871992`.

Private search history, export, and adoption-example software evidence:

```console
cargo fmt --all -- --check
# passed
cargo run --locked -p socialname-protocol \
  --bin socialname-api-contract -- check
# verified exact committed OpenAPI with 28 operations, 33 JSON Schema roots,
# SSE, and manifest
cargo test --locked --workspace --all-targets
# passed, including protocol 58 unit + 16 wire + 1 publication;
# server 42 library + 2 binary; the PostgreSQL integration compiled and
# remained environment-gated locally
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# passed
node --test examples/api-v1/client.test.mjs
# 5 passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# passed
```

`GET /v1/searches` now returns a forced-RLS tenant history ordered by immutable
creation time and search ID. `GET /v1/searches/{search_id}/export` independently
requires `data:export`, refuses nonterminal work, and pages the immutable
`socialname.dev/search-export/v1` event set by Event ID with a 50-event page
and 1,026-event whole-search ceiling. Any lineage-hidden target or event hides
the whole search from both surfaces. Migration `0019` adds only the history
index; export is a stateless projection and creates no duplicate retention or
deletion store.

The PostgreSQL 18 gate proves stable pagination, read/export scope separation,
pre-terminal conflict, exact full traversal, malformed/foreign cursor
rejection, two-tenant hiding, and deletion-tombstone suppression.
Dependency-free Node.js 24 examples keep keys in environment variables, accept
target-bearing input on stdin, resume/deduplicate strict SSE, and traverse
history/export without unbounded accumulation. Their tests run in Quality.
OpenAPI remains the generation input; no generated SDK is published because
there is not yet a hosted origin, package-distribution policy, compatibility
telemetry, or observed language-specific friction. Exact behavior is in
[`docs/private-search-history-export.md`](docs/private-search-history-export.md).
Hosted export handling, package distribution, adoption measurement, and
availability remain external evidence and are not claimed.

Quality run
[`30238982627`](https://github.com/yhay81/socialname/actions/runs/30238982627)
passed Rust core including PostgreSQL 18 history/export isolation tests,
contract drift, and the Node.js examples; Windows/macOS desktop, monitoring
console, and managed-worker OCI also passed for commit `2420203`.

Plan entitlement and billing-boundary software evidence:

```console
cargo fmt --all -- --check
# passed
cargo run --locked -p socialname-protocol \
  --bin socialname-api-contract -- check
# verified exact committed OpenAPI with 29 operations, 34 JSON Schema roots,
# SSE, and manifest
cargo test --locked --workspace --all-targets
# passed against PostgreSQL 18, including protocol 61 unit + 17 wire +
# 1 publication; server 45 library + 2 binary + 1 full integration
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# passed
node --test examples/api-v1/client.test.mjs
# 5 passed
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules; pack sha256=eb6c0754038b53aebe052ee8e7531c92f68555172dd3522e0874e2fbdc3f49a2
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
cd apps/desktop
npm ci
npm run check
npm run build
# passed; npm reported 0 vulnerabilities
```

Migration `0020` adds forced-RLS current and append-only plan state with closed
`community`, `developer`, `monitor`, and `evaluation` plans. Exact capabilities
are derived rather than provider supplied. Database time derives pending,
active/grace, and suspended access. New workspaces start `community`; existing
workspaces receive an explicit `evaluation` bridge so migration does not
silently disable prior managed behavior.

`GET /v1/workspace/plan` publishes only the plan, derived capabilities,
optimistic revision, and timestamps. The schema-owner
`reconcile-plan-entitlement` adapter stores only SHA-256 event/request identity,
advances exactly one revision, and writes append-only history plus target-free
audit. The HTTP role can read only safe current columns and cannot read current
hashes, event history, or mutate access.

New managed searches and completion-webhook bindings require
`managed_search`; new or resumed/active watches and due-watch scheduling
require `monitoring`. Exact replay, existing reads/history/export, cancellation,
watch pause/delete, and privacy/recovery paths remain available. Quota remains
an independent admission guardrail, and no plan type enters the domain,
measurement engine, observation, assertion, or worker execution contracts.

The PostgreSQL 18 gate proves pending/grace/suspension/restoration, idempotent
event replay and conflict detection, denied-admission rollback without usage,
two-tenant isolation, least privilege, suspension-safe operations, and due-run
suppression. Exact behavior is in
[`docs/plan-entitlements-billing.md`](docs/plan-entitlements-billing.md).
Checkout, pricing, taxation, invoices, provider webhook verification,
self-service subscription management, hosted deployment, and live commercial
reconciliation remain external or later gates and are not claimed.

Acceptance gate:

- Local test behavior and managed API behavior use the same engine, rule pack,
  and protocol semantics.
- Every response exposes source, freshness, provenance, and uncertainty.

## Milestone 5 — Team workflows and quality network

Status: **Planned**

- [ ] Add organizations, roles, audit, review, acknowledgement, and retention
      controls.
- [ ] Add collaboration and incident integrations based on demonstrated
      customer workflow demand.
- [ ] Accept minimized, explicitly consented shared observations with replay,
      quota, anomaly, diversity, and reputation controls.
- [ ] Implement strict quorum-based `corroborated` assertions and managed
      verification escalation.
- [ ] Evaluate a separately installed community measurement daemon only after
      managed regional workers are proven.

Acceptance gate:

- Ordinary CLI installations never execute unrelated central jobs.
- Sybil or fabricated client evidence cannot independently produce
  `verified`.
- Revoking a grant removes the contributor's support and recomputes downstream
  knowledge.

## Milestone 6 — Advanced public-identifier intelligence

Status: **Exploratory**

Potential extensions, admitted only through the product decision filter:

- permitted username-variant and namespace-collision monitoring;
- stable public-ID rename and migration tracking;
- rule-drift proposal and fingerprint clustering;
- human-reviewable brand protection workflows;
- regional availability and policy-change intelligence;
- evidence summarization and operator triage assistance.

String similarity alone never establishes identity, common ownership, or
impersonation.

## Explicitly deferred choices

Choose these only when their trigger is measured:

| Choice | Trigger |
| --- | --- |
| Redis or coordinator | Multiple API instances cannot maintain acceptable single-flight behavior |
| Durable broker | PostgreSQL job claims are a measured bottleneck |
| Analytics store | Observation analytics materially harm transactional workloads |
| Dedicated event gateway | SSE fan-out exceeds the modular monolith |
| Browser automation | A high-value site cannot be measured safely by declarative HTTP and policy permits it |
| Community probe daemon | Managed regions are proven and measurement diversity has quantified value |
| Full microservices | Independent scaling or ownership is demonstrated, not anticipated |

## Roadmap update log

- **2026-07-25:** Established the authoritative goal, separated software and
  external evidence gates, marked the Rust foundation complete, and selected
  live canary software plus the local cache/source policy as the current
  milestone.
- **2026-07-25:** Added independent typed canary manifests with strict temporal,
  review, entropy, duplication, and site-policy validation; retained an empty
  production manifest set so all ten rules remain discovery-only pending real
  external evidence.
- **2026-07-25:** Added the production-engine canary runner with conservative
  request/byte preflight, concurrency and deadline caps, cancellation-safe
  partial results, minimized evidence, explicit live acknowledgement, and CI
  manifest validation.
- **2026-07-25:** Added Canary Report v1 with executable engine hashing,
  rational precision/coverage, deterministic latency and response metrics,
  bounded expiry, content-integrity and duplicate checks, strict
  ingestion-policy validation, and privacy-bounded case evidence.
- **2026-07-25:** Added Canary Aggregate v1 with validator-only inputs, an exact
  24-hour interval, three-region/three-run requirements, per-region precision,
  coverage, conflict and p95 gates, and typed non-suppressing rejection issues.
- **2026-07-25:** Added Canary Shadow v1 with same-private-target paired
  execution, combined safety budgets, independently validated nested reports,
  content-integrity and duplicate checks, and typed precision, coverage,
  conflict, and per-case regression rejection.
- **2026-07-25:** Added regional rule-health records with quarantined
  initialization, contiguous evidence sequencing, bounded two-pass recovery,
  operational degradation, immediate classification quarantine, persisted
  record validation, and health-only notification semantics.
- **2026-07-25:** Added `socialname-cache` with embedded SQLite migrations,
  explicit database ownership, fail-closed foreign/future/corrupt handling,
  immutable observation rows, separate access metadata, and deterministic
  initialization and migration tests.
- **2026-07-25:** Added transactional typed observation persistence with full
  domain round trips, immutable-ID replay/conflict behavior, initial cache
  metadata, rollback on partial failure, and explicit incomplete-row errors.
- **2026-07-25:** Added exact cache eligibility across target, region, rule,
  current and captured health, verdict policy, expiry, and maximum age; returns
  a bounded observation set with transactional access accounting instead of a
  latest-writer result.
- **2026-07-25:** Added expiry-first/LRU maintenance with deterministic logical
  data limits, create-new versioned JSONL export, full relational integrity
  checks, explicit corrupt-file quarantine and empty-cache recovery, and
  complete database/sidecar deletion.
- **2026-07-25:** Added orthogonal CLI `local`/`cache` source and `sync=never`
  policy, strict no-network cache execution, promoted-plus-fresh-health gates,
  optional local observation persistence, verdict-specific TTLs, and
  source/freshness-aware human and JSON output.
- **2026-07-26:** Added consent-bound idempotent managed-search persistence,
  ordered resumable SSE with mid-stream authorization checks, least-privilege
  PostgreSQL event storage, and repeatable PostgreSQL 18 boundary tests; kept
  probing quarantined behind the signed-worker gate.
- **2026-07-26:** Added the signed-only managed worker, exact regional
  promotion/pack revalidation, conservative DNS rebinding and SSRF rejection,
  independent response byte budgets, cancellation, and a live-acknowledged
  stdin-only operator probe; left database claims and ingestion to the next
  ordered slice.
- **2026-07-26:** Added consent/visibility-isolated managed job expansion,
  fenced leases and reclamation, bounded retry, continuous authorization
  cancellation, and idempotent atomic observation/event/lineage ingestion
  through the signed worker under a non-owner forced-RLS role; kept all
  discovery-only rules behind their external promotion gate.
- **2026-07-26:** Added scoped revisioned watch CRUD, atomic due-run expansion
  with deterministic jitter, exact-rule freshness reuse, conservative
  inspected-byte reservation, search/watch job coalescing, and
  revision/consent-aware cancellation with PostgreSQL 18 RLS evidence; kept
  discovery-only rules quarantined and selected assertion recomputation next.
- **2026-07-26:** Added transactional exact-rule `assertion/v1`
  recomputation, explicit support and search events, per-watch account
  baselines, confirmation-aware account candidates, conflict suppression, and
  separate degraded/unavailable measurement transitions with PostgreSQL 18
  RLS evidence; selected deduplicated signed webhook delivery next.
- **2026-07-26:** Added one-logical-delivery webhook enqueue, stable signed
  payloads, encrypted endpoint-bound destinations, public-only managed
  transport, fenced retry/dead-letter handling, append-only attempts, audit,
  and lineage with PostgreSQL 18 evidence; selected the minimal monitoring UI
  next.
- **2026-07-26:** Added bounded tenant-RLS watch and transition/delivery pages
  plus a same-origin memory-only-key React/Vite monitoring console,
  deterministic model and PostgreSQL 18 boundary tests, and an independent CI
  job. Completed the Milestone 2 software gate while leaving hosting,
  destination ownership, managed deployment, and production policy as explicit
  external evidence.
- **2026-07-26:** Added compatible regional assertion event projections,
  immutable PostgreSQL regional support and two-layer lineage, global conflict
  with preserved regional truths, and budget-preserving managed verification
  priorities for conflict and pending account transitions. Kept the real
  multi-region worker/canary claim behind its external deployment evidence
  gate and selected signed rollout/key-rotation metadata next.
- **2026-07-26:** Added threshold-signed rule-pack metadata with embedded site
  promotions, expiry and staged worker selection, durable global/per-site
  replay floors, PostgreSQL active/staged/LKG state, exact managed-worker
  binding, dual-threshold trust rotation, and signed retained-pack rollback.
  Kept production keys, artifacts, deployment, and rollback observation
  external, and selected versioned purpose-specific consent grants next.
- **2026-07-26:** Added exact purpose/profile/notice consent resources for
  account and installation subjects, tenant-separated installation digests
  with membership non-override, scoped bounded APIs, serialized replay-safe
  creation, and immutable immediate withdrawal with PostgreSQL 18 RLS
  evidence. Kept prior-contribution erasure behind the ordered lineage-backed
  deletion workflow and selected bounded Evidence Capsules and retention next.
- **2026-07-26:** Added closed 64 KiB Evidence Capsules atomically with managed
  observations, exact signed provenance, sanitized evidence summaries,
  `evidence:read` inspection with database-time hiding, consumer-specific
  deadlines, bounded irreversible purge, and payload-free three-year receipts
  with PostgreSQL 18 RLS evidence. Kept existing observation/support erasure
  behind the ordered lineage-backed workflow and selected it next.
- **2026-07-26:** Added owned contributor deletion and externally verified
  target-person workflows with exact deadlines, immediate lineage-backed
  hiding, grant withdrawal, HMAC-only fail-closed suppression, fenced support
  withdrawal/recomputation, current-primary purge, exact post-purge replay,
  and explicit private-target routing under PostgreSQL 18 RLS. Kept completed
  receipts, analytics/restore/backup proof, and daily delete-through drills in
  the next ordered item.
- **2026-07-26:** Added fixed-shape deletion receipts, atomic
  primary/derived completion, deadline- and inventory-gated backup completion,
  HMAC-authenticated target-free restore-ledger export/replay, and
  restore-aware readiness quarantine. Added a daily PostgreSQL 18
  delete-through workflow and deterministic coverage for premature refusal,
  exact replay, restored-row hiding, and final receipts. Kept hosted schedule
  history, provider inventory completeness, and elapsed production SLA proof
  external, and selected notification acknowledgement, email delivery,
  dashboards, and SLO reporting next.
- **2026-07-26:** Added delivered-only, idempotent notification
  acknowledgement with closed API v1 resources, forced-RLS append-only
  storage, private actor audit, deletion hiding, and same-origin console
  action. Kept destination ownership external and selected email delivery next
  within the still-open combined roadmap item.
- **2026-07-26:** Added provider-neutral HTTPS email delivery with a
  confirmed-only canonical DTO, separate logical/encryption/claim domains,
  fixed plain-text trust language, stable gateway idempotency, public-only
  egress, fenced retry/dead letter, and secret-free audit/lineage. Kept
  endpoint ownership, sending-domain/provider evidence, dashboards, and SLO
  reporting open.
- **2026-07-27:** Added a target-free operational report with an independent
  scope, database-time fixed windows, derived no-data/meeting/breached
  objectives, channel-separated delivery success and latency, current
  deletion deadline health, and responsive same-origin dashboard. Closed the
  combined notification/reporting software item while keeping multi-region,
  production provider, retained SLO history, and elapsed SLA evidence
  external.
- **2026-07-27:** Started Milestone 4 by publishing every implemented API v1
  route as deterministic OpenAPI 3.1.2 and Draft 2020-12 schemas, with a
  separate exact SSE contract, digest manifest, and committed-byte plus
  Axum route/scope drift gates. Declared no hosted origin or availability and
  selected batch, quota, usage, and service reporting next.
- **2026-07-27:** Added serialized tenant/API-key UTC-day target-pair quotas,
  immutable target-free usage, fixed 400-day expiry, owner/admin policy
  operation, and an independently scoped Developer service report. Preserved
  exact replay without double charge and proved whole-batch rollback plus
  least privilege under PostgreSQL 18. Kept the combined roadmap item open for
  search-completion webhooks and kept hosted availability, historical SLA,
  plans, and billing outside this software claim.
- **2026-07-27:** Completed the combined Developer search item with a separate
  per-search completion-webhook resource, both-order terminal enqueue,
  deduplicated signed target-free delivery, cancellation and endpoint-disable
  states, and search/target deletion lineage. Published 26 operations and 31
  schema roots and proved the boundary under PostgreSQL 18. Selected remote
  and remote-assisted CLI/desktop source combinations next while keeping
  hosted delivery/availability evidence external.
- **2026-07-27:** Connected CLI and desktop remote and cached-first
  remote-assisted policies to the managed API with an explicit source/sync
  matrix, purpose-specific consent inputs, memory-only/redacted credentials,
  bounded resumable SSE, actual-source output, and confirmed cancellation.
  Selected private cloud history, exports, and adoption-focused API examples
  next while keeping hosted service evidence external.
- **2026-07-27:** Added tenant-local private search history, independent
  terminal Event ID export, deletion-safe visibility, two executable Node.js
  examples, and exact contract publication. Kept export stateless instead of
  creating a second retention store and deferred generated SDK distribution
  until hosted origin and language-specific adoption friction are observed.
  Selected plan entitlements and billing boundaries next.
- **2026-07-27:** Completed the Milestone 4 repository software gate with
  closed provider-neutral plan entitlements, digest-only optimistic
  reconciliation, a scoped plan read, fail-closed new-work admission and
  scheduling, suspension-safe recovery/privacy paths, and PostgreSQL 18
  least-privilege evidence. Kept provider integration, pricing, checkout,
  invoicing, hosted deployment, and live commercial evidence external, and
  selected Milestone 5 team workflows next.
