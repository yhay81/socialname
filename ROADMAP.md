# SocialName execution roadmap

Status: **Active**

Last reviewed: 2026-07-26

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

Next executable item: add `socialname-worker` with signed-rule-only execution
and managed-probe SSRF/DNS-rebinding defenses, consuming accepted searches
without weakening the now-persisted consent and event boundaries.
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

Status: **Current**

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
- [ ] Add `socialname-worker` with signed-rule-only execution and managed-probe
      SSRF/DNS-rebinding defenses.
- [ ] Implement transactional PostgreSQL job claims, leases, retries, and
      idempotent observation ingestion.
- [ ] Implement freshness-aware watch scheduling and equivalent-work
      coalescing.
- [ ] Recompute `assertion/v1`, persist meaningful transitions, and distinguish
      account change from measurement degradation.
- [ ] Deliver a deduplicated signed webhook with retry, dead-letter state, and
      audit history.
- [ ] Add a minimal monitoring UI without weakening the API boundary.
- [ ] Provide one end-to-end test: watch creation -> managed observation ->
      assertion change -> transition -> exactly-once logical notification.

Protocol-slice evidence:

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-protocol
# 25 unit tests and 5 public contract tests passed
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
# 23 library, 2 binary, and 1 PostgreSQL integration test passed
cargo clippy --locked -p socialname-server --all-targets --all-features -- -D warnings
cargo build --locked -p socialname-server
```

`socialname-server` is an explicit Axum 0.8/Tower 0.5 binary with a
loopback-only default. It exposes versioned liveness, PostgreSQL-aware
readiness, authenticated workspace/search resources, polling, cancellation,
and bounded ordered SSE; worker, watch, notification, and HTTP administration
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
# socialname-server: 23 library, 2 binary, and 1 PostgreSQL integration test passed
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

The three embedded SQLx migrations create 31 bounded product tables and 26
tenant-isolation policies with forced RLS. Composite tenant foreign keys,
immutable observation and support history, closed observation outcomes,
transition-specific confirmation bases, exact confirmed-delivery checks,
encrypted notification destinations, ordered deletion deadlines, receipts,
lineage, and HMAC-only suppression tokens preserve the trust and privacy
boundaries. A separate `migrate` command requires an explicit schema-owner
database URL, uses one connection with connection/migration deadlines, and
returns fixed errors without reflecting credentials.

The CI core job runs both the operator command and an integration test against
`postgres:18-alpine`. The test reapplies all three migrations, inventories all
tables and forced-RLS policies, uses a real non-owner `NOBYPASSRLS` role to
prove tenant isolation, rejects cross-tenant references and observation
mutation, suppresses shared-only absence delivery, accepts an independently
confirmed delivery, and checks deletion deadlines, receipts, and lineage.

Authenticated-workspace evidence:

```console
cargo fmt --all -- --check
cargo run --locked -p socialname-server -- migrate
cargo test --locked -p socialname-protocol -p socialname-server --all-targets
# protocol: 25 unit + 5 contract; server: 23 library + 2 binary + 1 PostgreSQL
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
workspace/key metadata; later non-search private routes remain closed.

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
column-limited privileges, and connection-cap recovery. This slice performs no
probe; accepted searches remain quarantined for the signed worker gate.

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

Status: **Planned**

- [ ] Deploy managed canaries and workers in the required regions.
- [ ] Add region-aware assertions, conflict escalation, and managed
      confirmation of high-value transitions.
- [ ] Implement signed rule-pack metadata, expiry, staged rollout, rollback
      protection, and key rotation.
- [ ] Implement versioned purpose-specific consent grants for private history,
      shared observation, and shared research.
- [ ] Store bounded Evidence Capsules and enforce the accepted retention
      schedule.
- [ ] Implement lineage-backed contributor deletion and target-person request
      workflows.
- [ ] Add daily delete-through tests, deletion receipts, restore-ledger replay,
      and backup-expiry verification.
- [ ] Add notification acknowledgement, email delivery, operational dashboards,
      and SLO reporting.

Acceptance gate:

- Multi-region disagreement is represented, not overwritten.
- Shared-only absence cannot trigger a disappearance alert.
- Production reads hide deleted data within five minutes, assertions are
  recomputed within one hour, primary stores are cleared within 24 hours, and
  backup expiry is tracked to 35 days.

## Milestone 4 — Developer platform

Status: **Planned**

- [ ] Publish stable versioned REST/JSON and SSE contracts.
- [ ] Add batch search, polling, webhooks, idempotency, quotas, usage records,
      and service-level reporting.
- [ ] Implement `remote` and remote-assisted source combinations in CLI and
      desktop with visible, independent sync policies.
- [ ] Add private cloud history, exports, API examples, and integration SDK
      generation only where it reduces real adoption friction.
- [ ] Add plan entitlements and billing boundaries without coupling billing to
      the measurement engine.

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
