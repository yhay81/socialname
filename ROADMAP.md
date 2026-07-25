# SocialName execution roadmap

Status: **Active**

Last reviewed: 2026-07-25

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

Status: **Current**

Outcome: local CLI and desktop users receive fast, source-explicit,
freshness-aware results from rules whose health is measured rather than
assumed.

Next executable item: add `socialname-cache` with embedded SQLite migrations.
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

- [ ] Add `socialname-cache` with embedded SQLite migrations.
- [ ] Persist immutable local observations and cache metadata, not just the
      latest boolean result.
- [ ] Key eligibility by normalized username, site, region class, rule hash,
      verdict policy, and freshness.
- [ ] Implement pruning, maximum-size behavior, corruption recovery, export,
      and complete local deletion.
- [ ] Add CLI `local` and `cache` modes plus independent `sync=never`.
- [ ] Show source, observed time, expiry, rule hash, and refresh state in normal
      and machine-readable CLI output.
- [ ] Expose the same cache/source policy through `socialname-app-core` and the
      desktop application.
- [ ] Stream an eligible cached result immediately while clearly marking any
      subsequent local refresh.
- [ ] Add deterministic cache-hit, stale, rule-change, negative-TTL,
      cancellation, pruning, migration, and deletion tests.

Software acceptance gate:

- The CLI and desktop work offline from eligible cached observations.
- Cached results are never represented as live.
- Default execution remains local with no network call to SocialName.
- Cache corruption or migration failure cannot silently produce a verdict.

## Milestone 2 — First paid monitoring loop

Status: **Planned**

Outcome: a user can create a watch, the managed system observes it over time,
derives a trustworthy transition, and delivers one auditable notification.

- [ ] Add `socialname-protocol` for versioned API, event, error, source,
      freshness, watch, transition, and notification DTOs.
- [ ] Add a Rust modular-monolith `socialname-server` using Axum/Tower.
- [ ] Add PostgreSQL migrations for tenants, credentials, sites, rule versions,
      searches, jobs, observations, assertion support, watches, transitions,
      notification endpoints, deliveries, consent, lineage, and deletion tasks.
- [ ] Add authenticated private workspaces and hashed, scoped API keys.
- [ ] Implement idempotent search creation and SSE partial-result streaming.
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
- [ ] Implement `remote` and `hybrid` modes in CLI and desktop with visible,
      independent sync policies.
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
