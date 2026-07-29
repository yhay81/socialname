# SocialName v2 design notes

This directory records the investigation and design decisions for rebuilding
SocialName. The current Python package is treated as a legacy reference, not as
the implementation foundation for v2.

The design was last reviewed on 2026-07-26.

## Authority and execution

- [Ultimate goal](ultimate-goal.md) is the stable, authoritative product
  charter: mission, promise, value system, North Star, boundaries, and decision
  filter.
- [`ROADMAP.md`](../ROADMAP.md) is the canonical execution order: current
  milestone, software gates, external evidence gates, and completion evidence.
- [Accepted decisions](decisions-2026-07-24.md) records binding architecture,
  trust, governance, and client decisions;
  [2026-07-28](decisions-2026-07-28.md) adds the single operated-service
  decision and [2026-07-29](decisions-2026-07-29.md) the domain and hosting
  providers.
- Focused design documents explain implementation details.

Repository agents follow [`AGENTS.md`](../AGENTS.md). Product work must remain
consistent with the charter and advance the first incomplete roadmap milestone.

## Product direction

SocialName v2 is a public-identifier observability platform:

- A fast, private, local-first CLI written in Rust.
- A stable developer API using the same engine and rule set as the CLI.
- Paid continuous monitoring, history, and notifications.
- A central quality system that maintains rule health and produces
  freshness- and provenance-aware results.

The project is not intended to become a public database of everybody who has
ever been searched. A username being present on two sites is also not proof that
both accounts belong to the same person.

## Current decisions

| Area | Decision |
| --- | --- |
| Implementation | Rust, with one shared engine for CLI and managed workers |
| Default CLI behavior | Local execution; no result upload without explicit consent |
| Cloud model | Optional private cloud state, managed scans, and monitoring |
| Shared data | Opt-in observations; untrusted client data cannot become global truth by itself |
| Result model | Immutable observations plus derived current assertions |
| Rule model | One typed declarative rule per site, compiled into signed rule packs |
| Initial paid value | Scheduled monitoring, change history, and notifications |
| Initial backend | Rust modular monolith, PostgreSQL, managed worker processes |
| Initial API | REST/JSON for commands and resources, SSE for streaming results |

## Implementation status

The first vertical slice is implemented in the repository:

- domain observations and deterministic `assertion/v1` derivation;
- strict Site Rule v1 source types and generated JSON Schema;
- semantic rule compiler, context-aware URL templates, and canonical pack
  hashing;
- asynchronous HTTP probe engine and explainable deterministic classifier;
- local CLI commands for rule validation, fixture validation, and live probing;
- ten representative rules with 30 minimized offline cases;
- independent, time-bounded positive/negative canary manifests with strict
  semantic validation against compiled site rules;
- a bounded, cancellable canary runner using the production measurement engine
  without exposing target identifiers in its result surface;
- a user-controlled SQLite observation cache with typed persistence,
  freshness/health eligibility, bounded maintenance, explicit export,
  quarantine recovery, and complete local deletion;
- an independent public API v1 crate with closed search/SSE, error,
  source/freshness, watch, transition-confirmation, notification endpoint, and
  delivery, deletion, operations, and authenticated-workspace DTOs plus
  deterministic OpenAPI 3.1.2, JSON Schema, SSE, and digest-manifest
  publication;
- an operable Axum/Tower modular monolith with loopback-safe defaults, bounded
  requests, database-aware readiness, closed errors, redacted tracing,
  transactional workspace/API-key operator lifecycle, digest-only bearer
  authentication, forced tenant RLS, consented idempotent private searches,
  polling/cancellation, and bounded resumable PostgreSQL-backed SSE;
- provider-neutral plan entitlements with closed derived capabilities,
  digest-only optimistic reconciliation, fail-closed admission/scheduling,
  and suspension-safe read, cancellation, and privacy behavior;
- closed purpose/profile/notice consent resources for account and
  installation subjects, tenant-separated installation digests, membership
  non-override, bounded reads, and immutable one-way withdrawal;
- owner-authorized contributor deletion and externally verified target-person
  workflows with immediate lineage tombstones, exact deadlines, HMAC-only
  fail-closed suppression, current-primary purge, and private-target routing;
- a signed managed worker with consent/visibility-isolated job expansion,
  fenced claims, bounded retries, continuous authorization cancellation, and
  atomic observation/assertion/transition/event/lineage ingestion under a
  non-owner forced-RLS database role;
- threshold-signed rule-pack metadata with embedded regional site promotions,
  staged worker selection, 24-hour expiry, durable global and per-site replay
  floors, safe overlapping key rotation, and signed retained-pack rollback;
- freshness-aware revisioned watch scheduling plus confirmed-transition
  webhook enqueue, endpoint-bound destination encryption, stable signed
  payloads, bounded retry/dead-letter handling, append-only attempt history,
  audit, and lineage;
- bounded tenant-RLS watch-list and transition/delivery timeline resources plus
  a target-free operational report and same-origin React/Vite monitoring
  console whose pasted scoped key remains only in page memory;
- a Tauri 2 Windows/macOS desktop slice with explicit local/offline-cache and
  cached-first sources, immutable observation persistence, source-preserving
  refresh streaming, freshness display, cancellation, and explicit
  research-mode consent.

`cargo test --workspace --all-targets` verifies the slice without Internet
access. Live canaries are intentionally a separate acceptance gate.

## Documents

- [Ultimate goal](ultimate-goal.md) — mission, product promise, North Star,
  sustainable advantage, hard boundaries, and decision filter.
- [Research findings](research.md) — legacy history, current Sherlock, adjacent
  projects, and distributed-measurement lessons.
- [Product vision](product.md) — users, value, execution modes, privacy, and
  commercial direction.
- [System architecture](architecture.md) — central server responsibilities,
  trust model, data model, API, and technology choices.
- [Site rule design](site-rules.md) — rule authoring, classification, validation,
  packaging, and migration.
- [Canary Manifest v1](canary-manifest-v1.md) — independent positive/negative
  controls, validity, review evidence, and policy compatibility.
- [Canary Report v1](canary-report-v1.md) — versioned run evidence, recomputed
  metrics, expiry, duplicate detection, and ingestion-policy validation.
- [Canary Aggregation v1](canary-aggregation-v1.md) — repeated-run,
  multi-region, 24-hour acceptance metrics and explicit regional failures.
- [Canary Shadow v1](canary-shadow-v1.md) — same-target paired execution and
  candidate regression checks against a last-known-good rule.
- [Regional Rule Health v1](rule-health-v1.md) — evidence-driven regional
  health, quarantine, recovery, replay rejection, and notification separation.
- [Signed Rule Promotion v1](rule-promotion-v1.md) — accepted regional evidence,
  Ed25519 trust policy, activation replay protection, and retained rollback.
- [Signed Rule-Pack Distribution v1](rule-pack-distribution-v1.md) —
  threshold trust, staged rollout, durable replay protection, key rotation,
  PostgreSQL activation, and exact worker binding.
- [Canary workflow operations](canary-workflows.md) — disabled-by-default
  manual and scheduled managed-vantage templates with fixed budgets.
- [Local cache](local-cache.md) — embedded SQLite persistence, eligibility,
  maintenance, export, recovery, deletion, and fail-closed behavior.
- [Public protocol v1](protocol-v1.md) — closed REST/SSE DTOs, source and
  freshness, bounded watches, transition confirmation, errors, and notification
  delivery contracts.
- [API v1 contract publication](api-contract-publication.md) — deterministic
  OpenAPI, JSON Schema, SSE resumption/frame semantics, manifest integrity,
  compatibility, and route/scope drift gates.
- [Modular-monolith server shell](server.md) — process configuration, health,
  request bounds, error and logging boundaries, and graceful shutdown.
- [PostgreSQL schema and migrations](postgresql-schema.md) — embedded migration
  operation, tenant RLS, evidence and notification constraints, deletion
  lineage, and PostgreSQL 18 verification.
- [Authenticated private workspaces and API keys](authenticated-workspaces.md)
  — one-time key lifecycle, digest-only authentication, non-owner RLS,
  database-aware readiness, and the first protected route.
- [Purpose-specific consent grant lifecycle](consent-api.md) — exact
  purpose/profile/notice contracts, account and installation subjects,
  bounded reads, idempotent creation, and immediate immutable withdrawal.
- [Private search API and ordered event stream](search-api.md) — consented
  idempotent creation, polling/cancellation, append-only events, and bounded
  resumable SSE with worker-created result and terminal events.
- [Private search history and export](private-search-history-export.md) —
  tenant-local discovery, terminal Event ID export, independent scopes,
  deletion hiding, and adoption-focused examples.
- [Signed managed worker boundary](managed-worker.md) — signed-metadata-only
  activation, DNS-rebinding/SSRF defenses, byte budgets, and one-shot
  operation.
- [Managed probe jobs and observation ingestion](managed-jobs.md) — exact work
  identity, narrow forced-RLS coordination, fencing, retries, consent locks,
  atomic fan-out, and the bounded one-job operator.
- [Regional managed-worker deployment boundary](regional-worker-deployment.md)
  — digest-pinned non-root OCI artifact, one-shot workload isolation,
  termination behavior, and the exact external evidence gate.
- [Freshness-aware watch scheduling](watch-scheduling.md) — authenticated
  lifecycle, atomic due runs, exact-rule freshness reuse, byte reservation,
  search/watch coalescing, and revision cancellation.
- [Accepted decisions](decisions-2026-07-24.md) — binding choices and
  implementation order.
- [Accepted decisions 2026-07-28](decisions-2026-07-28.md) — one operated
  managed service; self-hosting removed as a product surface.
- [Accepted decisions 2026-07-29](decisions-2026-07-29.md) — `socialname.net`
  as the product domain; Neon plus Cloudflare Containers as the lowest-cost
  hosting posture.
- [First hosted deployment runbook](hosted-deployment.md) — provider
  evaluation, published image digests, and the ordered path to the external
  deployment evidence gates.
- [First rule promotion runbook](promotion-runbook.md) — what the canary
  fleet already produces, the ordered path from reports to an activated
  rule, and why promotion is deliberately not automated.
- [Data governance](data-governance.md) — consent grants, evidence capsules,
  retention, lineage, and deletion guarantees.
- [Bounded Evidence Capsule v1](evidence-capsule-v1.md) — closed sanitized
  evidence, scoped inspection, database-time deadlines, bounded purge, and
  payload-free receipts.
- [Lineage-backed deletion workflows](deletion-workflows.md) — contributor and
  verified-target intake, immediate hiding, suppression, recomputation,
  current-primary purge, least privilege, and remaining gates.
- [Assertion trust](assertion-trust.md) — evidence classes, producer reputation,
  quorum, conflict, and notification confirmation.
- [Signed webhook delivery](webhook-delivery.md) — logical deduplication,
  destination encryption, HMAC payloads, outbound SSRF policy, fenced retry,
  dead letter, audit, and operator boundaries.
- [Minimal monitoring console](monitoring-console.md) — Topcoat evaluation,
  bounded read API, memory-only browser credential policy, presentation, and
  deployment gates.
- [Operational reporting and software objectives](operational-reporting.md) —
  exact cohorts, fixed targets, current backlog/deletion health, independent
  scope, no-data semantics, and production evidence boundary.
- [Developer quota, usage, and service reporting](developer-usage-reporting.md)
  — atomic UTC-day target-pair admission, immutable target-free usage,
  independent aggregate scope, fixed search objectives, and bounded expiry.
- [Search-completion webhooks](search-completion-webhooks.md) — idempotent
  per-search binding, terminal-state convergence, minimal signed payload,
  cancellation, and deletion lineage.
- [Plan entitlements and billing boundary](plan-entitlements-billing.md) —
  closed capabilities, effective/suspended access, digest-only reconciliation,
  admission gates, least privilege, and external payment-provider boundary.
- [Team organizations, review, audit, and retention](team-workflows.md) —
  one-workspace organization boundary, closed role authorization, member
  lifecycle, confirmed-transition review, target-free audit, and enforced
  watch-retention policy.
- [Shared contribution ingestion v1](shared-contributions.md) — minimized
  consented client submissions with replay, quota, anomaly, diversity, and
  reputation admission controls, structurally outside `verified` truth.
- [Installation](installation.md) — desktop and CLI install paths, checksum
  verification, unsigned-build warnings, and the distribution gaps that need
  accounts rather than code.
- [Representative validation](site-rule-v1-validation.md) — discovery evidence,
  ten-site proof set, fixtures, and live acceptance gates.
- [Desktop application](desktop-application.md) — Tauri selection, native
  boundary, first GUI slice, and platform policy.

## Vocabulary

These terms have distinct meanings and should not be used interchangeably:

- **Search**: a user request covering one or more usernames and sites.
- **Probe**: one concrete network operation against a site.
- **Observation**: an immutable result produced by one probe execution at a
  particular time and vantage point.
- **Assertion**: the best current interpretation derived from one or more
  observations.
- **Vantage**: the network location and execution environment from which a
  probe ran.
- **Rule**: a typed definition of how to build probes and classify evidence for
  one site.
- **Rule pack**: a versioned, signed, distributable collection of compiled
  rules.
- **Watch**: a persisted request to re-evaluate a target and emit state-change
  notifications.

## Current execution focus

The **First paid monitoring loop** software gate is complete. Managed
observation, assertion recomputation, meaningful transitions, signed webhook
delivery, and the minimal API-backed console form the tested loop. Milestone 3,
**Trust, governance, and multi-region operation**, has completed its
repository-completable software. Hosted schedule history, provider inventory,
multi-region deployment, retained production SLO history, and live notification
evidence remain external.

The **Developer platform** repository software gate is complete: stable
REST/JSON and SSE publication, bounded batch/polling/idempotency, atomic quota,
immutable usage, service reporting, target-free completion webhooks,
consent-bound remote clients, private history/export, and provider-neutral
plan entitlements are verified. Payment-provider integration and hosted
commercial evidence remain external. The next ordered roadmap milestone is
**Team workflows and quality network**.

Representative live rules remain discovery-only until external regional
evidence exists. Infrastructure, pricing, scale, and community-network choices
remain deferred until their roadmap trigger is measured.
