# SocialName v2 design notes

This directory records the investigation and design decisions for rebuilding
SocialName. The current Python package is treated as a legacy reference, not as
the implementation foundation for v2.

The design was last reviewed on 2026-07-25.

## Authority and execution

- [Ultimate goal](ultimate-goal.md) is the stable, authoritative product
  charter: mission, promise, value system, North Star, boundaries, and decision
  filter.
- [`ROADMAP.md`](../ROADMAP.md) is the canonical execution order: current
  milestone, software gates, external evidence gates, and completion evidence.
- [Accepted decisions](decisions-2026-07-24.md) records binding architecture,
  trust, governance, and client decisions.
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
- a Tauri 2 Windows/macOS desktop slice with local streaming and explicit
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
- [Canary workflow operations](canary-workflows.md) — disabled-by-default
  manual and scheduled managed-vantage templates with fixed budgets.
- [Local cache](local-cache.md) — embedded SQLite persistence, eligibility,
  maintenance, export, recovery, deletion, and fail-closed behavior.
- [Accepted decisions](decisions-2026-07-24.md) — binding choices and
  implementation order.
- [Data governance](data-governance.md) — consent grants, evidence capsules,
  retention, lineage, and deletion guarantees.
- [Assertion trust](assertion-trust.md) — evidence classes, producer reputation,
  quorum, conflict, and notification confirmation.
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

The current milestone is **Trustworthy local product**. The canonical task
breakdown and acceptance evidence live in [`ROADMAP.md`](../ROADMAP.md):

1. Add explicit `local` and `cache` source modes with `sync=never` to the CLI.
2. Expose source and freshness policy through the desktop application.

Infrastructure, pricing, scale, and community-network choices remain deferred
until their roadmap trigger is measured.
