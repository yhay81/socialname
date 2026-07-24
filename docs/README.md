# SocialName v2 design notes

This directory records the investigation and design decisions for rebuilding
SocialName. The current Python package is treated as a legacy reference, not as
the implementation foundation for v2.

The design was last reviewed on 2026-07-24.

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
- ten representative rules with 30 minimized offline cases.

`cargo test --workspace --all-targets` verifies the slice without Internet
access. Live canaries are intentionally a separate acceptance gate.

## Documents

- [Research findings](research.md) — legacy history, current Sherlock, adjacent
  projects, and distributed-measurement lessons.
- [Product vision](product.md) — users, value, execution modes, privacy, and
  commercial direction.
- [System architecture](architecture.md) — central server responsibilities,
  trust model, data model, API, and technology choices.
- [Site rule design](site-rules.md) — rule authoring, classification, validation,
  packaging, and migration.
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

## Next implementation decisions

The following remain deliberately open until the next vertical slices provide
measurements:

- Site-specific freshness policies and monitoring intervals.
- Pricing and quota boundaries for developer API and monitoring plans.
- PostgreSQL job/SSE coordination performance and failover behavior.
- Signing, expiry, rollback, and key-rotation details for distributed rule
  packs.
- Whether a separately installed, explicitly operated community probe network
  is justified after managed regional workers are established.
