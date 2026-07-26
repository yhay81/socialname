# Decisions: 2026-07-24

This record supersedes conflicting provisional language in `product.md`,
`architecture.md`, and `site-rules.md` until those overview documents are
integrated.

The [ultimate goal](ultimate-goal.md) is the authoritative product charter.
The live implementation order is maintained in [`ROADMAP.md`](../ROADMAP.md)
so status does not diverge across design records.

## Accepted

- The web console evaluates Topcoat first at a replaceable UI boundary.
- The public Developer API, SSE, authentication enforcement, and background
  jobs remain Axum/Tower services.
- SocialName collects rich Evidence Capsules when a versioned, purpose-specific
  consent grant permits it.
- Private history, shared observation, and shared research are separate grants.
- Contributor consent does not substitute for a lawful basis or data-subject
  process for a third-party target username.
- Shared structured Evidence Capsules have an initial 400-day retention period.
- Assertions have no independent retention and must be recomputed when support
  is deleted or expires.
- Deletion is lineage-backed, removes production data within 24 hours, and ages
  data out of encrypted backups within 35 days.
- Strict independent shared-client quorum may establish a `corroborated`
  assertion. Only eligible managed evidence can establish `verified`.
- Shared-only absence cannot trigger a disappearance notification.
- Site Rule v1 is proven against ten representative sites, including blocked
  and soft-404 cases; a correct `inconclusive` is part of acceptance.
- The Windows and macOS application uses Tauri 2 with a React/Vite presentation
  layer and the Rust engine linked directly into the process.
- Desktop webviews receive no generic HTTP, filesystem, database, or shell
  capability. Product operations cross explicit typed commands.
- Trustworthy Coverage Time is the primary product North Star; search volume or
  nominal site count cannot override correctness, freshness, continuity,
  privacy, or deletion guardrails.
- Roadmap gates distinguish repository-completable software from external
  deployment, elapsed measurement, credential, signing, and production
  evidence. Missing external evidence keeps a capability disabled but does not
  authorize fabricated validation.
- Rule health is scoped to an exact site, rule hash, and managed region. New
  records start quarantined; two distinct fresh aggregate-plus-shadow passes
  are required for recovery, two consecutive operational failures quarantine,
  and any classification failure quarantines immediately. Health transitions
  never authorize account-state notifications.
- Rule promotion is a domain-separated Ed25519 statement over one exact
  candidate, canonical rule pack, previous pack, manifest, engine, required
  region set, accepted evidence identities, and at-most-24-hour expiry.
  Activation revalidates the real pack, enforces a monotonic sequence and exact
  predecessor, and retains the complete prior validated pack for explicit
  rollback without lowering the anti-replay high-water mark. Trust policy maps
  key IDs to public keys so rotation can overlap deliberately.
- The local cache is a SocialName-identified SQLite database with embedded
  forward migrations. It refuses foreign application IDs, newer successful
  migration versions, and integrity failures instead of treating them as an
  empty cache. Observations are immutable; mutable access metadata is a
  separate child record, while explicit deletion remains available for
  pruning and complete local deletion.
- Local observation persistence is transactional across the immutable
  observation and its initial cache metadata. Exact replay of an observation ID
  is idempotent, different immutable content under that ID is a conflict, and
  missing metadata or an unknown stored enum is an error rather than a cache
  miss.
- Cache eligibility requires the exact target, region class, current rule hash,
  current healthy regional rule state, captured green health, observation
  expiry, request maximum age, and explicit verdict policy. It returns the
  bounded matching observation set rather than choosing a latest boolean;
  overflow fails instead of hiding possible conflicts.
- Cache maintenance deletes expiry-first and then deterministic LRU rows under
  nonzero observation-count and logical-payload-byte limits. Logical payload
  is explicitly not SQLite file size. Export is an explicit, create-new,
  versioned JSONL snapshot that contains sensitive target data and never
  implies synchronization.
- Cache recovery is explicit quarantine, not salvage: healthy, foreign,
  nonempty unowned, and future-schema databases are preserved and refused;
  corrupt current data and sidecars move to an adjacent quarantine before a
  new empty cache is created. Complete deletion consumes the cache and removes
  its journal, SHM, WAL, and main file without claiming secure media erasure.
- CLI source and synchronization are orthogonal. `local` and strictly offline
  `cache` sources currently accept only `sync=never`; unsupported sync values
  fail parsing. Cache lookup never constructs the network engine or falls back
  to a probe, and requires both a promoted rule and fresh exact regional health
  evidence. Human and JSON envelopes identify source, freshness, health, rule,
  and refresh state.
- `socialname-app-core` is the shared local/cache policy boundary for CLI and
  desktop. Its result envelope keeps the complete cached observation set
  separate from an optional live result. The Tauri shell resolves the
  application-local database path and reports cache availability; the webview
  receives neither a path nor filesystem/database capabilities. Cache opening
  failure disables cache mode without disabling an independent local probe.
- Cache schema v2 distinguishes `local_cli` and `local_desktop` producer
  lineage. The v1-to-v2 migration rebuilds the constrained table while
  preserving immutable observations and access metadata.
- Desktop cached-first execution uses requested source `hybrid` while preserving
  the actual `cache` or `local` origin on each emitted result and observation.
  The cache phase is emitted before the local executor starts; cancellation
  after that phase retains cached evidence and prevents the local call. The CLI
  rejects `hybrid` until it has a versioned ordered-event output contract.
- Public API v1 is an independent, closed wire contract in
  `socialname-protocol`, not direct serialization of mutable domain or app-core
  types. Ordered search events structurally separate definitive observations,
  uncertainty, and operational failure. Cross-field validation binds freshness,
  purpose-specific sync consent, watch bounds, transition confirmation, and
  delivery state. Sensitive destinations and usernames redact `Debug`, and
  errors never echo rejected values or raw response data.
- The modular-monolith server starts as a separate Axum/Tower binary with a
  loopback-only default, bounded deadline/body/concurrency, target-free request
  tracing, closed protocol errors, hardened health responses, and graceful
  shutdown. A product route does not exist until its ordered slice supplies the
  complete authentication, authorization, persistence, and failure boundary.
- API keys use an independent 64-bit public prefix and 256-bit CSPRNG secret;
  only SHA-256 secret digests are stored. Authentication performs a restricted
  global digest lookup because the tenant is not yet known, then rechecks
  active key, expiry, scope, and tenant through a non-owner connection under
  forced transaction-local RLS. Operator-only bootstrap, issue, and revoke
  operations are transactional and audited; the one-time secret is never a
  protocol resource or normal log value.
- Managed search creation rejects `sync=never`, requires `remote`/`hybrid` and
  an active purpose-specific account consent bound to the API-key membership,
  and hashes the tenant-scoped idempotency key. Exact replay returns the
  original search; changed content conflicts. Search events are append-only
  tenant-RLS records with an explicit per-search sequence and target relation.
  SSE uses event UUIDs for bounded `Last-Event-ID` replay and rechecks
  authorization while connected. The API creates/cancels work but has no
  network authority; a separate signed worker can now expand, claim, execute,
  and atomically ingest only an exact promoted, region-healthy rule binding.
- Active managed work coalesces only across equal tenant, normalized target,
  site, rule version, region, consent grant, and visibility. Attempt count is a
  fencing token. A non-owner NOBYPASSRLS worker receives only six narrow
  coordinator functions; tenant rows remain behind transaction-local forced
  RLS. Final ingestion rechecks rule health and locks purpose-specific consent
  before atomically writing one immutable observation, per-search events,
  watch-run target state, terminal state, and lineage.
- Central `assertion/v1` recomputation serializes by tenant target, admits only
  current strong exact-rule observations with active consent, versions the
  current interpretation and explicit support, and emits the same assertion
  to managed-search consumers. Each watch target owns its initial account
  baseline; only E4/E3-follow-up appearance or independently confirmed
  disappearance advances it. Conflicts suppress candidates. Typed uncertainty
  and terminal operational failure create regional measurement transitions
  and never account disappearance; an operational measurement transition uses
  probe-job lineage instead of a fabricated observation.

## Detailed records

- [Data governance](data-governance.md)
- [Assertion trust](assertion-trust.md)
- [Site Rule v1 representative validation](site-rule-v1-validation.md)
- [Site rule base design](site-rules.md)
- [System architecture](architecture.md)
- [Desktop application](desktop-application.md)
- [Ultimate goal](ultimate-goal.md)
- [Execution roadmap](../ROADMAP.md)
- [Regional rule health](rule-health-v1.md)
- [Signed rule promotion](rule-promotion-v1.md)
- [Local cache](local-cache.md)
- [Public protocol v1](protocol-v1.md)
- [Modular-monolith server shell](server.md)
- [PostgreSQL schema and migrations](postgresql-schema.md)
- [Authenticated private workspaces and API keys](authenticated-workspaces.md)
- [Private search API and ordered event stream](search-api.md)
- [Managed probe jobs and observation ingestion](managed-jobs.md)
- [Assertion recomputation and transition persistence](assertion-recomputation.md)

## Implementation baseline

1. **Partial:** Encode observation and assertion types in
   `socialname-domain`. Consent, deletion, and full Evidence Capsule types move
   into the server/data slice.
2. **Done:** Define strict Site Rule v1 source and compiled schemas.
3. **Done:** Implement deterministic fixtures for the representative ten sites.
4. **Done:** Implement the local probe engine and matcher trace.
5. **Done:** Implement assertion replay with synthetic producers and conflicts.
6. **Done:** Add the local Tauri desktop search vertical slice and native
   Windows/macOS compile CI.
7. **Done:** Add the independent public protocol v1 DTO and JSON Schema
   boundary.
8. **Done:** Add the bounded Axum/Tower modular-monolith process shell.
9. **Done:** Add the embedded PostgreSQL schema, forced tenant RLS, lineage,
   deletion, and real PostgreSQL 18 migration gate.
10. **Done:** Add transactional workspace/API-key operator lifecycle,
    digest-only credential authentication, a non-owner forced-RLS runtime
    boundary, database-aware readiness, and the first private workspace route.
11. **Done:** Add consented idempotent private-search creation, polling,
    cancellation, append-only ordered event persistence, and bounded resumable
    SSE without enabling managed probe execution.
12. **Done:** Add a separate `socialname-worker` whose execution capability can
    only be constructed from a verified regional rule promotion and an exactly
    recompiled pack. Managed transport disables proxies, revalidates every DNS
    answer at connection/redirect time, rejects any special/private/mixed
    answer set, and independently bounds parsed headers, compressed bytes,
    decompressed bytes, and inspected text. The only operator probe reads its
    target from bounded stdin JSON and requires explicit live acknowledgement.
13. **Done:** Connect eligible accepted searches to that worker through
    consent/visibility-isolated job expansion, fenced claims and lease
    reclamation, bounded retries, continuous cancellation/authorization
    monitoring, and idempotent atomic observation/event/lineage ingestion under
    a non-owner forced-RLS worker role.
14. **Done:** Add authenticated revisioned watches, atomic due-run expansion,
    deterministic bounded jitter, exact-rule freshness reuse, conservative
    pre-network byte reservation, search/watch work coalescing, and
    revision/consent-aware cancellation under the same forced-RLS worker
    boundary.
15. **Done:** Recompute exact-rule `assertion/v1` generations transactionally,
    stream assertion updates, establish per-watch account baselines, confirm or
    suppress meaningful account candidates, and persist measurement
    degradation separately with complete support and generic lineage.

Milestone 1's repository-completable software gate is done. Its external live
rule evidence remains pending and all affected rules stay disabled. The next
work in Milestone 2 is deduplicated signed webhook delivery from already
confirmed transitions.
