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
- Consent contract identity is `(purpose, profile version, notice version)`.
  Account grants derive their subject from the active API-key membership;
  installation grants store only a tenant-separated digest and are owned by
  the first registering membership, so another workspace administrator cannot
  override refusal. Withdrawal is immediate and immutable. Prior-contribution
  deletion is not claimed until the lineage-backed workflow can meet its
  deadlines.
- Contributor consent does not substitute for a lawful basis or data-subject
  process for a third-party target username.
- Shared structured Evidence Capsules have an initial 400-day retention period.
- Private interactive Evidence Capsules retain for 90 days; private watches
  use their accepted 30–730 day setting; one coalesced observation uses the
  longest live consumer period. Shared-research excerpts are independently
  capped at 2 KiB and 30 days. Product reads enforce database deadlines before
  bounded physical cleanup.
- Assertions have no independent retention and must be recomputed when support
  is deleted or expires.
- Deletion is lineage-backed, removes production data within 24 hours, and ages
  data out of encrypted backups within 35 days.
- Contributor deletion is selected by an owned consent subject and purpose,
  revokes every matching active grant, and materializes immutable hide
  tombstones before returning. Target-person deletion requires an externally
  verified stdin operator case, affects only exact matching shared
  observations, and routes private tenant records separately.
- Contributor/target selectors are retained only as tenant-separated,
  length-framed HMACs. The 256-bit suppression key is stable for every
  unexpired token; a legacy or different active key fingerprint fails closed
  for consent, target operation, and shared managed execution. This boundary
  does not claim online suppression-key rotation.
- Primary deletion atomically withdraws support, recomputes from remaining
  observations, purges current PostgreSQL dependencies, and leaves the request
  `rebuilding`. Analytics completion, receipts, restore replay, production
  scheduling, and backup-expiry proof remain a distinct next gate.
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
- Rule-pack distribution is a second domain-separated threshold-Ed25519
  envelope over the exact pack, predecessor, required regions, rollout stage,
  candidate trust generation, and every site promotion. Metadata and per-site
  promotion sequences are durable monotonic high-water marks. Candidate trust
  stays staged through canary/regional evaluation and becomes current only on
  general activation or signed rollback. Rotation advances one generation and
  must satisfy both current and candidate thresholds; rollback restores only
  the retained exact release and never lowers either replay floor.
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
  fencing token. A non-owner NOBYPASSRLS worker receives only seven narrow
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
- A confirmed transition creates at most one logical webhook delivery per
  tenant/transition/endpoint in the same transaction. Attempts reuse one stable
  delivery ID and signed body. The network guarantee is at least once, so
  receivers deduplicate that ID. Destinations are endpoint-bound
  XChaCha20-Poly1305 envelopes; the HMAC-signed outbound client is HTTPS-only,
  public-address-only, proxy-free, redirect-free, time-bounded, lease-fenced,
  and response-body-blind. Attempt history, audit, and lineage retain closed
  metadata rather than destinations or bodies.
- Email is a second channel-specific logical delivery, not a webhook-shaped
  special case. It uses a distinct logical-key/envelope domain and claim
  coordinator, derives a fixed plain-text message from a confirmed
  `EmailNotification`, and submits one bounded JSON request to an
  operator-owned HTTPS gateway. The stable delivery ID is the gateway
  idempotency key. Provider SDKs, SMTP credentials, HTML/tracking content,
  response bodies, recipients, and gateway secrets stay outside persisted
  attempt/audit/lineage metadata. Sending-domain, endpoint-ownership,
  bounce/complaint, and live delivery evidence remain external gates.
- Notification acknowledgement is one authenticated, tenant-local,
  append-only receipt per successfully delivered logical notification. It is
  idempotent, records private membership/API-key attribution, exposes only the
  delivery ID and database time, and is hidden with deletion lineage. It does
  not prove email open, webhook processing, or Team review.
- Topcoat 0.4.0 was evaluated at the replaceable web boundary and rejected for
  the Milestone 2 console because its experimental direct-data model would add
  a second authentication/authorization path. The implemented React/Vite
  client consumes only bounded same-origin Axum API v1 resources, keeps a
  pasted scoped key in page memory only, and has no CORS or direct PostgreSQL
  access.
- Operational reporting uses an independent `operations:read` scope and one
  target-free tenant aggregate rather than deriving workspace totals from
  paginated watch pages. Database time defines closed 24-hour, 7-day, and
  30-day cohorts. Initial software objectives are 99.0% terminal watch-run and
  per-channel delivery success, five-minute per-channel
  transition-to-delivery p95, and zero current overdue deletion milestones.
  `no_data` is distinct from success. Deletion is a current deadline-health
  snapshot because the existing schema does not support a complete historical
  compliance claim; production SLA history remains external evidence.
- API v1 publication is generator-owned and committed as OpenAPI 3.1.2,
  independent Draft 2020-12 roots, an exact SocialName SSE contract, and a
  SHA-256 drift manifest. One closed registry owns the 22 published
  method/path/schema/scope descriptions; Axum keeps an independent
  operation-to-scope mapping and tests route registration plus exact scope
  agreement. The publication declares no production origin or availability.
  Existing v1 field, enum, union, scope, status, or SSE semantic
  incompatibility requires a new public version and migration policy.
- Global and regional `assertion/v1` interpretations are derived from the same
  eligible exact-rule observations and evaluation time. Cross-region
  disagreement preserves definitive regional projections behind one global
  conflict; same-region disagreement remains regionally conflicted. Regional
  support is immutable and lineage-backed. Historical event JSON remains
  readable without a regional field, but missing historical projections are
  never inferred or backfilled. Managed verification may raise only an
  already-budgeted queued/retry watch job: regional conflict outranks pending
  account confirmation, which outranks routine work. Priority alone cannot
  create a probe, region, or deployment claim.

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
- [Signed rule-pack distribution](rule-pack-distribution-v1.md)
- [Local cache](local-cache.md)
- [Public protocol v1](protocol-v1.md)
- [Modular-monolith server shell](server.md)
- [PostgreSQL schema and migrations](postgresql-schema.md)
- [Authenticated private workspaces and API keys](authenticated-workspaces.md)
- [Private search API and ordered event stream](search-api.md)
- [Managed probe jobs and observation ingestion](managed-jobs.md)
- [Assertion recomputation and transition persistence](assertion-recomputation.md)
- [Signed webhook delivery](webhook-delivery.md)
- [Email delivery](email-delivery.md)
- [Notification acknowledgement](notification-acknowledgement.md)
- [Minimal monitoring console](monitoring-console.md)
- [Purpose-specific consent grant lifecycle](consent-api.md)
- [Bounded Evidence Capsule v1 and retention enforcement](evidence-capsule-v1.md)
- [Lineage-backed deletion workflows](deletion-workflows.md)

## Implementation baseline

1. **Done:** Encode observation and assertion types in
   `socialname-domain`, with consent, closed Evidence Capsule, and
   lineage-backed deletion contracts at the protocol/server/worker boundaries.
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
    only be constructed from threshold-validated pack metadata, its verified
    regional site promotion, and an exactly recompiled pack. Managed transport
    disables proxies, revalidates every DNS
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
16. **Done:** Enqueue one logical delivery from each confirmed transition,
    encrypt destinations, sign stable webhook payloads, enforce public-only
    outbound networking, fence bounded retries and dead-letter state, and
    preserve append-only attempts, audit, and lineage.
17. **Done:** Add bounded watch-list and transition/delivery timeline API v1
    resources under tenant-local forced RLS, then consume them from a
    same-origin React/Vite monitoring console with memory-only scoped-key
    handling and independent CI.
18. **Done:** Derive compatible regional assertion projections, persist their
    immutable support and two-layer lineage, preserve per-region truth behind
    a global conflict, and prioritize already-budgeted managed verification for
    conflicts and high-value account candidates.
19. **Done:** Compose site promotions into threshold-signed rule-pack
    metadata; enforce expiry and canary/regional/general worker selection;
    persist trust, active/staged/LKG state, and replay floors in PostgreSQL;
    bind managed jobs to exact metadata and promotion identities; and prove
    overlap rotation, old-key removal, and signed rollback.
20. **Done:** Add exact purpose/profile/notice consent resources for account
    and installation subjects, tenant-separated installation digests with
    membership non-override, scoped bounded APIs, serialized replay-safe
    creation, append-only actor history, and immediate one-way withdrawal.
21. **Done:** Add one closed 64 KiB Evidence Capsule per managed observation,
    exact signed provenance, sanitized summaries, scoped database-deadline
    inspection, consumer-specific retention, bounded irreversible purge, and
    payload-free three-year receipts.
22. **Done:** Add owned contributor deletion and externally verified
    target-person workflows with immediate lineage-backed hiding, exact
    deadlines, HMAC-only fail-closed suppression, remaining-support
    recomputation, fenced current-primary deletion, private-target routing,
    and exact replay before and after physical purge.
23. **Done:** Add daily delete-through scheduling, fixed-shape completion
    receipts, inventory- and deadline-gated backup expiry, authenticated
    target-free restore-ledger replay, and restore-aware readiness quarantine.
24. **Done:** Add delivered-only notification acknowledgement with closed
    protocol resources, exact replay, forced tenant RLS, private audit
    attribution, deletion hiding, and same-origin console action.
25. **Done:** Add provider-neutral HTTPS email delivery with a confirmed-only
    canonical DTO, channel-separated logical identity, encryption and claim
    domains, stable gateway idempotency, fixed plain text, public-only
    networking, bounded retry/dead letter, and secret-free audit/lineage.
26. **Done:** Add a closed target-free operational report under an independent
    scope, database-time fixed windows, derived `no_data`/`meeting`/`breached`
    objectives, channel-separated delivery success and latency, current
    deletion deadline health, and a responsive same-origin dashboard.
27. **Done:** Publish all implemented API v1 operations as deterministic
    OpenAPI 3.1.2, Draft 2020-12 JSON Schema, exact resumable SSE, and
    digest-manifest artifacts with committed-byte, route, and scope drift
    gates.

Milestones 1 and 2 have completed their repository-completable software gates.
Their external live-rule, destination-ownership, hosted-security, and managed
deployment evidence remains pending, with affected capabilities disabled.
Milestone 3's deployment/operator artifact, regional assertion behavior,
signed rule-pack distribution, purpose-specific consent lifecycle, bounded
Evidence Capsule retention, lineage-backed deletion and restore drills,
notification acknowledgement, email delivery, and operational reporting are
repository-complete, while actual multi-region deployment, retained production
SLO history, and mail-provider evidence remain external gates. Milestone 4 has
started with stable REST/JSON and SSE publication. The next ordered
repository-completable work is its batch-search, quota, usage-record, and
service-reporting boundary.
