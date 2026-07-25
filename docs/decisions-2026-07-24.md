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

The next work is Milestone 1 in `ROADMAP.md`: stream eligible cached observations
before an explicitly labelled local refresh without relabelling either source.
The first paid monitoring loop follows as Milestone 2.
