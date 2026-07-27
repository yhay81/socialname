# Local cache

The local cache is a user-controlled SQLite database for immutable SocialName
observations and cache-management metadata. It is an optional local product
component: opening or using it does not contact a SocialName service. It can
persist and read domain observations and is integrated with the CLI and
desktop application's explicit source policy. Cached-first local and
remote-assisted streaming are implemented, but the cache itself never performs
networking or synchronization.

## Ownership and opening policy

`socialname-cache` embeds forward-only SQL migrations into the binary. Opening
a database:

1. creates it when absent;
2. rejects a nonzero SQLite application ID that is not SocialName's and refuses
   to adopt a nonempty unowned database with application ID zero;
3. rejects a successful migration version newer than the binary supports;
4. resolves a file-backed path to its existing file or parent-directory
   identity so later deletion targets the database rather than a symlink;
5. enables WAL, full synchronous writes, foreign keys, and a bounded busy
   timeout only after the ownership and version preflight;
6. applies the embedded migrations; and
7. requires the exact current schema version, a successful SQLite
   `integrity_check`, no foreign-key violations, and no observation missing its
   cache metadata.

The cache does not reinterpret a foreign, future, or corrupt database as an
empty cache. That distinction prevents storage failure from silently becoming
an account-state result. Reopening a current database is migration-idempotent.

Migration SQL is forced to LF in `.gitattributes`, and the crate build script
tracks the migration directory so embedded migration hashes cannot drift
silently after an SQL edit.

Schema v2 adds distinct `local_desktop` producer lineage alongside `local_cli`.
Its forward migration rebuilds the constrained observation table and preserves
both immutable observations and cache access metadata. A deterministic test
creates a real schema-v1 database, inserts an observation and metadata, opens it
with the current binary, and verifies the v2 round trip.

## Schema boundary

`local_observations` stores the full domain fields needed to interpret an
observation at its original time and vantage:

- observation, site, normalized-username, rule, and evidence identities;
- verdict and a separately constrained inconclusive reason;
- evidence class, rule-health state, observed time, and expiry;
- region, network, independence, producer, reputation, and collection policy;
- the local insertion time.

Rows are immutable after insertion. A database trigger rejects updates, while
deletion remains available for explicit pruning and complete local deletion.
SQLite constraints preserve the same distinctions as the domain model,
including `found`, `not_found`, invalid input, and operational uncertainty.

`observation_cache_metadata` is a separate child row for mutable cache facts:
when the observation was cached, last access, and access count. Deleting an
observation cascades to this metadata. Eligibility and expiry indexes include
normalized username, site, region class, rule hash, observation time, and
expiry. Eligibility is evaluated over the observation set rather than inferred
from the latest row.

## Persistence contract

`LocalCache::store_observation` accepts a typed domain `Observation` plus the
local cache time. It validates bounded identities, exact lowercase digest
encoding, expiry order, cache time, and the relationship between verdict and
inconclusive reason before writing.

The immutable observation and its initial metadata row are inserted in one
transaction. A first insert returns `Inserted`; replaying the exact same
observation ID and content returns `AlreadyPresent` without changing its
original cache time. Reusing an observation ID for different immutable content
returns an explicit conflict and preserves the first row. A metadata insert
failure rolls the observation insert back.

`LocalCache::get_observation` reconstructs the complete closed domain enums and
returns cache metadata separately. A missing observation returns no result.
An existing observation with missing metadata, an unknown stored enum, or
otherwise invalid stored content returns an explicit error rather than a cache
miss or verdict.

## Eligibility contract

`LocalCache::eligible_observations` requires an explicit query containing:

- normalized username and site;
- region class and exact current rule hash;
- current regional rule health;
- evaluation time and maximum acceptable age;
- an exact, definitive-only, or all-observation verdict policy.

An observation is reusable only when all key fields match, both its captured
health and current regional health are green, it is not from the future, its
own expiry is later than the evaluation time, and its age is within the
request's maximum. The observation expiry retains verdict-specific TTLs, so a
short-lived `not_found` cannot inherit the longer life of a `found` result.
Changing a rule hash or region creates a miss rather than a broad fallback.

The query returns every eligible observation in deterministic newest-first
order. It never selects one latest boolean from potentially conflicting
evidence. The result set is bounded at 256; exceeding the bound is an explicit
error rather than silent truncation. A successful hit transaction increments
access count and advances last-access time for every returned observation.
Misses and failed or oversized queries do not touch metadata.

This API establishes safe cache eligibility only. The application core labels
cached data as cached, preserves the complete observation set, and decides
whether a requested `hybrid` search should continue to a local executor or the
separately configured managed client. Cache access never implies either path.

## Maintenance and size limits

`LocalCache::maintain` takes an explicit evaluation time, maximum observation
count, and maximum logical payload bytes. It validates both nonzero limits
before changing data, verifies cache integrity, deletes expired observations
first, and then removes the least-recently-used rows until both limits hold.
LRU ties use observation time and observation ID for deterministic behavior.
Metadata deletion follows through the foreign key.

Logical payload bytes count the UTF-8 bytes of every persisted text field plus
the fixed-width domain and metadata integers. This is a deterministic limit on
sensitive product data, not a claim about the SQLite main-file, WAL, allocator,
or filesystem byte count. The maintenance report records observations and
logical bytes before and after, with expiry and capacity deletions separated.
If the requested limits are not reached, the transaction rolls back and
returns an error.

## Explicit export

`LocalCache::export_jsonl` creates a new file and refuses to overwrite any
existing path. The first line is a
`socialname.dev/local-cache-export/v1` manifest with the caller-supplied export
time and snapshot observation count. Following lines contain complete typed
observations and separate cache metadata in deterministic chronological order.
Every line is self-identifying JSON.

The export uses one database snapshot, validates every stored row, flushes and
synchronizes the completed file, and reports its exact byte count. On Unix the
new file mode is `0600`; Windows uses the containing directory's ACL. An
invalid cache creates no export, and a failure after creation removes only the
new partial file or reports cleanup failure explicitly. Export includes target
identifiers and is therefore a deliberate sensitive-data action; it is never
sync.

## Recovery and complete deletion

Recovery is never automatic. `LocalCache::recover` first tries the normal
fail-closed open path:

- a healthy cache returns `RecoveryNotRequired` and remains untouched;
- a foreign application ID, a nonempty unowned database, or a future schema is
  refused and is not renamed or downgraded;
- a corrupt or failed current cache is closed, then its main file and available
  WAL/SHM/journal sidecars are renamed together to a unique adjacent
  `.corrupt-<process>-<sequence>` quarantine path;
- only after quarantine succeeds is a new empty migrated cache created.

The quarantine is retained for explicit inspection or deletion; no
observations are silently salvaged into trusted results. If new-cache creation
fails, recovery removes its partial files and restores the quarantine. Windows
file sharing is handled with a short bounded retry, and any incomplete
quarantine or rollback is an explicit error.

`LocalCache::delete_database` consumes and closes a file-backed cache, then
removes its journal, SHM, WAL, and main database in that order. It reports the
number of removed files and stops with an explicit partial-deletion error on
the first non-absence failure. It does not claim secure media erasure.
In-memory caches cannot claim file deletion.

## CLI source and synchronization policy

`socialname search` separates source from synchronization:

```console
socialname search USERNAME --site SITE --source local --sync never
socialname search USERNAME --site SITE --source cache --sync never \
  --cache-path PATH --rule-health-record RECORD
```

`local` is the default source and performs the bounded third-party probe. A
cache path is optional; when supplied it is opened before network work, and a
valid result becomes an immutable `local_cli`/`local_only` observation.
`found`, `not_found`, and `inconclusive` receive initial TTLs of 24 hours,
15 minutes, and 5 minutes respectively. Invalid usernames make no request and
are not persisted. Ctrl-C cancels the in-flight local search future.

`cache` is strictly offline. It requires a cache path, never constructs the
network engine, and does not create a database for a missing path. Reuse also
requires:

- a promoted (`metadata.enabled`) exact rule, so a health record cannot promote
  a discovery rule;
- a structurally valid health record whose site, rule hash, and region match;
- `healthy` state with unexpired evidence;
- the cache eligibility contract above.

Failure remains typed as `rule_not_promoted`, `rule_health_unavailable`,
`rule_not_healthy`, `rule_health_stale`, or `cache_miss`; none falls through to
a live probe. All ten repository rules therefore remain safely
`rule_not_promoted` pending their external acceptance and signed promotion
gate.

Only `sync=never` is accepted. Other synchronization values fail CLI parsing,
independently of source. Both human and JSON output expose source, sync,
completion/miss status, refresh state, promotion and health state, rule hash,
and every returned observation's observed time, expiry, evidence, and region.
Cache output has no `live_result`; local output includes the engine result and
the time-bounded observation. Cached observations are never labelled live, and
cache mode does not imply a refresh.

The shared source type also contains `hybrid`, but the CLI rejects that value.
Its current result boundary produces one terminal envelope and cannot truthfully
stream a cached phase followed by a local phase. CLI cached-first support
therefore waits for a versioned event-stream contract instead of collapsing the
two sources into one result.

## Desktop source and cache boundary

The Tauri shell resolves a fixed application-local
`observations.sqlite3` path, creates only its containing application directory,
and gives `socialname-app-core` the validated cache handle. The React webview
can select `local`, `cache`, or cached-first `hybrid` and can set the bounded
region/maximum-age policy, but it receives no database path and has no
filesystem or database capability.

`local` remains the default and records non-invalid results with
`local_desktop` producer lineage. `cache` remains offline and uses the same
promotion, exact rule/region health, expiry, maximum-age, and definitive-verdict
eligibility checks as the CLI. A site result contains a complete observation
set and a separate optional live result. The UI therefore labels cached data,
shows observed time and expiry for every observation, and does not collapse
conflicting cached observations into one apparent current truth.

`hybrid` emits a cache phase before the local executor is invoked, with
`refresh=pending`, and then emits a separately labelled local phase with
`refresh=completed`. The envelope records both the requested `hybrid` mode and
each result or observation's actual `cache` or `local` origin. The local phase
retains the cached observation set alongside its separately represented live
result. If the event receiver closes after the cache phase, app-core checks
cancellation before invoking the local executor, retaining cached evidence
without starting the probe. Cache initialization or lookup failure is an
explicit non-verdict cache phase and never silently becomes a miss or a live
result.

Cache initialization failure is reported by `get_app_info`; the UI disables
cache selection while local probing remains available. The failure does not
become a cache miss or verdict. The repository embeds no production promotion
or regional health record, so its discovery-only rules remain
`rule_not_promoted` in desktop cache mode.

## Privacy and failure behavior

Normalized usernames and public identifiers are sensitive local product data.
The cache API does not log them, serialize them for sync, or expose raw SQL
connections. Ordinary local execution remains independent of any SocialName
service.

Opening failure is explicit:

- a foreign or nonempty unowned database is refused before WAL is enabled;
- a newer schema is refused instead of downgraded;
- migration errors are returned without producing observations;
- integrity, foreign-key, and missing-metadata failure is distinct from a valid
  empty cache;
- immutable-ID conflicts and incomplete stored records are distinct from a
  cache miss.

Opening, lookup, maintenance, and export never contact a SocialName service.
Recovery and deletion are explicit local calls; later CLI/desktop surfaces
must keep their destructive confirmation and source/sync policy visible.

## Verification

```console
cargo test --locked -p socialname-cache
cargo clippy --locked -p socialname-cache --all-targets --all-features -- -D warnings
cargo test --locked -p socialname-app-core -p socialname-desktop
cd apps/desktop
npm run check
npm run build
```

The deterministic tests cover first initialization, schema ownership and
integrity, idempotent reopen, the data-preserving schema-v1-to-v2 migration,
foreign and future database refusal, corrupt input, complete domain round trips
including CLI/desktop producer lineage, exact replay, immutable-ID conflict,
transaction rollback, missing metadata, observation immutability, and deletion
for later pruning. Eligibility tests cover exact hits, target/site/region/rule
misses, current and captured rule health, verdict filtering, expiry, maximum
age, negative TTL, access accounting, invalid queries, and bounded conflict
preservation. Maintenance and lifecycle tests cover expiry-first and LRU
pruning, count and logical-byte limits, metadata cascade, deterministic export,
overwrite refusal, integrity failure, corrupt-byte quarantine, healthy,
foreign, unowned, and future recovery refusal, Windows close/retry behavior,
and complete database/sidecar deletion.

App-core tests additionally cover a complete offline hit, cache-before-local
event ordering, preservation of cached and local lineage in the refresh phase,
and cancellation after the cache phase with zero local-executor calls.
