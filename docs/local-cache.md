# Local cache

The local cache is a user-controlled SQLite database for immutable SocialName
observations and cache-management metadata. It is an optional local product
component: opening or using it does not contact a SocialName service. It can
persist and read domain observations, but does not implement synchronization,
export, search integration, or source-mode presentation yet.

## Ownership and opening policy

`socialname-cache` embeds forward-only SQL migrations into the binary. Opening
a database:

1. creates it when absent;
2. rejects a nonzero SQLite application ID that is not SocialName's;
3. rejects a successful migration version newer than the binary supports;
4. enables WAL, full synchronous writes, foreign keys, and a bounded busy
   timeout only after the ownership and version preflight;
5. applies the embedded migrations; and
6. requires the exact current schema version and a successful SQLite
   `quick_check`.

The cache does not reinterpret a foreign, future, or corrupt database as an
empty cache. That distinction prevents storage failure from silently becoming
an account-state result. Reopening a current database is migration-idempotent.

Migration SQL is forced to LF in `.gitattributes`, and the crate build script
tracks the migration directory so embedded migration hashes cannot drift
silently after an SQL edit.

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

This API establishes safe cache eligibility only. Later source-policy work
must label cached data as cached, derive any current interpretation from the
observation set, and decide whether to refresh locally.

## Privacy and failure behavior

Normalized usernames and public identifiers are sensitive local product data.
The cache API does not log them, serialize them for sync, or expose raw SQL
connections. Ordinary local execution remains independent of any SocialName
service.

Opening failure is explicit:

- a foreign application ID is refused before WAL is enabled;
- a newer schema is refused instead of downgraded;
- migration errors are returned without producing observations;
- integrity failure is distinct from a valid empty cache.
- immutable-ID conflicts and incomplete stored records are distinct from a
  cache miss.

Recovery, export, maximum-size policy, pruning, and complete deletion remain
separate roadmap items so none of those behaviors is implied before it is
implemented and tested.

## Verification

```console
cargo test --locked -p socialname-cache
cargo clippy --locked -p socialname-cache --all-targets --all-features -- -D warnings
```

The deterministic tests cover first initialization, schema ownership and
integrity, idempotent reopen, foreign and future database refusal, corrupt
input, complete domain round trips, exact replay, immutable-ID conflict,
transaction rollback, missing metadata, observation immutability, and deletion
for later pruning. Eligibility tests cover exact hits, target/site/region/rule
misses, current and captured rule health, verdict filtering, expiry, maximum
age, negative TTL, access accounting, invalid queries, and bounded conflict
preservation.
