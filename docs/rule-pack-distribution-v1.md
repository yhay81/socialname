# Signed Rule-Pack Distribution v1

## Purpose

`socialname.dev/rule-pack-metadata/v1` is the authenticated distribution
boundary for one exact canonical rule pack. It composes the site-scoped
regional evidence in `socialname.dev/rule-promotion/v1` into one release,
selects which workers may evaluate that release, and makes expiry, replay
protection, trust rotation, activation, and rollback explicit.

The metadata does not manufacture rule health or deploy a region. Every
included site must already have a valid signed promotion for the same pack,
predecessor, required regions, and validity window. The metadata and embedded
promotions contain no usernames, search targets, response bodies, cookies, or
credentials.

## Artifact model

A public `socialname.dev/rule-pack-trust/v1` root contains:

- a positive generation;
- from one through 16 closed-label Ed25519 key IDs and public keys;
- a threshold no greater than the key count; and
- an absolute public-trust expiry.

Its `trust_id` is the SHA-256 identity of deterministic JSON prefixed by the
trust domain separator. The first database installation requires this exact
identity through a separate operator pin; a metadata file cannot choose its
own initial trust root.

A `socialname.dev/rule-pack-metadata/v1` envelope binds:

- a globally monotonic metadata sequence and content-derived `metadata_id`;
- a content-derived release ID;
- the exact canonical pack hash and exact predecessor, if any;
- one through 16 required regions;
- `canary`, `regional`, `general`, or `rollback` rollout stage and its closed
  eligibility sets;
- issue and expiry times no more than 24 hours apart;
- the complete candidate public trust generation;
- one signed `rule-promotion/v1` envelope per included site, up to 256 sites;
  and
- a bounded map of Ed25519 signatures over the complete metadata payload.

The release ID covers pack, predecessor, required regions, site IDs, and rule
hashes. Canary, regional, and general artifacts for the same release therefore
share a release ID while carrying new metadata and promotion sequences.

The verifier recompiles every rule source, rebuilds the canonical pack, and
requires every embedded promotion to name a rule actually present in those
exact bytes. Each promotion must have the same pack, predecessor, and complete
required-region set, and its expiry must cover the metadata expiry.

## Trust and key rotation

Metadata signatures use strict Ed25519 verification over deterministic JSON
prefixed by the metadata domain separator. Unknown fields, algorithms,
malformed IDs, malformed signatures, unknown trust shapes, future issue times,
and expired artifacts fail closed.

An unchanged release trust must equal the current trust root. A rotation may
advance exactly one generation, must change the key map, and cannot shorten
the public-trust expiry. The rotation artifact must independently satisfy:

1. the threshold of the currently installed trust root; and
2. the threshold of the complete candidate trust root.

This dual-threshold rule requires an explicit overlap ceremony. A new-only
signature cannot introduce its own authority, and an old-only signature cannot
claim that the new threshold accepted the transition.

Candidate trust is recorded as `staged` during `canary` and `regional`
metadata. The registry continues to treat the prior root as current so the
active general pack remains verifiable across worker restarts. Only successful
`general` activation or signed `rollback` makes the candidate root `active`;
the prior active root becomes `retired`. Removal of an old key therefore uses
a later generation signed under both the current overlapping threshold and
the candidate new-only threshold.

Private seeds are exactly 32 bytes encoded as 64 hexadecimal characters in
operator-owned files. They are never serialized into trust or metadata
artifacts, accepted as literal command arguments, stored in PostgreSQL, or
included in the repository.

## Rollout and rollback state machine

| Stage | Eligible regions | Eligible workers | Customer jobs | State effect |
| --- | --- | --- | --- | --- |
| `canary` | Nonempty subset of required regions | Nonempty explicit set | No | Creates or monotonically widens a staged release |
| `regional` | Nonempty proper subset of required regions | Empty | No | Monotonically widens the same staged release |
| `general` | Exactly all required regions | Empty | Yes | Activates the staged release and retains the prior active release as last-known-good |
| `rollback` | Exactly all required regions | Empty | Yes | Restores the retained active release while naming the failed pack as predecessor |

The first release starts at `canary` with no predecessor. A different release
must start at `canary` and name the exact active pack as predecessor. Later
canary eligibility can only expand; regional eligibility can only expand;
stage progression cannot move backward. A general metadata refresh for the
same active release is permitted so operators can renew short-lived evidence
without changing pack bytes.

Metadata sequence is global and strictly increasing. Each site's embedded
promotion sequence is independently strictly increasing. A successful
rollback advances both high-water marks; it never lowers them or makes an old
artifact replayable. Rollback accepts only the exact retained release and
exact failed staged or active predecessor. It cannot select arbitrary older
bytes.

Expired staged metadata is not selected. General and rollback metadata are
also rechecked immediately before managed execution, so an operator must
publish a newly signed, higher-sequence general refresh before the current
artifact expires. Expiry is loss of execution authority, not evidence that an
account changed state.

## Durable PostgreSQL registry

Migration `0009_rule_pack_distribution.sql` adds five global tables:

- `rule_pack_trust_roots` retains staged, active, and retired public roots;
- `rule_pack_metadata` retains the bounded signed envelopes and rollout state;
- `rule_pack_promotions` materializes each exact site/promotion binding;
- `rule_pack_registry` stores the serializable state machine, global sequence
  high-water, current trust generation, active release, staged release, and
  last-known-good release; and
- `rule_site_promotion_high_water` stores the durable per-site anti-replay
  floor.

`socialname-server apply-rule-pack` takes an exclusive registry lock and
performs verification, exact pack compilation, state transition, trust
materialization, rule-version installation, high-water updates, and registry
persistence in one transaction. It cross-checks the serialized registry
against its materialized columns and the complete site high-water table before
accepting another artifact. Missing, divergent, or decreasing state is a
storage invariant failure, not a reason to reset the floor.

Only an active, unexpired `general` or `rollback` metadata row can enable rule
versions and promote sites. Staged releases do not disable the active pack.
Replacement disables prior rule versions, and rollback re-enables the exact
retained version.

The worker coordinator resolves a rule only when site, rule hash, pack hash,
region, metadata ID and sequence, and embedded promotion ID and sequence all
match the current database registry. A second narrow availability function
rechecks the active version, current metadata, regional health, and expiry
during a lease. Both functions have fixed `pg_catalog` search paths and
`PUBLIC` execution revoked.

## Operator workflow

Create and review the public trust JSON outside the repository, then print its
domain-separated pin:

```console
cargo run --locked -p socialname-cli -- rules trust-id \
  --trust-file <current-trust.json>
```

After producing one current signed site promotion per included site, sign the
pack metadata. The same trust file is used for current and candidate trust
when no rotation occurs:

```console
cargo run --locked -p socialname-cli -- rules sign-metadata \
  --rules-dir <exact-pack-directory> \
  --promotion <site-a-promotion.json> \
  --promotion <site-b-promotion.json> \
  --sequence <next-global-sequence> \
  --previous-rule-pack-hash <active-pack-sha256> \
  --required-region <region-a> \
  --required-region <region-b> \
  --rollout-stage canary \
  --eligible-region <region-a> \
  --eligible-worker <worker-a> \
  --expires-at <rfc3339> \
  --current-trust-file <current-trust.json> \
  --trust-file <candidate-trust.json> \
  --signing-key <old-key-id=old-private-seed-file> \
  --signing-key <new-key-id=new-private-seed-file> \
  > rule-pack-metadata.json
```

First release omits `--previous-rule-pack-hash`. `regional` has no
`--eligible-worker`; `general` and `rollback` use every required region and no
worker list. The signing command self-verifies the signatures, trust
transition, embedded promotions, and exact pack before writing JSON.

Verify independently, including the replay floor and optional worker
selection:

```console
cargo run --locked -p socialname-cli -- rules verify-metadata \
  --artifact rule-pack-metadata.json \
  --rules-dir <exact-pack-directory> \
  --current-trust-file <current-trust.json> \
  --minimum-sequence-exclusive <highest-seen-sequence> \
  --region <worker-region> \
  --worker-id <worker-id>
```

Apply to the durable registry with the schema-owner operator credential:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://OPERATOR:SECRET@HOST:5432/DB"
$env:SOCIALNAME_RULES_DIRECTORY = "<exact-pack-directory>"
$env:SOCIALNAME_RULE_METADATA_FILE = "<rule-pack-metadata.json>"

# Required together only while the registry is empty.
$env:SOCIALNAME_INITIAL_RULE_TRUST_FILE = "<current-trust.json>"
$env:SOCIALNAME_INITIAL_RULE_TRUST_ID = "<reviewed-trust-id>"

cargo run --locked -p socialname-server -- apply-rule-pack
```

The command emits one target-free
`socialname.dev/rule-pack-apply/v1` JSON object containing metadata ID,
sequence, rollout stage, pack hash, and installed trust generation. Errors are
fixed classes and do not echo database credentials, filesystem contents, or
private key material.

## Worker consumption

Direct canary probes and database jobs receive the exact metadata artifact and
the currently active public trust root. A canary carrying candidate generation
`N+1` is verified from active generation `N`; after general activation, the
dual-signed general artifact can also be verified from installed generation
`N+1`.

The managed job command is:

```console
cargo run --locked -p socialname-worker -- process-one \
  --site <site-id> \
  --region <worker-region> \
  --rules-dir <exact-pack-directory> \
  --metadata <rule-pack-metadata.json> \
  --current-trust-file <current-trust.json> \
  --minimum-metadata-sequence-exclusive <worker-high-water> \
  --worker-id <closed-lowercase-label> \
  --lease-seconds 60 \
  --maximum-attempts 3 \
  --expansion-limit 32 \
  --allow-live
```

`process-one` rejects canary and regional metadata for customer work. It
activates only an exact general or rollback site binding, then the database
must independently resolve the same metadata and promotion identities.
`--allow-live` is checked before files or PostgreSQL are touched.

The direct `probe` command uses the same metadata, trust, sequence, pack, site,
region, and worker checks but may use a selected canary or regional artifact.
Its output adds metadata ID, sequence, and rollout stage to the existing
promotion and minimized result fields.

## Verification and remaining external gate

Deterministic tests cover malformed and unknown fields, tampering, expiry,
pack mismatch, missing or stale promotions, global and per-site replay,
rollout narrowing and regression, worker selection, general activation,
last-known-good replacement, signed rollback, dual-threshold key overlap,
old-key removal, and new-only refresh.

The PostgreSQL 18 integration test applies canary and general metadata, rejects
a persisted replay, stages a second pack and trust generation without
disrupting the active root, activates both, removes the old key through a
second dual-threshold transition, rolls back to the retained version, rejects
the stale worker binding, and accepts the new rollback binding.

The repository contains synthetic test keys only. Production key custody,
threshold ceremony, registry artifact distribution, multi-region observation,
and an exercised production rollback remain external evidence gates.
