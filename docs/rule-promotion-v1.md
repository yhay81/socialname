# Signed Rule Promotion v1

## Purpose

`socialname.dev/rule-promotion/v1` is the authenticated boundary between
measured regional rule health and activation. It does not create health and
cannot turn a rejected report into acceptance. It signs a narrowly scoped
statement that one exact rule in one exact rule pack satisfied the required
regional policy before the evidence expired.

The artifact binds:

- a monotonically increasing promotion sequence;
- site, candidate rule, complete rule-pack, manifest, and executing-engine
  SHA-256 identities;
- the previous active pack identity, except for first activation;
- the exact required region map;
- each region's health sequence, observation time, evidence expiry, aggregate
  identity, and same-target shadow identity;
- issue and expiry times no more than 24 hours apart;
- an Ed25519 key ID, signature algorithm, and signature.

It contains no usernames, search targets, response bodies, credentials, or
cookies.

## Construction gate

`PromotionBuilder` accepts compiled rule and pack objects plus persisted
regional `RuleHealthRecord` values. Before signing, it:

1. recompiles every rule source and recomputes the canonical pack hash;
2. proves that the candidate source is exactly present in that pack;
3. validates every persisted health record under the default state policy;
4. requires `healthy` state and the distinct aggregate-plus-shadow evidence
   shape that only an acceptance event can produce;
5. requires exactly one record for every policy region, with no omitted,
   extra, duplicated, or reused regional shadow evidence;
6. requires all regions to bind the same candidate, manifest, and engine;
7. rejects future observations and evidence that expires before the requested
   artifact expiry.

Operational or classification failure changes a record away from `healthy`.
Such a record cannot be signed into a promotion. Rule-health transitions also
remain structurally ineligible for account-state notifications.

## Signature and trust policy

The implementation signs deterministic JSON payload bytes prefixed by the
`socialname.dev/rule-promotion/v1` domain separator. `promotion_id` is the
SHA-256 identity of those exact signing bytes. The verifier then:

- resolves the declared key ID through an explicit trusted-key map;
- uses strict Ed25519 verification;
- recomputes the content identity;
- rejects unknown JSON fields, algorithms, malformed identities, and
  signatures;
- pins the expected site, candidate, pack, previous pack, manifest, engine,
  region set, and sequence floor;
- rejects future, expired, over-24-hour, or evidence-outliving artifacts.

The trust map can contain overlapping old and new public keys during an
operator-controlled rotation. A key not present in the map is untrusted even
when its signature is mathematically valid. Private seeds are not serialized
by the library or accepted directly as command-line values.

The cryptographic API is provided by
[`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/), using
its strict verification path.

## Activation and rollback

`PromotionActivationRegistry` is scoped to one site. Activation takes only an
opaque `ValidatedPromotion`, recompiles the supplied rule pack again, and
checks that its bytes match the signed pack and candidate hashes. It rejects:

- a sequence at or below the highest previously activated sequence;
- an expired or not-yet-issued artifact;
- a transition whose `previous_rule_pack_hash` is not the active pack;
- a different site, candidate, or pack.

Successful replacement retains the complete previous compiled pack and
candidate as last-known-good. Explicit rollback restores that retained object
and discards the failed candidate. It does not lower the sequence high-water
mark, so the rollback path cannot make an older signed update replayable.
Expiry prevents accepting stale update metadata; it does not erase an already
validated retained pack needed for local recovery.

## Operator commands

Provision Ed25519 key material outside the repository. The signing file is
exactly one 32-byte private seed encoded as 64 hexadecimal characters. The
verification file is the corresponding 32-byte public key in the same
encoding.

After separate health commands have produced one current healthy record per
required region:

```console
cargo run --locked -p socialname-cli -- canaries promote --site <site-id> --rules-dir <candidate-pack-directory> --health-record <region-a.json> --health-record <region-b.json> --health-record <region-c.json> --required-region <region-a> --required-region <region-b> --required-region <region-c> --sequence <next-sequence> --previous-rule-pack-hash <active-pack-sha256> --expires-at <rfc3339> --key-id <release-key-id> --signing-key-file <private-seed-file> > promotion.json
```

First activation omits `--previous-rule-pack-hash`. Verify independently
against the exact pack and purpose-specific trust policy:

```console
cargo run --locked -p socialname-cli -- canaries verify-promotion --artifact promotion.json --site <site-id> --rules-dir <candidate-pack-directory> --manifest-hash <sha256> --engine-hash <sha256> --required-region <region-a> --required-region <region-b> --required-region <region-c> --previous-rule-pack-hash <active-pack-sha256> --minimum-sequence-exclusive <highest-seen-sequence> --key-id <release-key-id> --verifying-key-file <public-key-file>
```

The build command self-verifies before emitting JSON. The verify command
recompiles the local pack and prints the exact hash eligible for activation.
Actual production key custody, signing ceremony, deployment, and rollback
exercise remain external evidence gates.

## Deterministic evidence

Tests cover valid signing and activation, strict verification, wrong keys,
payload and report tampering, expiry, unknown fields, incomplete regions,
non-healthy evidence, stale evidence, wrong pack bytes, previous-pack
mismatch, replay rejection, regional classification drift, two-pass recovery,
last-known-good retention, and rollback.

The repository contains no private signing key, production promotion artifact,
or production canary evidence. All representative rules remain
discovery-only.
