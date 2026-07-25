# Canary Manifest v1

## Purpose

A canary manifest declares the reviewed public controls used to measure whether
one site rule is producing trustworthy results. It is deliberately separate
from the site rule:

- a rule describes how to probe and classify a site;
- a canary manifest describes time-bounded evidence inputs used to evaluate
  that rule;
- operational reports and rule-health state are separate runtime records.

This separation prevents changing a classifier from silently changing its own
acceptance controls. It also lets the same manifest compare a candidate rule
with the last-known-good rule in shadow mode.

The schema identifier is `socialname.dev/canary-manifest/v1`. The
`socialname-canary` crate owns the typed source model, strict YAML validation,
semantic validation against a compiled Site Rule v1, canonical JSON, and a
SHA-256 content hash.

## Source shape

The following is structural documentation, not an accepted production
manifest:

```yaml
schema: socialname.dev/canary-manifest/v1
site_id: example
issued_at: 2026-07-25T00:00:00Z
expires_at: 2026-08-01T00:00:00Z
positive:
  - id: platform
    username: alpha
    kind: platform_official
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/alpha
  - id: project
    username: bravo
    kind: project_controlled
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/bravo
  - id: stable-one
    username: charlie
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/charlie
  - id: stable-two
    username: delta
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/delta
  - id: stable-three
    username: echo
    kind: long_lived_public
    reviewed_at: 2026-07-24T00:00:00Z
    evidence_url: https://example.test/u/echo
negative:
  generator:
    alphabet: lowercase_alnum
    random_length: 20
    count: 5
    attempts_per_candidate: 3
```

## Validation contract

Validation is deterministic for an explicit validation time. A manifest is
rejected when:

- its schema, site ID, or filename does not match;
- its issue time is in the future, its validity window is reversed, or it is
  expired;
- it contains fewer than five or more than 32 positive controls;
- positive IDs or normalized usernames are duplicated, or a positive ID uses
  the reserved `generated-negative-` prefix;
- a positive username violates the current compiled rule's username policy or
  is not in canonical form;
- a review is newer than the manifest or the validation time;
- review evidence is not an HTTPS URL without embedded credentials;
- the negative generator requests fewer than five or more than 32 controls,
  uses an invalid retry budget, provides less than 64 bits of random input, or
  cannot produce a canonical username accepted by the rule.

The authoring surface also rejects unknown fields, oversized sources and lines,
tabs, excessive nesting, YAML anchors, aliases, tags, and merge keys.

Negative values are generated at execution time. The eventual report records
the manifest hash and bounded per-canary outcomes; it must not store complete
HTTP bodies. A generated negative that unexpectedly exists is a conflict and
must never be relabeled or discarded to improve precision.

## Trust boundary

A valid manifest does not make a rule healthy and does not enable it. Promotion
still requires the multi-region, repeated-run acceptance report defined in
[`site-rule-v1-validation.md`](site-rule-v1-validation.md), followed by signed
publication and a last-known-good rollback path.

No production manifest is committed yet because the required five reviewed
positive controls per representative site are external evidence. The empty
`rules/canaries/` directory is therefore an explicit safe state: all current
rules remain discovery-only.

Validate the current repository state or print the generated schema with:

```console
cargo run --locked -p socialname-cli -- canaries validate
cargo run --locked -p socialname-cli -- canaries schema
```

## Bounded runner

The implemented runner consumes a manifest compiled against the selected rule
hash and calls the same `SearchEngine` used by the local product. Before any
network work it:

- rejects a rule hash other than the one used for manifest validation;
- generates unique negative candidates with the operating-system-seeded
  cryptographic RNG and the manifest's bounded retry policy;
- computes the maximum requests and inspected response bytes implied by the
  rule's probe plan;
- rejects runs whose worst case exceeds the caller's request or byte budget;
- validates hard caps for concurrency, wall time, and coarse region labels.

During execution it limits concurrency, honors cancellation, applies a wall
clock deadline, and drops pending probe futures when a limit is reached. A
cancelled or timed-out run returns its completed partial outcomes with an
explicit terminal state; it is not represented as a complete failed canary
sample.

Runner outcomes omit usernames, profile URLs, response bodies, final URLs, and
matcher detail. They retain only the control ID, expectation, verdict,
inconclusive reason, evidence class and digest, plus bounded probe status,
transport, content type, inspected bytes, truncation, and latency. Request and
byte counters are explicitly labeled as completed values because an interrupted
in-flight request cannot yet be counted exactly.

Live execution requires both an accepted manifest and an explicit acknowledgement:

```console
cargo run --locked -p socialname-cli -- canaries run --site <site-id> --region <coarse-region> --allow-live --json
```

The repository currently has no accepted production manifests, so this command
cannot run against the representative sites. That is the intended external-gate
state.

## Next integration

The next slice will turn the bounded run into a versioned report bound to the
manifest, rule, engine, and declared vantage; derive precision, conclusive
coverage, latency, bytes, response classes, and conflicts; and reject malformed
or replay-incompatible reports. Aggregation, shadow comparison, and promotion
remain later Milestone 1A deliverables.
