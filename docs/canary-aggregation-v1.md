# Canary Aggregation v1

## Purpose

`socialname.dev/canary-aggregate/v1` combines independently validated Canary
Report v1 envelopes into one region-explicit acceptance decision. It implements
the repeated-run and 24-hour parts of the live gate; it does not promote or
enable a rule.

The aggregator accepts only the opaque `ValidatedCanaryReport` type returned by
the report validator. Raw or merely deserialized JSON cannot be passed directly
into acceptance calculation.

## Policy

An aggregation policy fixes:

- one site, canary manifest, candidate rule, and executable engine hash;
- at least three required managed-region labels;
- an exact 24-hour measurement window;
- at least three reports per required region;
- the rule's reviewed maximum p95 probe latency.

All input reports must match those hashes and regions, finish inside the
declared window, remain within their 48-hour ingestion validity, and have unique
content IDs. Incompatible, out-of-window, expired, or duplicate inputs are
rejected instead of silently filtered.

The operator CLI reads a directory of strict report JSON files, validates each
one, rejects duplicates within the batch, and emits the aggregate:

```console
cargo run --locked -p socialname-cli -- canaries aggregate --reports-dir <path> --site <site-id> --manifest-hash <sha256> --rule-hash <sha256> --engine-hash <sha256> --region <region-a> --region <region-b> --region <region-c> --window-start <rfc3339> --window-end <rfc3339> --json
```

Server ingestion will additionally back the duplicate registry with durable
transactional storage.

## Regional acceptance

Reports are sorted deterministically by completion time and report ID. Each
required region is evaluated independently:

- at least three runs;
- first-to-last completion span of at least 24 hours;
- 100 percent conclusive precision;
- at least 95 percent conclusive coverage;
- zero conflicting-evidence cases;
- aggregate probe p95 no greater than the reviewed site limit.

The exact-ratio and nearest-rank metric definitions are inherited from Canary
Report v1. Combining reports cannot hide a region: missing regions, too few
runs, short intervals, low precision, low coverage, conflicts, and excessive
latency remain typed region-specific issues.

The overall summary combines all provided cases for operator visibility, but
global volume cannot compensate for a failed required region.

## Output and trust boundary

The aggregate records its input report IDs, per-region summaries, overall
summary, policy hashes, window, aggregation time, typed issues, and an
`accepted` or `rejected` disposition.

Acceptance means only that this candidate/engine combination met the synthetic
report policy. It is not a signature, publication, health-state transition, or
account-state observation. The separate shadow-comparison, health-state,
signed-promotion, and rollback gates remain mandatory.

Deterministic tests cover:

- three regions with three precise runs spanning the full 24 hours;
- missing regions, insufficient runs, and short intervals;
- low precision, low coverage, conflicts, and excessive latency in one region;
- duplicate report input.

There are still no production canary manifests or external managed-region
reports in the repository. No real site has been promoted by this software
slice.
