# Canary Report v1

## Purpose

`socialname.dev/canary-report/v1` is the bounded, machine-readable output of one
complete canary run. It records enough information to reproduce acceptance
metrics and detect tampering without carrying search targets, URLs, matcher
detail, or response bodies.

The envelope has two fields:

```json
{
  "report_id": "<sha256 of canonical report JSON>",
  "report": {
    "schema": "socialname.dev/canary-report/v1",
    "site_id": "example",
    "manifest_hash": "<sha256>",
    "rule_hash": "<sha256>",
    "engine_hash": "<sha256 of the executing binary>",
    "vantage": { "region": "managed-region-1" },
    "started_at": "2026-07-25T00:00:00Z",
    "finished_at": "2026-07-25T00:01:00Z",
    "expires_at": "2026-07-26T00:01:00Z",
    "completion": "complete",
    "summary": {},
    "cases": []
  }
}
```

The actual `summary` and `cases` fields are strict typed objects; the abbreviated
example is not itself valid.

## Provenance and validity

The report binds:

- the canonical canary manifest hash;
- the exact compiled site-rule hash used by the runner;
- the SHA-256 of the current CLI or worker executable containing the production
  engine;
- the declared coarse managed-region label;
- the start and finish timestamps.

The report expires no later than 48 hours after completion and never later than
its canary manifest. Aggregation separately admits only an explicit 24-hour
measurement window. The extra ingestion margin lets the first and last samples
span a full day without making a past measurement timeless.

Only a complete run can become a report. Cancellation and deadline outcomes
remain explicit partial runner diagnostics and cannot be mislabeled as an
acceptance sample.

## Recomputed metrics

The report builder and validator deterministically derive:

- total positive and generated-negative cases;
- conclusive `found` and `not_found` cases;
- conclusive cases that matched their declared expectation;
- conflicting-evidence cases;
- precision as `matched_conclusive / conclusive`;
- conclusive coverage as `conclusive / total`;
- planned and completed requests;
- completed inspected response bytes;
- probe-latency sample count plus nearest-rank min, p50, p95, and max;
- HTTP 2xx/3xx/4xx/5xx classes and explicit transport outcome classes.

Ratios remain numerator/denominator pairs. In particular, no conclusive sample
is represented as `0/0`, not as an invented zero or 100 percent.

## Privacy boundary

Case records contain a positive control ID or generated-negative ordinal,
expectation, verdict, inconclusive reason, evidence class and digest, and
bounded probe metadata.

They exclude:

- usernames and generated negative values;
- profile, requested, and final URLs;
- response bodies and body excerpts;
- raw response headers and content-type parameters; only a small allowlisted
  media-type class remains;
- matcher trace detail.

Complete request counters and byte counters cover completed outcomes. A partial
run does not claim exact counts for an interrupted in-flight request and is not
eligible for report construction.

## Validation

Validation is performed against an explicit ingestion policy. The policy
specifies the expected site and manifest, allowed rule and engine hashes,
allowed managed regions, and maximum request and completed-byte budgets.

A report is rejected when:

- JSON is oversized, malformed, contains unknown fields, or uses another
  schema;
- `report_id` is not the canonical content hash or is already present in the
  caller's durable duplicate registry;
- the report is expired, has an invalid window, exceeds the maximum run
  duration, or is implausibly future-dated;
- site, manifest, rule, engine, region, completion state, or budgets are
  incompatible with policy;
- positive/generated-negative counts, case IDs, verdict/reason pairs, evidence
  digests, probe bounds, or content types are malformed;
- any summary, ratio, latency percentile, byte total, response class, or
  conflict count differs from recomputation over the cases.

The in-memory validator accepts a caller-provided set of previously persisted
report IDs. A future server ingestion transaction must enforce the same ID with
a database uniqueness constraint before acknowledging acceptance.

## Trust boundary

The content hash detects accidental or deliberate modification after a report
is sealed. It does not authenticate the producer. Signed promotion artifacts,
approved engine artifacts, worker identity, and replay-resistant ingestion are
separate later gates. A structurally valid report also does not enable a rule
by itself; aggregation and the full multi-run, multi-region acceptance policy
remain required.

`socialname canaries run --json` emits this envelope only after the runner
completes and the newly built report passes the validator. No representative
site can currently reach that path because no external-evidence-backed
production manifest has been committed.
