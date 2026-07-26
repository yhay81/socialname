# Bounded Evidence Capsule v1 and retention enforcement

## Scope

This slice makes managed observations inspectable without turning normal
evidence into a response archive. One successful managed observation and its
`socialname.dev/evidence-capsule/v1` resource commit in the same tenant
transaction. The worker cannot commit the observation if typed Capsule
construction, validation, serialization, or persistence fails.

The public read is:

```http
GET /v1/observations/{observation_id}/evidence-capsule
```

It requires `evidence:read`, rechecks the active API key and membership under
transaction-local forced RLS, and makes foreign-tenant, expired, purged, and
unknown observations uniformly `not_found`.

## Closed content

The Capsule has a 64 KiB serialized ceiling, at most 32 probe summaries, and at
most 128 matcher-trace entries. It contains only:

- the normalized target and typed definitive or uncertain outcome;
- exact rule, pack, engine, signed-metadata, and promotion identities;
- coarse managed region and network class;
- evidence class/digest and optional public HTTPS profile URL;
- probe ID, closed transport outcome, status, bounded public HTTPS final URL,
  sanitized content type, byte count, truncation flag, and bucketed latency;
- bounded matcher path, boolean outcome, and sanitized rule-generated detail.

The type has no slot for a request or response body, arbitrary header map,
cookie, credential, client IP, exact location, process data, or unrelated
profile field. Research content is a separately typed, redacted extension of
at most 2 KiB; the managed worker does not currently collect it. Complete
response artifacts remain an unimplemented exceptional facility and are not
silently represented by this Capsule.

Malformed hashes, non-HTTPS or credential-bearing URLs, control text, excessive
counts/bytes, inconsistent timestamps, unknown JSON fields, and an invalid
research/profile relation fail closed. The database independently checks the
closed root shape, IDs, profile, millisecond timestamps, SHA-256 digest sizes,
payload size, and retention relation.

## Retention policy

Deadlines use the database observation time, not a worker clock:

| Live consumers | Structured Capsule deadline |
| --- | ---: |
| private interactive search only | 90 days |
| private watch only | the watch's accepted 30–730 day setting |
| coalesced private search/watches | longest live consumer deadline |
| shared observation | fixed 400 days |
| shared research non-content structure | fixed 400 days |

A shared-research excerpt, when a future authorized ingestion path supplies
one, has a hard 30-day maximum and cannot outlive the structured Capsule.
Coalescing chooses the longest authorized consumer period because one
observation cannot be physically removed while another live consumer still
requires it.

Product reads include `structured_retained_until > clock_timestamp()`.
Research content is independently projected only while its deadline is still
future. Therefore an overdue cleanup run cannot extend visibility.

## Physical enforcement

The bounded operator entry point is:

```console
socialname-worker enforce-retention --batch-limit 128 --allow-live
```

It performs no network probe or webhook. `--allow-live` acknowledges
irreversible database deletion. A narrow `SECURITY DEFINER` function accepts
only 1–1000 rows per class, orders by deadline and Capsule ID, uses
`FOR UPDATE SKIP LOCKED`, and:

1. clears due research excerpts;
2. clears due structured JSON payloads;
3. deletes retention receipts after their independent three-year term.

Immutable IDs, digests, byte counts, profiles, and deadlines remain as
non-payload metadata. A trigger permits only the one-way non-null-to-null purge
after the database deadline. Each purge inserts one idempotent receipt with
Capsule ID, closed action, deadline, completion, and three-year expiry; the
receipt schema contains no username, site, payload, or excerpt column. Command
output contains counts only.

## Deliberate boundary

Capsule expiry clears the rich structured payload. The existing immutable
observation summary and its assertion/transition support are not falsely
claimed deleted here. The next ordered roadmap slice uses lineage to hide,
withdraw, recompute, and physically delete contributor/target material with
the separate five-minute, one-hour, 24-hour, seven-day, and 35-day guarantees.

Production scheduling, alerting on overdue retention work, jurisdictional
review, and proof from a real managed deployment remain external operational
evidence.

## Verification

Unit and wire-contract tests cover exact JSON shape, unknown-field rejection,
hash/URL/text/count/byte bounds, retention relations, redacted research
content, consumer-specific deadlines, metric bucketing, and target-free
operator output.

The real PostgreSQL 18 integration test proves:

- one observation/Capsule transaction and exact observation lineage;
- 400-day watch-derived retention for coalesced managed work;
- no body, arbitrary-header, cookie, or authorization field;
- `evidence:read`, insufficient-scope, and cross-tenant behavior;
- deadline-based hiding before physical purge;
- immutable payload/deadline enforcement and least-privilege roles;
- one-row batching, research-before-structure deadlines, receipts, and
  idempotent empty replay.
