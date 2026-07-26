# Signed managed worker boundary

`socialname-worker` is the first managed-execution boundary. It proves that a
reviewed, signed rule can be executed with stricter network controls than the
local engine. The database-job slice now uses this same boundary to expand and
claim accepted searches, execute at most one fenced job, and atomically ingest
observations and events. See
[Managed probe jobs and observation ingestion](managed-jobs.md).

## Signed-rule activation

The worker library exposes `ManagedRule::activate`, not a raw-rule execution
method. Activation requires an opaque `ValidatedPromotion` produced by the
strict Ed25519 promotion verifier plus the exact local `CompiledRulePack`.
Activation then:

1. checks the worker's closed region label;
2. requires that exact region in the signed acceptance map;
3. rejects future or expired promotion metadata and expired regional evidence;
4. recompiles every source in the pack;
5. recomputes the canonical pack hash;
6. selects the candidate named by the signed site ID; and
7. requires the recomputed rule and pack hashes to equal the promotion.

The `ManagedRule` fields are private. Its execution method rechecks promotion
and regional-evidence expiry immediately before probing, and a pre-cancelled
token wins before any network future is polled. A rule source, site choice, or
API scope by itself therefore cannot create managed network authority.

Promotion trust policy still pins the expected key ID/public key, site, rule,
pack, predecessor, manifest, engine, region set, and minimum sequence. The
repository contains no production verifying policy, private signing key,
promotion artifact, or accepted live-rule evidence.

## Managed transport

`SearchEngine::new_managed` builds a separate Reqwest client. The ordinary
local engine remains unchanged. The managed client:

- requires HTTPS and the compiled rule's exact host allowlist for every initial
  and redirected URL;
- disables system and environment proxies;
- disables automatic response decoding so raw and decoded sizes are measured
  independently;
- installs a custom resolver that validates every address before Reqwest is
  allowed to connect;
- repeats resolution and validation for every new connection and redirect
  host; an already-open pooled socket remains pinned to the address that
  passed validation;
- rejects an empty answer, more than 16 answers, or the entire answer set when
  any address is not permitted.

Reqwest's resolver contract returns concrete `SocketAddr` values to its
connector, which lets the worker validate before connection
([Reqwest `Resolve`](https://docs.rs/reqwest/0.13.4/reqwest/dns/trait.Resolve.html)).
The address policy conservatively permits ordinary public IPv4 unicast and
IPv6 global-unicast space while denying private, shared, loopback, link-local,
benchmark, documentation, multicast, transition, reserved, and
metadata-capable ranges. The denial table follows the
[IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml),
[IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml),
and the current
[IPv6 global-unicast allocation](https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml).
Special allocation blocks are denied conservatively even where a narrower
anycast exception might be globally reachable.

This prevents a hostname from passing an early public-IP check and later
rebinding to loopback, RFC 1918/4193 space, link-local cloud metadata, or
another reserved destination. A mixed public/private answer is not filtered
down to the public subset; it fails closed.

## Response budgets

Every response, including a followed redirect response, checks the rule's
complete parsed header-name/value byte limit before classification. The final
response then enforces:

- declared `Content-Length` against the compressed limit;
- streamed wire bytes against the compressed limit;
- `gzip`, Brotli, zlib/deflate, Zstandard, or identity decoding under the
  decompressed limit;
- retained matcher text under the inspected-byte limit.

Unknown or multiple content encodings fail as decode errors. Any size breach
is `response_too_large`, an operational transport outcome, and cannot become
`not_found`. Only matcher-selected non-sensitive headers and a bounded
decompressed prefix reach the classifier; cookies, authorization data, full
headers, and complete response bodies are not returned by the worker result.

## Direct one-shot operator entry point

The direct diagnostic command remains:

```console
cargo run --locked -p socialname-worker -- probe \
  --site <site-id> \
  --region <worker-region> \
  --rules-dir <exact-pack-directory> \
  --promotion <promotion.json> \
  --manifest-hash <sha256> \
  --engine-hash <sha256> \
  --required-region <policy-region> \
  --previous-rule-pack-hash <active-pack-sha256> \
  --minimum-sequence-exclusive <highest-seen-sequence> \
  --key-id <trusted-key-id> \
  --verifying-key-file <public-key-hex-file> \
  --allow-live
```

First activation omits `--previous-rule-pack-hash`. The username is not a
command argument or environment variable. The command reads at most 1 KiB of
closed JSON from standard input:

```json
{"username":"explicit-public-target"}
```

The input permits only `username`, bounds it to 256 UTF-8 bytes, and rejects
control characters before rule-specific normalization. `--allow-live` is
checked before files or stdin are read. Ctrl-C cancels and drops the in-flight
request future. Errors are fixed classes that do not echo the target or key
material.

Successful standard output is one explicit
`socialname.dev/managed-probe-result/v1` JSON object containing promotion ID,
region, and the minimized `SearchResult`. This operator output intentionally
contains the normalized public target; it must not be redirected into ordinary
service logs or metrics.

## Deterministic evidence and database connection

Engine tests cover public-unicast acceptance, IPv4/IPv6 special ranges,
metadata addresses, empty/mixed/oversized DNS answers, second-resolution
rebinding, raw unselected header limits, declared body limits, all supported
decoders, decompression bombs, and inspected-body separation.

Worker tests build and verify a synthetic Ed25519 promotion, activate only its
accepted region, recompile pack bytes, reject tampering and expiry, prove
pre-network cancellation, keep error formatting target-free, and validate the
closed stdin/public-key contracts. No test bypasses the managed resolver to
claim a live site result.

The `process-one` command adds the database connection without adding a
raw-rule path. It binds the same `ManagedRule` to the exact promoted registry
row, expands a bounded batch, claims at most one fenced lease, monitors
authorization during the request, and records a target-free operator status.
The job identity, forced-RLS role, coalescing, retries, consent lock, atomic
ingestion, and remaining rule-acceptance gate are specified in
[Managed probe jobs and observation ingestion](managed-jobs.md).
