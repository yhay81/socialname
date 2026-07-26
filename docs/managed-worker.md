# Signed managed worker boundary

`socialname-worker` is the first managed-execution boundary. It proves that a
reviewed, signed rule can be executed with stricter network controls than the
local engine. The database-job slice now uses this same boundary to expand and
claim accepted searches, execute at most one fenced job, and atomically ingest
observations and events. See
[Managed probe jobs and observation ingestion](managed-jobs.md).

## Signed-rule activation

The worker library exposes `ManagedRule::activate`, not a raw-rule execution
method. Activation requires an opaque `ValidatedRulePackMetadata` produced by
the strict threshold verifier plus the exact local `CompiledRulePack`, site,
region, and worker ID. Activation then:

1. checks the closed region and worker labels;
2. requires that worker to be selected by the metadata rollout stage;
3. selects the site's embedded validated promotion;
4. rejects future or expired pack metadata, promotion, and regional evidence;
5. recompiles every source in the pack;
6. recomputes the canonical pack hash; and
7. requires the metadata, promotion, candidate rule, and pack identities to
   match exactly.

The `ManagedRule` fields are private. Its execution method rechecks pack
metadata, promotion, and regional-evidence expiry immediately before probing,
and a pre-cancelled token wins before any network future is polled. A rule
source, site choice, API scope, or standalone site promotion therefore cannot
create managed network authority.

The metadata trust policy pins the current public trust root, exact candidate
generation, threshold signatures, global sequence floor, pack, predecessor,
rollout eligibility, and every embedded site promotion. The complete
distribution and rotation contract is in
[Signed Rule-Pack Distribution v1](rule-pack-distribution-v1.md). The
repository contains no production trust root, private signing key, metadata
artifact, promotion artifact, or accepted live-rule evidence.

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
  --metadata <rule-pack-metadata.json> \
  --current-trust-file <current-trust.json> \
  --minimum-metadata-sequence-exclusive <highest-seen-sequence> \
  --worker-id <closed-lowercase-label> \
  --allow-live
```

Canary and regional metadata work only for explicitly eligible workers;
general and rollback metadata select every required region. The username is
not a command argument or environment variable. The command reads at most
1 KiB of closed JSON from standard input:

```json
{"username":"explicit-public-target"}
```

The input permits only `username`, bounds it to 256 UTF-8 bytes, and rejects
control characters before rule-specific normalization. `--allow-live` is
checked before files or stdin are read. Ctrl-C cancels and drops the in-flight
request future. Errors are fixed classes that do not echo the target or key
material.

Successful standard output is one explicit
`socialname.dev/managed-probe-result/v1` JSON object containing metadata ID,
metadata sequence, rollout stage, promotion ID, region, and the minimized
`SearchResult`. This operator output intentionally contains the normalized
public target; it must not be redirected into ordinary service logs or
metrics.

## Deterministic evidence and database connection

Engine tests cover public-unicast acceptance, IPv4/IPv6 special ranges,
metadata addresses, empty/mixed/oversized DNS answers, second-resolution
rebinding, raw unselected header limits, declared body limits, all supported
decoders, decompression bombs, and inspected-body separation.

Worker tests build and verify synthetic threshold-signed pack metadata with an
embedded Ed25519 promotion, activate only a stage-selected worker, recompile
pack bytes, reject tampering and expiry, prove pre-network cancellation, keep
error formatting target-free, and validate the closed stdin/public-trust
contracts. No test bypasses the managed resolver to claim a live site result.

The `process-one` command adds the database connection without adding a
raw-rule path. It accepts only `general` or `rollback`, binds the same
`ManagedRule` to the exact metadata ID/sequence and promotion ID/sequence in
the active registry row, expands a bounded batch, claims at most one fenced
lease, monitors authorization during the request, and records a target-free
operator status.
The job identity, forced-RLS role, coalescing, retries, consent lock, atomic
ingestion, and remaining rule-acceptance gate are specified in
[Managed probe jobs and observation ingestion](managed-jobs.md).

The provider-neutral container and regional operator contract is specified in
[Regional managed-worker deployment boundary](regional-worker-deployment.md).
The image is non-root and inert by default. Once a request is in flight, both
Ctrl-C and `SIGTERM` cancel it; a forced stop leaves the fenced lease to expire
without committing a target result.
