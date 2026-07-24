# Research findings

This document records the evidence used to choose the SocialName v2 direction.
It separates observed facts from design conclusions so the decisions can be
revisited later.

## Legacy SocialName

### Repository state

The current repository is version 0.1.3. Its last commit is dated 2021-01-23.
The package targets Python 3.6 through 3.9 and contains:

- 393 site entries.
- 234 `status_code` rules.
- 116 `message` rules.
- 43 `response_url` rules.
- A single placeholder test rather than behavioral coverage.

One `linktree` record still uses the older `url`, `username_claimed`, and
`username_unclaimed` field names, while the v0.1.3 loader requires
`urlUser`, `usernameClaimed`, and `usernameUnclaimed`. This is evidence that
schema validation existed but was not continuously enforced against the
shipped artifact.

### Improvements over the 2021 Sherlock base

The Git history shows that SocialName was not only a rename. Its important
design changes were:

1. Introduce explicit site and result domain objects.
2. Separate notification/output behavior from the search operation.
3. Split CLI parsing, command orchestration, output, loading, and search logic.
4. Validate site data before execution.
5. Replace one large conditional search implementation with detector-specific
   modules.
6. Move detector-specific fields into detector-specific `options`.

Relevant commits:

- [`7395c31`: dataclasses for site and result objects](https://github.com/yhay81/socialname/commit/7395c319e34e2d058fbbec100fd7c31e5db7377b)
- [`3f15cb2`: site data validation](https://github.com/yhay81/socialname/commit/3f15cb25539e13326e1fc881c76f4bb6fd6a8320)
- [`7362685`: CLI and output separation](https://github.com/yhay81/socialname/commit/7362685f5ea7f25c668c4a985bfd1211f2c807d1)
- [`4bdc834`: detector-specific logic modules](https://github.com/yhay81/socialname/commit/4bdc834f68532d3030b9ee7792abc5dc2e0268bc)

The central idea remains sound: common site fields and detector-specific fields
should have different types and validation.

### Limitations to avoid carrying forward

- The rule selects a Python module using a string and dynamic import.
- Detector options are ultimately an untyped dictionary.
- A detector class mixes request construction, transport, classification, and
  reporting.
- `response_url` requires an `errorUrl` option but does not use it in the
  decision.
- A separate HTTP session is constructed for every site.
- HTTP concurrency is limited by CPU count even though the workload is I/O
  bound.
- Multiple usernames are processed sequentially.
- A missing timeout can leave a request waiting indefinitely.
- Sub-second elapsed times are truncated.
- Remote rule loading is not authenticated or protected against rollback.
- There is no maintained live test corpus for all shipped rules.

The v2 implementation should preserve the separation of concerns, while
replacing runtime polymorphism and untyped options with a closed, typed rule
algebra.

## Current Sherlock

The upstream project currently identifies itself as v0.16.x and advertises
support for 400+ sites. An inspection of the upstream manifest on 2026-07-24
found 481 actual targets, excluding the `$schema` property:

| Detection type | Targets |
| --- | ---: |
| `status_code` | 327 |
| `message` | 127 |
| `response_url` | 27 |

Less-common fields in the same manifest were:

| Capability | Targets |
| --- | ---: |
| Separate probe URL | 52 |
| Username regex | 95 |
| Custom headers | 7 |
| Explicit request method | 27 |
| POST request | 3 |
| JSON request payload | 3 |
| Custom error code | 6 |
| NSFW flag | 19 |

This distribution supports a small declarative HTTP engine. Almost every
current target is a single request; only a small minority needs custom methods,
payloads, or headers.

### Useful upstream practices

- A JSON Schema Draft 2020-12 manifest.
- Unknown fields are rejected.
- Detector-specific required fields are expressed in the schema.
- Known-positive and generated likely-negative online checks exist.
- WAF is represented separately from found/not-found.
- False-positive exclusions can be distributed independently.

Sources:

- [Sherlock repository and CLI](https://github.com/sherlock-project/sherlock)
- [Current target manifest](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/resources/data.json)
- [Manifest schema](https://github.com/sherlock-project/sherlock/blob/master/sherlock_project/resources/data.schema.json)
- [Live target validation](https://github.com/sherlock-project/sherlock/blob/master/tests/test_validate_targets.py)

### Remaining upstream limitations

- The manifest is a single, high-conflict JSON file.
- Fields overload scalar and array forms.
- Detection types and their options are still stored in one flat object.
- Multi-detector behavior is evaluated procedurally and can overwrite a
  previous result.
- Operational failures and account verdicts still share one status enum.
- A result is treated as the answer rather than as one time- and
  vantage-specific observation.
- Manifest freshness is not cryptographically bound to a release or protected
  from rollback.

SocialName v2 should be able to import the upstream manifest, but should not
adopt its internal data model.

## Adjacent products

Breadth and a one-shot username API are already competitive markets:

- [Maigret](https://github.com/soxoj/maigret) advertises 3,000+ sites,
  recursive discovery, profile extraction, reports, a web UI, and a
  commercially maintained site database/API.
- [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) maintains a dataset
  of 700+ sites, and a related service exposes an asynchronous username search
  API.
- [Sherlock](https://github.com/sherlock-project/sherlock) has a large
  established user base and mature packaging.

Consequently, these features alone are not a durable advantage:

- More site entries without measured reliability.
- A hosted wrapper around the CLI.
- A boolean found/not-found API.
- A report produced from a single scan.

The stronger opportunity is **continuously maintained truth over time**:

- Rule health and automatic quarantine.
- Freshness and provenance on every result.
- Change history and transition alerts.
- Regional comparison.
- A stable API contract backed by the same local and managed engine.
- Lower target-site load through trustworthy cache reuse and request
  coalescing.

## Distributed measurement lessons

The proposed CLI/cloud relationship resembles Internet measurement systems
more than a normal application cache.

### RIPE Atlas

RIPE Atlas distinguishes a measurement definition from each probe's individual
measurement result. It also makes public/private visibility an explicit
property and limits the precision of location and address data.

Applicable lessons:

- Store every contributing result as its own observation.
- Preserve the vantage that produced it.
- Make visibility an explicit policy, not an implementation accident.
- Obscure or omit precise client location and network identity.
- Derive current state from observations instead of overwriting history.

Sources:

- [RIPE Atlas measurement model](https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/)
- [RIPE Atlas public/private objects and obfuscation](https://beta-ui.atlas.ripe.net/docs/apis/rest-api-manual/authentication/anonymous-access/)

### OONI Probe

OONI documents the risks of client-side network measurements, gives users
control over submission, and attaches time, country, network, and platform
context to results. Its web-connectivity test also compares the user's network
with a control server rather than assuming either vantage is universally
correct.

Applicable lessons:

- Upload must be visible and configurable.
- A local result and a managed-server result may both be correct for their
  respective networks.
- Region can be essential evidence, but must be collected at the coarsest useful
  granularity.
- HTTP responses may accidentally contain personal or identifying data.
- Raw response storage and publication should not be the default.

Sources:

- [OONI data policy](https://ooni.org/about/data-policy/)
- [OONI local/control comparison](https://ooni.org/nettest/web-connectivity/)

## Technology evidence

The current Rust ecosystem supports one implementation shared by the CLI and
server:

- [Tokio](https://tokio.rs/) provides the asynchronous runtime and bounded
  network primitives.
- [reqwest](https://docs.rs/reqwest/latest/reqwest/) provides an asynchronous
  HTTP client with reusable connection pools, redirect policies, proxies, and
  TLS.
- [axum](https://docs.rs/axum/latest/axum/) integrates with Tokio and Tower for
  HTTP APIs, middleware, timeouts, tracing, authorization, and SSE.
- [SQLx](https://docs.rs/sqlx/latest/sqlx/) supports both PostgreSQL and SQLite,
  allowing similar typed persistence code for the server and local cache.
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) is suitable
  for generated rule schemas and editor tooling.
- [The Update Framework](https://theupdateframework.io/) provides a mature
  model for signed metadata, expiry, key rotation, and rollback protection.

Specific dependency versions are intentionally not pinned in the design
documents. They will be selected and locked when the Rust workspace is created.

## Research conclusion

The project should not optimize for producing a faster copy of Sherlock's
single-run output. It should optimize for:

1. A trustworthy and fast local engine.
2. Typed, testable, continuously verified site rules.
3. Observations carrying time, vantage, provenance, and evidence.
4. Current assertions derived from several possible sources.
5. Monitoring and state transitions as the first paid product.
6. Explicit privacy and trust boundaries for client-contributed data.
