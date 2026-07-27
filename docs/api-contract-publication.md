# API v1 contract publication

## Purpose and boundary

Milestone 4 publishes the already implemented Developer API as deterministic,
reviewable repository artifacts. The publication describes the wire surface;
it does not create a hosted service, production base URL, entitlement,
destination ownership, live-rule eligibility, or availability claim.

The authoritative package is
[`contracts/api/v1`](../contracts/api/v1/README.md). It contains:

- `openapi.json`: OpenAPI 3.1.2 for all 23 implemented authenticated
  REST/JSON and SSE operations;
- `schemas/*.schema.json`: every independent
  `socialname-protocol::api_v1_schemas()` Draft 2020-12 root;
- `sse.json`: exact event-frame and resumption behavior that is not fully
  represented by an OpenAPI media-type entry;
- `manifest.json`: deterministic SHA-256 binding for every generated
  machine-readable artifact except the manifest itself.

The manifest is a drift/integrity artifact, not a signature or deployment
attestation. No example contains a bearer key, username, destination,
installation ID, consent subject, or other product data.

## Source of truth

`socialname-protocol` remains the inward dependency and public DTO authority.
Its publication registry records, for each implemented operation:

- HTTP method and versioned path;
- stable operation ID;
- exact required API-key scope;
- request and success-resource schema roots;
- bounded path, query, and header parameters;
- successful status codes and `Location` behavior;
- whether the response is JSON or the search SSE stream.

OpenAPI is generated from that registry and links to JSON Schema generated
directly from the DTO types. Runtime `Validate` still owns relational checks
that JSON Schema cannot express completely. Axum authentication,
transaction-local tenant RLS, consent, destination policy, suppression, and
worker authorization remain runtime boundaries; a schema-valid request grants
nothing by itself.

The server independently maps operation IDs to the scopes it actually applies.
A router test compares every published scope with that mapping, makes the
published method and a non-sensitive concrete path request, and requires the
registered route to stop at authentication. A missing method/path, public
route, or scope mismatch fails the server suite.

## REST and JSON compatibility

Every top-level JSON resource keeps
`"schema": "socialname.dev/api/v1"`. Existing request/response fields, required
fields, enum values, tagged-union discriminators, validation meanings, route
semantics, and required scopes are stable v1 behavior.

Because request and response DTOs reject unknown fields, adding a field to an
existing document can be incompatible for current consumers. Such a change is
not treated as a harmless additive v1 edit. An incompatible change requires:

1. a new public schema/contract version;
2. separate routes or an explicit negotiated migration boundary;
3. coexistence and withdrawal policy;
4. regenerated artifacts and consumer fixtures.

Adding a new independent operation still requires registry, router, scope,
schema, documentation, and drift-test evidence. It does not authorize a
client to infer fields absent from existing resources.

Every non-SSE operation publishes `application/json` success resources and the
closed `ApiErrorResponse` default error. Creation/replay operations list their
actual HTTP 200/201 behavior and `Location` response. Paths use UUID syntax
where the server currently requires UUID-backed public IDs. Page limits,
cursors, the operational window, `Idempotency-Key`, and `Last-Event-ID` are
bounded explicitly.

Every operation also publishes the optional bounded `X-Request-ID` input. An
invalid input is ignored and replaced rather than reflected. Success, error,
and SSE responses publish the required validated/generated `X-Request-ID`,
`Cache-Control: no-store`, and `X-Content-Type-Options: nosniff` headers.
Operations with closed query structs explicitly mark unknown query parameters
forbidden.

## SSE compatibility

OpenAPI publishes
`GET /v1/searches/{search_id}/events` with `text/event-stream` and links to
`sse.json`. The separate SSE contract fixes:

- persisted `search_event` frames with UUID `id`, the literal event name,
  `retry: 1000`, and one complete `SearchEvent` JSON object;
- unpersisted terminal `stream_error` frames with one `ApiErrorResponse`, no
  `id`, and no retry field;
- strictly ascending relational sequence order;
- at-least-once replay and UUID deduplication;
- one optional strict `Last-Event-ID`, resolved only inside the authenticated
  tenant and search;
- a 128-event query bound, 250 ms idle poll, 10-second comment keep-alive, and
  30-second connection lifetime;
- authorization recheck on every poll;
- pre-stream `invalid_request` for malformed, duplicate, foreign, or unknown
  cursors.

Normal connection closure is a reconnect point, not an operational result.
`stream_error` cannot deserialize as a `SearchEvent`, definitive verdict,
uncertainty, or absence observation.

## Generation and verification

From the repository root:

```console
cargo run --locked -p socialname-protocol --bin socialname-api-contract -- write
cargo run --locked -p socialname-protocol --bin socialname-api-contract -- check
cargo test --locked -p socialname-protocol --all-targets
cargo test --locked -p socialname-server \
  every_published_api_operation_is_registered_by_the_router
```

`write` produces only the known generated files and then verifies them.
`check` compares exact bytes and rejects unexpected JSON under the publication
directory. The protocol integration test performs the same comparison during
the normal workspace test gate, so a DTO, registry, generated artifact, or
manifest change cannot drift silently.

## Consumer use and remaining work

Consumers can resolve the relative schema references from `openapi.json`,
validate JSON at their own trust boundary, and generate exploratory clients.
Generated clients do not replace runtime validation, idempotency, SSE
deduplication, source/freshness/provenance interpretation, or consent policy.
No SDK is committed until it reduces measured adoption friction.

Hosted documentation, a production origin, release signing, package
distribution, quotas, usage records, service-level reporting, and production
compatibility observations remain later software or external evidence gates.
The next ordered Milestone 4 slice is the batch/quotas/usage/reporting item;
this publication does not pre-claim it.
