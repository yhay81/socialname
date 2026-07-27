# SocialName API v1 contracts

This directory is the repository publication of the stable
`socialname.dev/api/v1` developer contract. It deliberately declares no hosted
base URL or production availability.

Machine-readable artifacts:

- `openapi.json` is an OpenAPI 3.1 description of every implemented
  authenticated REST/JSON operation and the SSE endpoint;
- `schemas/*.schema.json` are the independent Draft 2020-12 JSON Schema roots
  generated from `socialname-protocol`;
- `sse.json` fixes the event names, frame fields, retry hint, keep-alive,
  ordering, resumption, authorization recheck, and terminal stream-error
  behavior that OpenAPI cannot express completely;
- `manifest.json` binds every generated artifact except the manifest itself to
  a SHA-256 digest. It is an integrity/drift manifest, not a release signature.

The OpenAPI description follows
[OpenAPI 3.1.2](https://spec.openapis.org/oas/v3.1.2.html) and links to the
separate JSON Schema and SSE files by relative reference. Runtime
cross-field validation, authentication, tenant isolation, consent, destination
policy, and production availability remain server behavior; a schema-valid
document alone does not authorize an operation or prove an account state.

Do not edit generated JSON by hand. From the repository root:

```console
cargo run --locked -p socialname-protocol --bin socialname-api-contract -- write
cargo run --locked -p socialname-protocol --bin socialname-api-contract -- check
```

The protocol test suite performs the same exact byte comparison and rejects
unexpected generated JSON files. Existing v1 fields, enum values, tagged-union
shapes, required scopes, status meanings, or SSE frame semantics are not
silently changed. An incompatible change requires a new public contract
version and an explicit migration policy.

The publication currently contains 28 authenticated operations and 33
independent JSON Schema roots. Adoption-focused, dependency-free Node.js
examples for resumable search and paginated private-history export live under
[`examples/api-v1`](../../../examples/api-v1/README.md); they do not replace
the machine-readable contract or runtime validation.
