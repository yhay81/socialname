# Modular-monolith server shell

`socialname-server` is the operable Axum/Tower process boundary for the managed
SocialName product. It embeds forward-only PostgreSQL migrations, provides
explicit workspace/API-key operator commands, and exposes one authenticated
private workspace read. Search, watch, notification, and other product routes
remain closed until their ordered roadmap slices add authorization, storage
use, lineage, and failure behavior end to end.

The server depends on `socialname-protocol`; it does not make the protocol,
domain, or engine depend on HTTP or persistence.

## Runtime configuration

The serving binary reads five environment variables:

| Variable | Default | Accepted range |
| --- | --- | --- |
| `SOCIALNAME_SERVER_BIND` | `127.0.0.1:8080` | A concrete socket address |
| `SOCIALNAME_SERVER_REQUEST_TIMEOUT_MS` | `30000` | 100 to 120000 whole milliseconds |
| `SOCIALNAME_SERVER_MAXIMUM_BODY_BYTES` | `262144` | 1024 to 1048576 bytes |
| `SOCIALNAME_SERVER_MAXIMUM_IN_FLIGHT` | `128` | 1 to 1024 requests |
| `SOCIALNAME_SERVER_DATABASE_URL` | none | A PostgreSQL URL for a non-owner runtime role |

The default is loopback-only. Binding a non-loopback address requires an
explicit value; it does not imply that TLS, authentication, abuse controls, or
production ingress are ready. Invalid and non-Unicode configuration is rejected
before bind. Errors name the variable and constraint but omit its supplied
value.

PowerShell development start:

```powershell
$env:SOCIALNAME_SERVER_BIND = "127.0.0.1:8080"
$env:SOCIALNAME_SERVER_DATABASE_URL = "postgres://SOCIALNAME_APP:...@HOST/DATABASE"
cargo run --locked -p socialname-server
```

No SocialName service is started by ordinary CLI or desktop execution. The
server is a separate explicit binary.

## Database migration command

Migration is an explicit operator action:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://USER:PASSWORD@HOST:5432/DATABASE"
cargo run --locked -p socialname-server -- migrate
```

There is no database URL default. Connection and migration work is bounded,
uses one connection, and returns fixed error classes that do not echo the URL
or credentials. The schema, RLS application contract, migration ownership, and
PostgreSQL 18 integration gate are documented in
[PostgreSQL schema and migration boundary](postgresql-schema.md).

Workspace bootstrap, one-time API-key issuance, revocation, runtime role
grants, token handling, and the protected route are documented in
[Authenticated private workspaces and API keys](authenticated-workspaces.md).

## Current HTTP surface

The server exposes:

```http
GET /health/live
GET /health/ready
GET /v1/workspace
```

The two health endpoints return a small `socialname.dev/api/v1` JSON document
with service name, crate version, and health status. Liveness is
dependency-free. Readiness probes PostgreSQL with a deadline shorter than the
outer request deadline and returns HTTP 503 `not_ready` when storage is
unavailable.

`GET /v1/workspace` requires one valid bearer API key with
`workspace:read`. It authenticates through the restricted credential lookup,
rechecks key/workspace state under forced transaction-local tenant RLS, and
returns only that private workspace plus nonsecret key metadata. Missing,
unknown, malformed, revoked, and expired credentials are uniformly
`unauthenticated`; insufficient scope is `forbidden`; database failure is
`unavailable`.

Every other path returns a protocol `not_found` response. Unsupported methods
return a protocol `invalid_request` response. In particular, `/v1/searches`,
watches, notification endpoints, and HTTP key-administration routes do not
exist yet, so authentication cannot accidentally make later product
capabilities available.

## Request boundary

The Tower stack is ordered so one outer request guard:

1. accepts only a syntactically bounded `x-request-id` or generates a server ID;
2. rejects invalid or oversized declared content lengths;
3. applies the configured handler deadline;
4. adds `cache-control: no-store`, `x-content-type-options: nosniff`, and the
   request ID to every response.

A Tower concurrency layer bounds in-flight handler work. Axum's default body
limit is set to the same configured maximum for future body-consuming
extractors. Each future JSON route must still map extractor rejections into the
closed protocol error envelope and must not bypass the body limit by polling raw
frames.

Missing routes, method errors, declared-body overflow, invalid content length,
and deadline failure remain JSON protocol errors. They do not return framework
debug text, a stack trace, the rejected value, or the request URI. Operational
deadline failure is `unavailable`, not `not_found` or an account verdict.

## Logging and sensitive data

Request spans contain only request ID and HTTP method. Completion records add
status and elapsed milliseconds. The URI, query, headers, request body,
username, public identifier, notification destination, and protocol DTO are not
logged by the shell.

That exclusion includes the `Authorization` header, API-key prefix/secret/hash,
workspace name, membership subject, and database URL. Authentication errors use
fixed protocol categories and never log or reflect a credential.

Future route work must preserve that boundary. Targets belong in validated JSON
bodies, not path or query fields that infrastructure commonly records. Error
mapping must use field/code information without rejected values.

## Shutdown

The binary uses `axum::serve` with graceful shutdown. Ctrl-C is supported on all
platforms and SIGTERM is also handled on Unix. Registration failure is logged
without pretending that a graceful signal was received. The library accepts an
injected shutdown future so drain behavior is deterministic in tests.

## Verification

```console
cargo fmt --all -- --check
cargo test --locked -p socialname-server
cargo clippy --locked -p socialname-server --all-targets --all-features -- -D warnings
cargo build --locked -p socialname-server
# With the documented owner, runtime, and test database URLs set:
cargo run --locked -p socialname-server -- migrate
```

The deterministic tests cover default and explicit configuration, secret-free
configuration errors, every resource bound, hardened/versioned health,
request-ID regeneration, closed 404/405 errors, typed content-length rejection,
deadline failure, absence of an unauthenticated `/v1/searches` route, API-key
parsing/redaction, operator configuration, and graceful shutdown. PostgreSQL CI
additionally covers migration replay, schema inventory, forced RLS, non-owner
authentication, workspace isolation, key expiry/revocation/scope, readiness,
operator lifecycle, evidence immutability, notification safety, and deletion
lineage.
