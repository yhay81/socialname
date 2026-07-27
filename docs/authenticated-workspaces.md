# Authenticated private workspaces and API keys

The first managed authentication slice provides an operator-created private
workspace, one-time API-key issuance and revocation, a least-privilege runtime
database boundary, and one authenticated read:

```http
GET /v1/workspace
Authorization: Bearer snk_v1_<prefix>_<secret>
```

It deliberately does not implement public signup, browser sessions, an identity
provider, billing, search creation, watch management, or network ingress. Those
capabilities remain closed until their ordered roadmap slices supply their full
authorization and failure behavior.

## API-key format and storage

An API key has the exact form:

```text
snk_v1_<16 lowercase hexadecimal prefix>_<64 lowercase hexadecimal secret>
```

The public prefix is generated from 64 independent random bits and is only an
index. The secret is generated separately from 256 random bits. Generation uses
the Rust CSPRNG; IDs use random UUID v4 values. OWASP recommends
cryptographically secure generation and sufficiently long, securely stored
tokens for security-sensitive flows
([Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html),
[Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)).

The presented token is never stored. `api_key_credentials` contains only its
prefix and SHA-256 secret digest plus the tenant/key IDs needed to begin
authentication. SHA-256 is appropriate here because the input is a uniformly
random 256-bit machine credential, not a human password with a guessable
distribution. The metadata row in tenant-RLS table `api_keys` contains scopes,
state, creation actor, expiry, revocation, and last-use time but no prefix or
digest.

The in-memory secret has a redacted `Debug` representation and is zeroized on
drop. Validation and database errors never include a presented key. Operator
commands print a newly issued key exactly once through an explicit exposure
method; production operation must capture that stdout directly into an
approved secret manager and must not place it in CI logs, shell history,
metrics, traces, tickets, or repository files.

## Closed scopes

Keys contain a nonempty, duplicate-free subset of at most 16 values from:

- `workspace:read`
- `search:read`, `search:write`
- `watch:read`, `watch:write`
- `consent:read`, `consent:write`
- `evidence:read`
- `notification:read`, `notification:write`
- `operations:read`
- `data:export`, `data:delete`

Migrations `0002_api_key_authentication.sql` and
`0010_consent_grant_lifecycle.sql`, `0011_evidence_capsule_retention.sql`, and
`0016_operational_reporting.sql` evolve the same closed set and reject null or
duplicate array entries. All scopes except `data:export` now have exact HTTP
consumers. `operations:read` protects only the target-free tenant aggregate; it
does not grant access to watches, notification resources, deletion resources,
or evidence.

## Operator lifecycle

Schema migration and workspace/key administration use the explicit
schema-owner URL `SOCIALNAME_DATABASE_URL`. The HTTP server never uses this
credential.

Bootstrap a workspace and initial owner key:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://SCHEMA_OWNER:...@HOST/DATABASE"
$env:SOCIALNAME_WORKSPACE_SLUG = "example"
$env:SOCIALNAME_WORKSPACE_DISPLAY_NAME = "Example"
$env:SOCIALNAME_MEMBERSHIP_SUBJECT = "operator-subject"
$env:SOCIALNAME_API_KEY_SCOPES = "workspace:read,search:read"
# Optional positive Unix timestamp in milliseconds:
$env:SOCIALNAME_API_KEY_EXPIRES_AT_UNIX_MS = "1798761600000"
cargo run --locked -p socialname-server -- bootstrap-workspace
```

The successful command creates the tenant, active owner membership, key
metadata, credential digest, and `workspace.bootstrap` audit event in one
transaction. It prints `workspace_id`, `membership_id`, `api_key_id`, and the
one-time `api_key`. A duplicate workspace fails without a partial tenant or
credential.

Issue a rotation or purpose-specific key:

```powershell
$env:SOCIALNAME_WORKSPACE_ID = "<workspace UUID>"
$env:SOCIALNAME_MEMBERSHIP_ID = "<active owner/administrator membership UUID>"
$env:SOCIALNAME_API_KEY_SCOPES = "workspace:read"
cargo run --locked -p socialname-server -- issue-api-key
```

Revoke a key:

```powershell
$env:SOCIALNAME_API_KEY_ID = "<API-key UUID>"
cargo run --locked -p socialname-server -- revoke-api-key
```

Issue and revoke require an active owner or administrator membership in an
active workspace, execute under transaction-local tenant RLS, and append
`api_key.issue` or `api_key.revoke` audit events. Unknown, inactive,
insufficient-role, duplicate, malformed, and database-failure paths return
fixed classes without echoing supplied values. Dropped or cancelled futures
roll back their transaction.

## Runtime database role

The HTTP process requires a separate non-owner connection:

```powershell
$env:SOCIALNAME_SERVER_DATABASE_URL = "postgres://SOCIALNAME_APP:...@HOST/DATABASE"
cargo run --locked -p socialname-server
```

The role must be `NOSUPERUSER NOBYPASSRLS` and must not own product tables. For
the current route it needs only:

```sql
GRANT USAGE ON SCHEMA public TO socialname_app;
GRANT SELECT ON tenants, api_keys TO socialname_app;
GRANT UPDATE (last_used_at) ON api_keys TO socialname_app;
GRANT EXECUTE ON FUNCTION socialname_authenticate_api_key(text, bytea)
    TO socialname_app;
```

It must not receive `SELECT` on `api_key_credentials`, membership mutation,
schema creation, or migration rights. The integration test creates this exact
kind of login and proves that the credential table remains unreadable. The
additional column-limited grants for private search are specified in
[Private search API and ordered event stream](search-api.md).

## Authentication and RLS flow

Each protected request:

1. accepts exactly one strict `Authorization: Bearer` value;
2. parses and hashes the secret without logging it;
3. calls a locked-down `SECURITY DEFINER` function that can compare only the
   prefix/digest table and returns only tenant/key IDs;
4. starts a runtime-role transaction and sets `socialname.tenant_id` with
   `set_config(..., true)`;
5. under forced RLS, rechecks active tenant, active key-creating membership,
   active/nonexpired key, and the required scope, then records `last_used_at`;
6. starts the route data transaction with the same transaction-local tenant and
   reads only that workspace.

PostgreSQL documents that forced RLS also subjects table owners unless they are
superusers or have `BYPASSRLS`, and that a local `set_config` applies only for
the current transaction
([row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html),
[`set_config`](https://www.postgresql.org/docs/current/functions-admin.html)).
The application nevertheless uses a non-owner role, and tenant state never
survives a transaction or leaks through the connection pool.

The definer function has `search_path=pg_catalog`, references its table with a
qualified name, and has `PUBLIC` execution revoked. The global credential
lookup table also has all `PUBLIC` privileges revoked. It is outside tenant RLS
only because the tenant is not known until a credential matches; no route can
read it directly.

## HTTP behavior

`GET /v1/workspace` requires `workspace:read` and returns a validated
`socialname.dev/api/v1` `WorkspaceResource` containing:

- workspace ID, slug, display name, and active state;
- authenticated key ID and public prefix;
- the key's closed scopes, active state, and optional expiry.

It contains no presented secret, digest, membership subject, database URL, or
cross-tenant data.

Missing, malformed, unknown, revoked, or expired credentials all return the
same nonretryable protocol `unauthenticated` response and
`WWW-Authenticate: Bearer`. A valid key missing `workspace:read` returns
`forbidden`. Database/acquire/deadline failure returns retryable `unavailable`,
never an authentication verdict or account-state observation.

`GET /health/live` remains dependency-free. `GET /health/ready` now performs a
bounded database probe shorter than the outer request deadline and returns
`ready` or HTTP 503 `not_ready`. Neither health endpoint needs a credential.

## Verification and remaining gates

The PostgreSQL 18 integration gate covers:

- replay-safe migrations, 49 product tables, and 37 forced-RLS policies;
- credential-table and definer-function `PUBLIC` privilege revocation;
- a real `LOGIN NOSUPERUSER NOBYPASSRLS` runtime role;
- transaction-local tenant separation for two valid keys;
- uniform missing/wrong/revoked/expired rejection and distinct scope denial;
- a successful private workspace response with no secret/digest fields;
- last-use persistence and database-aware readiness degradation;
- transactional bootstrap, issuance, revocation, audit, conflict rollback, and
  digest-only persistence.

TLS termination, ingress trust, per-source authentication throttling, external
identity proofing, production secret-manager capture, and deployed credential
rotation are external or later software gates. The server remains
loopback-only by default and no claim is made that this slice alone is safe for
open Internet exposure.
