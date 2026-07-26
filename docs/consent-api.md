# Purpose-specific consent grant lifecycle

## Scope

The server exposes a versioned lifecycle for the three independent consent
purposes accepted in [Data governance](data-governance.md):

- `private_history`
- `shared_observation`
- `shared_research`

Authentication, workspace role, payment, search mode, and one grant for a
different purpose never imply consent. The wire contract is owned by
`socialname-protocol`; migration
`0010_consent_grant_lifecycle.sql` supplies the database constraints.

## Current contract versions

Every new grant binds the tuple:

```text
(purpose, collection_profile_version=profile-v1, notice_version=notice-v1)
```

`profile-v1` means the field categories documented for that exact purpose in
[Data governance](data-governance.md); the purpose is part of the version
identity. The database rejects any other profile or notice value. A material
notice or collection change therefore requires a reviewed migration, a new
closed protocol value, and a new grant rather than reinterpretation of an old
row.

## Subjects

An account grant is always bound to the active membership that created the
authenticated API key. A caller cannot provide another membership ID.

An installation grant accepts a locally generated canonical lowercase UUID v4
as opaque `installation_id`. Clients must generate it with a CSPRNG; the
server can enforce the 122-bit UUIDv4 namespace shape but cannot prove how a
particular value was generated. The unpredictable identifier prevents
practical pre-registration by another workspace member.
The request value is sensitive and has a redacted Rust `Debug` representation.
The server stores only a domain- and tenant-separated SHA-256 digest, creates
an opaque `clients` resource, and returns that client ID as `subject_id`. The
first active membership to register the installation becomes its consent
owner. Even another administrator in the same workspace receives `conflict`
for that installation, so workspace policy cannot silently override an
installation refusal. A suspended, deleted, unowned legacy, or differently
owned client also fails closed.

The API key still authenticates the request; the installation ID is not an
authentication secret and is never accepted in place of the bearer key.

## HTTP API and scopes

```http
POST /v1/consent-grants
GET  /v1/consent-grants?limit=20&after={consent_grant_id}
GET  /v1/consent-grants/{consent_grant_id}
POST /v1/consent-grants/{consent_grant_id}/withdrawals
```

Creation and withdrawal require `consent:write`; list and single-resource
reads require `consent:read`. Both are closed API-key scopes. All four routes
run under the authenticated workspace's transaction-local forced RLS.

Creation accepts `ConsentGrantCreateRequest`. The request names the subject
kind, exact purpose/profile/notice tuple, and an optional future expiry.
`installation_id` is required only for an installation subject. The server
derives `source=api` and database time; callers cannot backdate a grant.

Concurrent or repeated creation for the same subject, purpose, current
contract, and expiry is serialized in PostgreSQL. While that grant remains
active, exact replay returns `200` and the same resource. A different expiry
conflicts instead of silently changing or ignoring the request. The first
creation returns `201` and `Location`. An expired or withdrawn grant is never
revived; a later affirmative choice creates a new grant and a new immutable
`granted` event.

Lists are ordered by grant time and ID, return at most 50 resources, and use a
tenant- and ownership-validated keyset cursor. Account grants are visible only
to their membership. Installation grants are visible only to the membership
recorded by their immutable `granted` event. Foreign IDs are `not_found`;
foreign or malformed cursors are `invalid_request`.

## Withdrawal

Withdrawal is a one-way, idempotent transition. One transaction locks the
owned grant, sets database `withdrawn_at`, and appends one actor-bound
`withdrawn` event. A trigger rejects changes to the subject, purpose, contract,
source, grant time, or expiry and rejects any attempt to clear or replace a
withdrawal. Consent events are append-only.

Search, watch, job expansion, and worker ingestion already require a matching
unexpired grant with `withdrawn_at IS NULL`. PostgreSQL locking gives a precise
race rule: either authorized ingestion commits before the withdrawal, or the
withdrawal commits first and the new ingestion is rejected. The integration
test also proves a managed search is accepted immediately before withdrawal
and forbidden immediately afterward.

Withdrawal stops new use but does not claim that retained contributions have
been deleted. A `delete_prior_contributions` option is intentionally not
published until the ordered lineage-backed deletion workflow can create,
process, and receipt the request within its documented deadlines. Operators
can withdraw now without receiving a false deletion guarantee.

## Failure boundary

- malformed bodies, subject/installation mismatches, past expiries, limits, and
  cursors: `invalid_request`;
- a valid key without the exact route scope: `forbidden`;
- foreign or unowned grant IDs: `not_found`;
- inactive or differently owned installation: `conflict`;
- database or invariant decoding failure: retryable `unavailable`.

Errors contain only closed codes and field names. They do not echo an
installation ID, bearer token, subject identifier supplied by a caller, or
database value.

## Verification

```console
cargo test --locked -p socialname-protocol
cargo clippy --locked -p socialname-protocol -p socialname-server \
  --all-targets --all-features -- -D warnings
# With disposable PostgreSQL 18 administrator/application/worker URLs:
cargo test --locked -p socialname-server --test postgres_migrations
```

The PostgreSQL gate applies migrations twice, uses real non-owner
`NOBYPASSRLS` application and worker roles, and covers all purposes, both
subject kinds, exact replay, pagination, tenant isolation, administrator
non-override, one-way withdrawal, immutable events, replacement grants, and
the immediate search authorization boundary.
