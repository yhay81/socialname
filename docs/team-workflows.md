# Team organizations, review, audit, and retention

## Scope

The first Team workflow builds on the existing tenant-isolated workspace. In
API v1, one workspace is one organization: the workspace ID remains the stable
organization boundary, and no second organization/workspace hierarchy or
cross-tenant membership is introduced.

This slice adds:

- bounded organization and member resources;
- role enforcement in addition to API-key scopes;
- owner/administrator member lifecycle controls;
- a target-free organization audit view;
- a confirmed account-transition review queue with assignment,
  acknowledgement, and resolution;
- organization-wide minimum and maximum watch-retention controls.

Public signup, invitations, browser sessions, identity-provider federation,
SCIM, organization switching, legal holds, arbitrary review notes, and
collaboration/incident-system integrations remain separate work.

## Compatibility and authorization

The published v1 scope enum is not expanded. Team authorization composes an
existing purpose-specific scope with the active membership role:

| Surface | API-key scope | Allowed active roles |
| --- | --- | --- |
| Organization and member reads | `workspace:read` | owner, administrator, member, viewer |
| Member creation and mutation | `workspace:read` | owner; administrator for member/viewer only |
| Retention read | `workspace:read` | owner, administrator, member, viewer |
| Retention mutation | `workspace:read` | owner, administrator |
| Audit read | `operations:read` | owner, administrator |
| Review read | `watch:read` | owner, administrator, member, viewer |
| Review assignment | `watch:write` | owner, administrator |
| Review acknowledgement/resolution | `watch:write` | assigned owner, administrator, or member |

Roles also bound every existing scope even if an API key was provisioned with
a broader scope:

- `owner` and `administrator` may use any scope on their key;
- `member` may use product read/write, consent, evidence, notification,
  operations, usage, export, and owned deletion scopes;
- `viewer` may use read/report/export scopes only.

An API key is therefore necessary but not sufficient authority. Suspending or
removing a membership immediately disables every key created for it because
authentication rechecks membership state and role on each request.

The owner invariants are:

- an organization always retains at least one active owner;
- only an owner may create, promote, demote, suspend, or remove an owner or
  administrator;
- administrators may manage only member and viewer memberships;
- an actor cannot suspend, remove, or change their own role;
- a member with an assigned unresolved review must be reassigned before being
  suspended, removed, or changed to viewer.

Membership subject references are tenant-private provisioning inputs. They are
never returned by the API, included in audit resources, or reflected in
errors. Public resources expose only an opaque membership ID, bounded display
name, role, state, revision, and database timestamps.

## Organization API

The closed routes are:

```text
GET   /v1/organization
GET   /v1/organization/members
POST  /v1/organization/members
PATCH /v1/organization/members/{membership_id}
GET   /v1/organization/audit-events
GET   /v1/organization/retention-policy
PATCH /v1/organization/retention-policy
```

Member and audit lists use bounded opaque-ID keyset cursors. Member creation
serializes on the tenant-private subject reference. An exact active replay
returns the existing resource; changed content, a removed subject, an invalid
role transition, a stale revision, or a last-owner violation is a conflict.
Removal is one-way and revokes the target membership's active API keys in the
same transaction.

The public audit projection contains only the event ID, closed actor
attribution, bounded action and resource kind, optional opaque resource ID, and
database time. The internal `details` object, membership subject, target,
destination, credential, request body, and evidence payload are never
projected.

## Review and acknowledgement

A Team review is created exactly once when an `account_state` transition first
becomes `confirmed`. Pending, suppressed, and `measurement_health` transitions
do not enter the human account-change queue. Migration backfill applies the
same rule to existing confirmed account transitions.

The routes are:

```text
GET   /v1/reviews
PATCH /v1/reviews/{review_id}
```

Each resource contains the complete validated transition plus the review's
current workflow state and attribution. The state machine is:

```text
open --assign--> open --acknowledge--> acknowledged --resolve--> resolved
```

Assignment or reassignment is allowed only while open and requires an active
non-viewer member. Acknowledgement and resolution require the exact assigned
membership. Resolution uses one of four closed dispositions:

- `action_taken`
- `no_action_required`
- `measurement_follow_up`
- `externally_escalated`

The disposition records workflow handling only. It cannot relabel the
transition, change assertion support, establish common ownership, or claim
impersonation. Arbitrary notes are excluded from this first contract so a
review action cannot become an unbounded store for target or incident data.

Every mutation uses an exact positive revision, advances it once with database
time, appends one immutable review event, and writes one bounded audit event in
the same transaction. Stale or changed replay conflicts. Deletion-lineage
hiding of the underlying transition hides the review immediately; physical
transition deletion cascades through its review history.

This review acknowledgement is distinct from
`notification_acknowledgements`. The existing receipt says only that a
workspace principal recorded one delivered notification. Team
acknowledgement says that the assigned reviewer accepted responsibility for
examining the underlying confirmed account transition.

## Organization retention policy

Each organization has one revisioned policy with:

- `minimum_watch_retention_days`, from 30 through 730;
- `maximum_watch_retention_days`, from the minimum through 730.

The migration gives existing and new organizations the compatibility policy
`30..730`. Watch creation and any patch that changes retention must satisfy the
current organization policy in addition to the existing hard protocol bounds.
A database trigger independently enforces the relation.

A policy update is refused while any non-deleting watch lies outside the new
range. The operator must first make those explicit revisioned watch changes;
the policy never silently shortens or lengthens existing retention. Once
accepted, the range applies immediately to all later watch writes and therefore
to the existing Evidence Capsule retention derivation.

This slice does not claim configurable retention for immutable consent or
deletion receipts, backups, rule-health history, or exceptional debugging
artifacts. Their accepted hard schedules and deletion workflows remain
unchanged.

## Storage and failure boundary

The migration adds:

- membership display name and optimistic revision;
- `organization_retention_policies`;
- `transition_reviews`;
- append-only `transition_review_events`;
- the indexes and triggers required for bounded pages, review creation,
  last-owner safety, and watch-policy enforcement.

All new tenant tables use forced RLS and composite tenant foreign keys. The
HTTP role receives only the column/table privileges used by these routes; it
cannot update audit or review-event history, mutate a review outside the
handler transaction, read membership subject references, or bypass RLS.

Role, scope, tenant, entitlement-independent privacy, revision, state-machine,
and database failures remain distinct authorization, conflict, not-found, or
unavailable responses. No failure can become an account-state observation or
alter measurement truth.

## Verification

The deterministic gate proves:

- role-based denial even when a key contains the requested scope;
- member creation replay/conflict, private subject handling, last-owner safety,
  self-mutation denial, membership suspension, and key invalidation;
- two-tenant member, audit, policy, and review isolation under a real non-owner
  `NOBYPASSRLS` PostgreSQL role;
- target-free audit projection and append-only internal history;
- compatibility-default and narrowed watch-retention enforcement in both HTTP
  and direct SQL paths;
- confirmed-account-only review creation, assignment, exact reviewer
  acknowledgement, resolution, stale revision rejection, immutable event
  history, and deletion hiding;
- exact committed OpenAPI/JSON Schema publication and Axum route/scope drift;
- console model, accessibility, TypeScript, and production-build behavior.

Repository evidence:

```console
cargo fmt --all -- --check
cargo run --locked -p socialname-protocol \
  --bin socialname-api-contract -- check
# exact committed OpenAPI with 38 operations and 45 JSON Schema roots
cargo test --locked --workspace --all-targets
# passed against PostgreSQL 18; includes protocol 64 unit + 20 wire +
# 1 publication and server 47 library + 2 binary + 1 full integration
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
# validated 10 rules
cargo run --locked -p socialname-cli -- fixtures
# verified 30 fixture cases across 10 sites
node --test examples/api-v1/client.test.mjs
# 5 passed
cd apps/desktop
npm ci
npm run check
npm run build
# passed; npm reported 0 vulnerabilities
cd ../console
npm ci
npm run check
npm test
npm run build
# 6 passed; npm reported 0 vulnerabilities
```

Local browser verification used live API data at the default desktop viewport
and a 375-by-812 viewport. The Team directory, review queue, retention controls,
and audit list rendered without console errors. The narrow viewport collapsed
Team and governance grids to one column with no horizontal overflow. The
disposable PostgreSQL 18 container and fixture database were removed after the
gate.
