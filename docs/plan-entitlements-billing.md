# Plan entitlements and billing boundary

## Purpose

Milestone 4 needs a commercial-access boundary without making payment state a
measurement concept. This slice adds a closed, provider-neutral entitlement
model around already implemented managed search and monitoring. It does not
add checkout, prices, invoices, tax, cards, a payment-provider SDK or webhook,
or a hosted-service claim.

The rule compiler, measurement engine, domain observations, assertions, and
worker execution types do not depend on plans or billing. Entitlements answer
only whether the server may admit new managed work.

## Closed model

Plans and their exact capabilities are:

| Plan | `managed_search` | `monitoring` | Meaning |
| --- | --- | --- | --- |
| `community` | no | no | local product use; no new managed work |
| `developer` | yes | no | managed search admission |
| `monitor` | yes | yes | managed search and scheduled monitoring |
| `evaluation` | yes | yes | migration/evaluation bridge, not a price or paid status |

Capabilities are derived from the plan and cannot be independently stored or
added by a provider. Unknown plans and capabilities fail closed.

The stored access state is only `active` or `suspended`. `effective_at` and an
optional `access_until` produce the public state at database evaluation time:

- `pending` before `effective_at`;
- `active` after `effective_at` while stored access is active and the optional
  deadline is still in the future;
- `suspended` after explicit suspension or expiry of `access_until`.

This permits a provider adapter to represent a bounded grace period without
introducing invoice, payment-method, or provider-specific state into the
product schema. A new workspace starts on `community`. Migration `0020`
assigns existing workspaces `evaluation` so deployment does not silently
disable managed work that was already available before entitlements existed.
Operators must replace that bridge with an intentional plan before making a
commercial claim.

## Public read

```http
GET /v1/workspace/plan
Authorization: Bearer snk_v1_<prefix>_<secret>
```

The route requires `workspace:read` and returns
`PlanEntitlementResource` with the closed plan, derived state, exact derived
capabilities, optimistic revision, effective/access deadline, update time, and
database evaluation time. It contains no provider, customer, subscription,
price, invoice, card, billing-event, or credential field.

`pending` and `suspended` resources always expose an empty capability list.
Runtime validation binds plan, state, capabilities, timestamps, and revision;
unknown JSON fields are rejected. The deterministic API publication includes
this route and its independent Draft 2020-12 schema.

## Admission and suspension behavior

The server checks entitlements inside the same transaction that would create
new managed work:

| Operation | Required capability | Suspension behavior |
| --- | --- | --- |
| new managed search | `managed_search` | rejected before quota/usage commits |
| exact search idempotency replay | none | original resource remains readable |
| new search-completion webhook binding | `managed_search` | rejected; exact existing binding replay remains readable |
| new watch | `monitoring` | rejected |
| patch whose resulting watch state is active | `monitoring` | rejected |
| pause or delete a watch | none | remains available |
| schedule a new due watch run | `monitoring` | scheduler skips the workspace |

History, polling, event streaming, terminal export, cancellation, plan reads,
existing webhook reads/cancellation, and other privacy or recovery operations
remain available according to their existing scopes. Already accepted search
or worker work may reach its existing terminal path. Entitlement loss does not
relabel an observation, assertion, transition, operational failure, quota, or
account state.

A capability denial uses the existing nonretryable HTTP 403 `forbidden`
contract. Database inability to evaluate the entitlement is retryable HTTP 503
`unavailable`; it never falls back to admission.

Developer target-pair quotas remain independent software capacity guardrails.
An entitlement allows admission to reach quota evaluation but does not choose,
replace, or bypass the tenant/API-key limits described in
[Developer quota, usage, and service reporting](developer-usage-reporting.md).

## Provider-neutral reconciliation

The schema-owner operator is the adapter seam for a future payment provider:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://SCHEMA_OWNER:...@HOST/DATABASE"
$env:SOCIALNAME_WORKSPACE_ID = "<workspace UUID>"
$env:SOCIALNAME_PLAN_EXPECTED_REVISION = "2"
$env:SOCIALNAME_PLAN_CODE = "monitor"
$env:SOCIALNAME_PLAN_ACCESS_STATE = "active"
$env:SOCIALNAME_PLAN_EFFECTIVE_AT_UNIX_MS = "1785100000000"
# Optional grace/access deadline; omit for no deadline:
$env:SOCIALNAME_PLAN_ACCESS_UNTIL_UNIX_MS = "1785704800000"
$env:SOCIALNAME_BILLING_EVENT_ID = "<provider event or reconciliation ID>"
cargo run --locked -p socialname-server -- reconcile-plan-entitlement
```

The command accepts one printable ASCII source event ID of at most 200 bytes.
It stores only a SHA-256 event digest and a SHA-256 digest of all effective
request fields. The raw event ID is never persisted, audited, printed, logged,
or included in an error. The current row advances by exactly one revision and
an append-only event plus target-free audit record commit in the same
transaction.

Replaying the same event and same effective request is idempotent. Reusing an
event with different content fails as an event conflict. A new event with a
stale expected revision fails as a revision conflict. An adapter therefore
must first map provider state into the closed SocialName model, choose the
effective/grace timestamps, and reconcile with the last observed revision.
Provider signature verification, replay intake, event ordering, API secrets,
and provider availability remain entirely outside this command.

## PostgreSQL and least privilege

Migration `0020_plan_entitlements.sql` adds:

- `tenant_plan_entitlements`, one forced-RLS current row per workspace;
- `plan_entitlement_events`, a forced-RLS append-only revision history;
- `socialname_has_plan_capability(uuid, text)`, a narrow tenant-checked
  `SECURITY DEFINER` admission function;
- a plan-aware replacement for `socialname_worker_lock_due_watch`.

The HTTP role may select only the current row's tenant, plan/access, revision,
and public timestamp columns and execute the capability function. It cannot
read the current source/request hashes, update entitlements, or read event
history. The worker does not receive direct plan-table privileges; only the
existing narrow scheduler function considers monitoring access. Schema-owner
reconciliation sets the transaction-local tenant and remains subject to the
same forced RLS.

No table contains provider, customer, price, invoice, payment-method, card, or
raw event fields. The initial bootstrap and migration event identities use
PostgreSQL's built-in SHA-256; billing reconciliation hashes in Rust before
persistence.

## Verification and remaining gates

Protocol tests prove the closed plan/capability mapping, exact provider-neutral
wire shape, state/timestamp relations, and generated-contract determinism.
Server tests prove closed/redacted operator input and the registered
route/scope map.

The PostgreSQL 18 integration gate proves:

- new-workspace `community` bootstrap and existing-workspace `evaluation`
  migration behavior;
- pending, grace-active, explicit suspension, and restoration;
- idempotent event replay plus event/revision conflicts;
- two-tenant plan reads, scope separation, forced RLS, and least privilege;
- no search or usage row on denied admission;
- existing search/webhook replay, history, cancellation, watch pause/delete,
  and privacy paths during suspension;
- denial of new searches, webhook bindings, watches, and watch resumption;
- no new due-watch scheduling while monitoring is suspended;
- digest-only event persistence and provider-neutral audit output.

Production provider selection, provider webhook verification, checkout,
pricing, taxation, invoices, refunds, subscription self-service, customer
support policy, dunning/grace policy approval, hosted deployment, and live
reconciliation evidence are external or later gates. This repository slice
does not claim that any plan has been sold or paid.
