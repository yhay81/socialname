# Operational reporting and software objectives

## Scope

The Milestone 3 operational slice adds one tenant-local, target-free report
and presents it in the same-origin monitoring console:

```http
GET /v1/operations/report?window=24h
Authorization: Bearer snk_v1_<prefix>_<secret>
```

The closed windows are `24h`, `7d`, and `30d`; omitting `window` selects
`24h`. The response is an `OperationalReportResource` under
`socialname.dev/api/v1`. It contains database timestamps, aggregate backlog
counts, and four narrowly defined software objectives. It contains no
workspace, watch, target, transition, delivery, deletion-request, destination,
membership, API-key, or worker identifier.

This resource is an operational view of stored tenant state. It is not
Trustworthy Coverage Time, conclusive-verdict precision, a production uptime
claim, or proof that any contractual SLA was met.

## Authorization and consistency

`operations:read` is an independent closed API-key scope. It does not grant
watch, notification, deletion, evidence, or workspace reads. The HTTP
middleware and report loader both require the exact scope. The loader starts a
normal authorized transaction, sets the tenant locally, and reads through the
non-owner forced-RLS application role.

The later Team workflow also reuses `operations:read` for its separate
organization audit route, but only when the active membership role is owner or
administrator. That does not add audit events, actors, resource IDs, targets,
or details to this report and does not make the aggregate an audit-log read.

One PostgreSQL statement computes the complete report. A materialized bounds
row supplies `statement_timestamp()` and the exact window start, so every
aggregate shares one database snapshot and one evaluation time. Client time
does not affect the result. Migration `0016_operational_reporting.sql` adds
the scope to the database-enforced closed set and tenant/time indexes for the
two windowed cohorts; it adds no product table and no RLS policy.

The runtime role needs `SELECT` on `watches`, `watch_runs`, `probe_jobs`,
`notification_deliveries`, `notification_endpoints`, `transitions`,
`deletion_requests`, and `deletion_tasks` in addition to the common
authentication grants. It receives no new write or coordinator-function
privilege for this route.

Unknown windows and query fields return the closed `invalid_request` response
without reflecting their value. Storage, conversion, or contract validation
failure returns `unavailable`; the server never returns a partial report.

## Status model

Every objective has one of three states:

- `no_data`: no eligible denominator or sample exists;
- `meeting`: eligible data exists and satisfies the fixed objective;
- `breached`: eligible data exists and fails it.

`no_data` is never serialized or displayed as 100% success. Protocol
validation recomputes each status from its integer counts, fixed target, and
latency sample. A client cannot relabel a breach as meeting or change a target
inside an otherwise valid resource.

All success ratios use integer basis-point comparison rather than floating
point. Cancelled and unfinished work remains visible in state/backlog data but
does not silently enter a terminal success denominator.

## Fixed software objectives

| Objective | Eligible data | Good value | Fixed target |
| --- | --- | --- | --- |
| Watch-run success | Runs created inside the selected window whose current state is `completed` or `failed` | `completed` | at least 99.0% |
| Email delivery success | Email deliveries created inside the window whose current state is `delivered` or `permanently_failed` | `delivered` | at least 99.0% |
| Webhook delivery success | Webhook deliveries created inside the window whose current state is `delivered` or `permanently_failed` | `delivered` | at least 99.0% |
| Transition-to-delivery latency | Delivered notifications created inside the window, evaluated separately for email and webhook | discrete p95 of database `delivered_at - detected_at` | at most 5 minutes |

Queued, leased, running, retrying, cancelled, and other nonterminal states are
excluded from ratio denominators. A permanently failed delivery counts as a
terminal failure; it cannot disappear into a retry bucket. Latency samples
include delivered notifications only, while the separate delivery-success
objective exposes permanent failures.

The cohort is selected by server-created record time. This makes the report
repeatable from current repository state, but it is not a historical event
ledger: a delivery or run that changes state later changes the report while it
remains in the selected cohort.

## Deletion deadline health

Deletion reporting is deliberately a current health objective rather than a
historical compliance percentage. It ignores the selected activity window and
examines every currently open tenant request at the same generated database
time:

- no open request is `no_data`;
- one or more open requests with no failed request and no overdue milestone is
  `meeting`;
- any failed request or overdue milestone is `breached`.

The target is zero overdue milestones. The report keeps hide,
support-withdrawal, primary-delete, derived-rebuild, and backup-expiry counts
separate. Completion is derived from the durable progress fields and deletion
tasks already used by the deletion workflow. A request can therefore reveal
which stage needs attention without exposing its selector or ID.

This snapshot cannot prove elapsed production compliance. In particular, the
schema does not retain a complete historical time series for every hide and
rebuild transition. Hosted schedule history, provider inventory completeness,
backup observations, and production alert response remain external evidence
gates.

## Backlog context

The report also exposes current, non-SLO context:

- active, paused, and deleting watch counts;
- planned and running watch-run counts;
- queued, leased, and retry-wait probe jobs plus oldest pending age;
- queued, delivering, and retry-scheduled email and webhook deliveries plus
  oldest pending age.

Pending ages are present exactly when the corresponding backlog is nonempty.
They measure age since server creation, not time overdue or third-party
latency. Failed terminal counts remain in the objective cohorts rather than
being mixed with current pending work.

## Console behavior

The monitoring console loads the workspace, bounded watch page, and
operational report with the pasted key. The key remains only in component/ref
memory and every request remains same-origin and `no-store`. The dashboard:

- shows current tenant-wide operational objectives above loaded-page context;
- labels `no_data`, `meeting`, and `breached` explicitly and does not rely on
  color alone;
- switches among the three closed windows without placing the key in a URL;
- shows channel-specific success and p95 rather than blending email and
  webhook failures;
- states that the values are software objectives, not production SLA
  evidence;
- keeps paginated timeline counts under a separate “Loaded page context”
  label.

Responsive browser verification covers the default desktop viewport and a
375-pixel viewport. Below 480 pixels the longer operational cards become a
single column so latency and trust labels remain readable.

## Verification and remaining evidence

Protocol unit and wire-contract tests prove exact JSON shape, fixed targets,
window relations, backlog-age relations, and relabelling rejection. Console
model tests repeat the closed-structure and derived-status checks in
JavaScript-safe integer space.

The real PostgreSQL 18 test proves migration replay, `operations:read` denial,
unknown-window rejection, database-time bounds, two-tenant isolation,
channel-separated terminal outcomes, latency samples, target/identifier
exclusion, and successful validation through the non-owner application role.

Production SLO evidence still requires an approved deployment, stable
collection interval, alert ownership, incident process, retained report or
telemetry history, and observed multi-region/mail-provider operation.
Repository tests do not fabricate those facts.
