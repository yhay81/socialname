# Notification acknowledgement

## Scope

Notification acknowledgement is a tenant-local operator action on one
successfully delivered notification. It answers whether an authenticated
workspace principal recorded receipt of that exact logical delivery. It does
not prove that an email was opened, that a webhook receiver processed the
payload, or that a human reviewed the underlying account-state evidence.

Organization roles, assignments, review decisions, and shared incident
workflow remain the later Team milestone. Destination ownership verification
also remains a separate delivery-admission and external-evidence gate.

## API contract

The closed API v1 routes are:

```text
POST /v1/notification-deliveries/{delivery-id}/acknowledgement
GET  /v1/notification-deliveries/{delivery-id}/acknowledgement
```

Creation requires `notification:write` and a version-only
`NotificationAcknowledgementCreateRequest`. Reading requires
`notification:read`. The response contains only the stable delivery ID and
database time:

```json
{
  "schema": "socialname.dev/api/v1",
  "delivery_id": "opaque-delivery-id",
  "acknowledged_at_unix_ms": 1000
}
```

The first accepted request returns `201 Created`; exact replay returns
`200 OK` with the original time. A delivery that is queued, sending, retrying,
failed, or cancelled returns `409 Conflict`. Missing, foreign, and
deletion-hidden deliveries are uniformly `404 Not Found`. Rejected identifiers
and request bodies are never reflected.

## Storage and privacy boundary

Migration `0014_notification_acknowledgements.sql` stores at most one
acknowledgement per delivery. A database trigger independently requires the
referenced delivery to be `delivered` and prevents an acknowledgement time
before delivery. A companion trigger prevents later delivery updates from
invalidating that relation through one fixed-search-path definer check, so the
delivery worker receives no acknowledgement-table read privilege. Rows are
append-only and protected by forced tenant RLS.

The stored membership and API-key IDs provide private audit attribution, while
the public resource and watch timeline omit both. Only the first insert creates
one closed `notification.delivery.acknowledged` audit event. The application
role can select and insert acknowledgements but cannot update or delete them.
If a delivery is physically deleted, its acknowledgement is removed by the
same database cascade; while deletion lineage hides a delivery, acknowledgement
reads and timeline projection hide it too.

## Console behavior

The monitoring console projects `acknowledged_at_unix_ms` beside a delivered
notification. A key with `notification:write` can acknowledge an unacknowledged
delivery in place. The key remains memory-only and the action uses the same
same-origin authenticated API boundary as watch operations.

Loaded counts remain explicitly page-local. Workspace-wide delivery and
acknowledgement totals belong to the operational dashboard/SLO slice.

## Verification

Protocol tests lock the exact request/resource shape, unknown-field rejection,
timestamp relation, and delivery-state relation. The real PostgreSQL 18 test
proves scope separation, cross-tenant hiding, non-delivered conflict, database
trigger enforcement, exact replay, one audit event, append-only behavior,
least privilege, and safe timeline projection. Console tests cover the
page-local acknowledgement total, TypeScript contract, and production build.
