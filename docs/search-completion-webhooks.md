# Search-completion webhooks

## Purpose and stable-v1 boundary

Developer clients can already submit a bounded search batch, poll its resource,
and resume its ordered SSE stream. This slice adds an optional webhook signal
for clients that should poll only after a search reaches `completed` or
`failed`.

The existing stable `SearchCreateRequest` remains closed and unchanged.
Webhook binding is a separate resource:

```http
POST   /v1/searches/{search_id}/completion-webhook
GET    /v1/searches/{search_id}/completion-webhook
DELETE /v1/searches/{search_id}/completion-webhook
```

Creation and cancellation require `search:write`; reads require `search:read`.
The create body contains only the API version and one existing active webhook
endpoint ID. Exactly one completion-webhook binding may exist per search.
Replaying the exact endpoint returns the same resource; a different endpoint
conflicts instead of silently replacing the delivery destination.

Endpoint destination creation, verification, activation, encryption, and
ownership remain the existing notification boundary. This slice accepts only
an active tenant-local `webhook` endpoint; it never accepts a URL in the
search request or binding URI.

## Completion and race semantics

Only `completed` and `failed` searches enqueue a completion delivery. A caller
or deletion-driven `cancelled` search never does. Cancellation is caller or
privacy intent, not a service completion claim.

Registration locks the tenant-local search, confirms that the referenced
tenant-local webhook endpoint is active, and inserts the binding. Database
triggers call one narrow enqueue function:

- after a search first changes from `accepted`/`running` to
  `completed`/`failed`;
- after a binding is inserted for an already completed/failed search.

This makes the two possible races converge:

- a binding that commits first is visible to the terminal search update;
- a terminal update that commits first is visible to binding insertion.

The logical delivery key binds tenant, search, endpoint, and the closed
`search_completion` kind. A unique constraint and `ON CONFLICT DO NOTHING`
permit exactly one delivery. Enqueue writes lineage from the search and each
search target to the delivery plus a target-free audit event in the same
transaction.

If the endpoint was disabled after binding but before completion, enqueue
creates an explicit cancelled delivery rather than losing the terminal state.
Deleting the binding before completion suppresses enqueue. Deleting it after
queueing cancels queued, retry-scheduled, or leased state transactionally;
an outbound request already accepted by the remote endpoint cannot be
recalled. Delivered and permanently failed history remains immutable until an
applicable deletion workflow removes it.

## Stable payload and delivery behavior

The signed body is deliberately a wake-up signal:

```json
{
  "schema": "socialname.dev/api/v1",
  "delivery_id": "00000000-0000-0000-0000-000000000001",
  "search_id": "00000000-0000-0000-0000-000000000002",
  "outcome": "completed",
  "completed_at_unix_ms": 1785123456789
}
```

`outcome` is exactly `completed` or `failed`. The payload contains no username,
site, result, verdict, uncertainty detail, consent identifier, API-key
identifier, endpoint, idempotency digest, or destination. A receiver uses its
own authenticated `search:read` credential to poll the search. Shared
usernames do not imply ownership, and the webhook is not evidence of account
existence or absence.

The existing webhook worker owns destination decryption, public-only HTTPS
egress, HMAC signature headers, request/body limits, one-through-ten-attempt
fencing, exponential retry, endpoint-disable cancellation, permanent failure,
attempt audit, and request-body digest lineage. Transition and search
completion bodies are closed independent protocol shapes. Email claims never
select a search-completion delivery.

## Resource status and privacy

The binding resource returns:

- search and endpoint IDs;
- current search and binding states;
- binding creation/cancellation times;
- optional delivery ID, state, attempt count, queue/retry/delivery times, and
  closed last-error code.

It never returns the destination or search targets/results. Foreign,
deletion-hidden, and missing searches remain uniformly `not_found`. Forced
tenant RLS protects bindings and generalized delivery rows. The operational
watch/delivery report and monitoring timeline continue to select only
transition deliveries; Developer search service reporting remains independent
of webhook delivery outcomes.

Search and per-target lineage let the existing deletion traversal cancel and
remove matching delivery/attempt history, including a completion signal shared
by a multi-target search when any contributing target is withdrawn. A binding
row itself is target-free and has no public list surface; its single-resource
API inherits search hiding. Tenant deletion remains the controller-wide
removal boundary.

## Verification and external gates

Deterministic protocol tests pin exact request, resource, and webhook body
relations. Worker tests preserve transition payload compatibility,
webhook-only routing, signature/body binding, retry, stale fencing, and
cancellation. The integration transport captures and checks the exact minimal
search payload and successful signed worker path.

The PostgreSQL 18 gate must prove:

- exact and conflicting registration replay under `search:write`;
- read-scope separation and two-tenant hiding;
- registration-before-terminal and terminal-before-registration convergence;
- one delivery under repeated terminal updates;
- no delivery for cancelled searches;
- endpoint-disable and subscription-cancel behavior;
- transition monitoring/report cohorts remain unchanged;
- target-free payload, audit, resource, and lineage;
- real worker claim and signed success behavior while the shared delivery
  suite preserves retry and stale-fence behavior.

Production endpoint ownership, DNS/TLS operations, retained successful-delivery
evidence, alert ownership, hosted origin, and availability remain external
gates. Search webhooks do not create plan or billing entitlements.
