# Signed webhook delivery

## Scope and delivery guarantee

Migration `0007_webhook_delivery.sql`, the managed worker, and the public
`WebhookNotification` DTO connect confirmed transitions to an auditable
webhook attempt. A transition is enqueued in the same tenant transaction that
confirms it. Pending or suppressed transitions, including shared-only absence,
cannot cross this boundary.

The database guarantees one logical delivery for each
`(tenant, transition, endpoint)` tuple. Its SHA-256 logical key is unique and
the stable delivery ID is reused across attempts. HTTP delivery is necessarily
**at least once**, not exactly once: a receiver can accept a request while the
worker loses the response. Receivers must therefore deduplicate on
`socialname-webhook-id`. SocialName does not create a second logical delivery
to hide an ambiguous attempt.

## Payload and signature

The bounded JSON body is `socialname.dev/api/v1` `WebhookNotification`:

```json
{
  "schema": "socialname.dev/api/v1",
  "delivery_id": "opaque-stable-delivery-id",
  "transition": {
    "schema": "socialname.dev/api/v1",
    "transition_id": "opaque-transition-id",
    "watch_id": "opaque-watch-id",
    "target": {
      "username": "alice",
      "site_id": "github"
    },
    "change": {
      "class": "account_state",
      "from": "not_found",
      "to": "found"
    },
    "confirmation": {
      "status": "confirmed",
      "basis": "closed-confirmation-basis"
    },
    "supporting_observation_ids": ["opaque-observation-id"],
    "detected_at_unix_ms": 1000
  }
}
```

Measurement-health notifications use the alternate closed `change` variant
from [Public protocol v1](protocol-v1.md). The serialized body is limited to
32 KiB.

Each POST has these headers:

| Header | Meaning |
| --- | --- |
| `content-type` | `application/json` |
| `socialname-webhook-id` | Stable delivery ID used for receiver deduplication |
| `socialname-webhook-timestamp` | Unix time in milliseconds |
| `socialname-webhook-signature` | `v1=` plus lowercase HMAC-SHA-256 |
| `socialname-webhook-signing-key` | Closed signing-key identifier |
| `socialname-webhook-attempt` | One-based fenced attempt number |

The v1 MAC input is the exact byte concatenation
`timestamp + "." + delivery_id + "." + body`. Receivers should select the
configured secret by signing-key ID, recompute the HMAC over the raw request
body, compare in constant time, reject stale timestamps according to their
local replay policy, and then deduplicate the delivery ID.

## Destination confidentiality and outbound safety

Webhook destinations have no plaintext database column. Provisioning seals an
HTTPS URL with XChaCha20-Poly1305 using this versioned envelope:

```text
1-byte version || 24-byte nonce || ciphertext || 16-byte authentication tag
```

Associated data binds the envelope to its tenant ID, endpoint ID, and
encryption-key ID. Moving ciphertext between endpoints or changing the key ID
therefore fails authentication. Secret key bytes and decrypted destinations
are zeroized on drop where the worker owns them; `Debug`, errors, attempt
history, audit details, and standard output do not expose destinations,
signatures, request bodies, tenant IDs, or targets.

The outbound client:

- accepts only HTTPS URLs without credentials or fragments;
- disables environment proxies, redirects, and response decompression;
- resolves every connection through the managed DNS policy and rejects empty,
  oversized, mixed public/private, loopback, link-local, metadata, multicast,
  documentation, transition, and reserved address sets;
- bounds connection establishment to two seconds, the complete request to at
  most 30 seconds, request headers to 16 KiB, and the request body to 32 KiB;
- records only the HTTP status and discards the response body.

This keeps DNS rebinding and redirect-based SSRF outside the delivery
capability. Verification of destination ownership is separate from URL syntax
and network safety.

## Claims, retries, and dead letter

The non-owner `NOBYPASSRLS` worker claims one due webhook through the narrow
`socialname_worker_claim_webhook_delivery` coordinator, then returns to
transaction-local forced tenant RLS. A claim increments the attempt number and
holds a one-to-30-second lease. Completion must match the exact delivery,
attempt, worker, and unexpired lease; stale workers cannot commit.

`408`, `425`, `429`, `5xx`, timeout, connection failure, and other transport
failure retry. Other HTTP responses and invalid/rejected destinations or
requests fail permanently. Retry delay is bounded exponential backoff starting
at five seconds and capped at 15 minutes. The operator selects one through ten
maximum attempts. An expired final lease moves the delivery to
`permanently_failed`; an inactive endpoint moves it to `cancelled`.

Every claim, lease expiry, completion, retry, permanent failure, and
cancellation has append-only attempt history. Completed attempts store only a
SHA-256 digest of the body, a bounded status/error classification, the worker
label, and time. Delivery-to-attempt and transition-to-delivery lineage plus
closed audit actions make retry and withdrawal ancestry explicit.

## Operator boundary

The one-delivery command requires the worker database credential, two
independent 32-byte lowercase-hex keys, closed key IDs, and explicit live
acknowledgement:

```powershell
$env:SOCIALNAME_WORKER_DATABASE_URL = "postgres://WORKER:SECRET@HOST:5432/DB"
$env:SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_ID = "endpoint-key-1"
$env:SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_HEX = "<64 lowercase hex characters>"
$env:SOCIALNAME_WEBHOOK_SIGNING_KEY_ID = "signing-key-1"
$env:SOCIALNAME_WEBHOOK_SIGNING_KEY_HEX = "<64 lowercase hex characters>"

cargo run --locked -p socialname-worker -- deliver-one `
  --worker-id webhook-worker `
  --lease-seconds 15 `
  --maximum-attempts 5 `
  --request-timeout-seconds 10 `
  --allow-live
```

The request timeout must be shorter than the lease. One invocation claims at
most one delivery and sends at most one request. Its output is a target-free
status with only the delivery ID and attempt number when work occurred.

The current worker loads one active destination-encryption key and one signing
key. Rotation therefore requires re-encrypting active endpoints before
retiring the old destination key, while receiver trust can overlap old and new
signing-key IDs operationally. An endpoint administration/verification route
and production key-management integration are intentionally absent. Until an
operator provisions an encrypted, verified active endpoint and supplies both
keys, webhook delivery remains safely disabled. External ownership
verification and production delivery evidence remain Milestone 2 external
gates.

## Verification

Deterministic unit tests cover payload admission, envelope binding and
redaction, signature input, logical deduplication, retry classification, and
managed outbound destination rejection. The PostgreSQL 18 integration test
uses a real non-owner worker and injected bounded transport to prove:

- managed observation through confirmed transition and one logical enqueue;
- timeout followed by success with the same delivery ID and body;
- permanent HTTP 4xx handling;
- lease expiry, reclamation, and stale-worker fencing;
- final lease-expiry dead letter;
- append-only attempts, audit, and complete lineage;
- absence of destination and body material from attempt and audit records.

The test does not claim that an external receiver is owned, reachable, or
correctly verifies signatures.
