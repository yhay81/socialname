# Email delivery

## Scope and guarantee

Migration `0015_email_delivery.sql`, the managed worker, and the public
`EmailNotification` DTO add email as a second delivery channel for confirmed
transitions. Email and webhook endpoints are enqueued in the same transaction
that confirms a transition. Pending or suppressed transitions, including
shared-only absence, remain non-deliverable.

The database creates at most one logical email delivery for each
`(tenant, transition, endpoint)` tuple. Its channel-specific SHA-256 logical
key and stable delivery ID survive retries. Delivery is **at least once**, not
exactly once: a gateway can accept a message while the worker loses the
response. The gateway must deduplicate the `idempotency-key` delivery ID.

This slice delivers through a provider-neutral HTTPS gateway rather than
embedding a vendor SDK or SMTP credential in the worker. The gateway is an
operator-owned adapter to an approved mail provider. Provider account,
sending-domain, suppression, bounce, and complaint handling remain
deployment responsibilities.

## Stable notification and gateway request

`EmailNotification` is a bounded `socialname.dev/api/v1` object containing the
stable delivery ID and complete typed confirmed transition. It repeats the
confirmation admission check. The worker derives a plain-text message from
that object and sends this closed JSON shape:

```json
{
  "schema": "socialname.dev/email-gateway/v1",
  "delivery_id": "opaque-stable-delivery-id",
  "from": "alerts@socialname.example",
  "to": "recipient@example.com",
  "subject": "SocialName account state changed",
  "text": "SocialName observed a time- and vantage-specific ..."
}
```

The subject is one of:

- `SocialName account state changed`;
- `SocialName measurement health changed`.

The text contains only the target, site, typed change, observation time,
stable delivery ID, and measurement region when applicable. It explicitly
states that an account result is time- and vantage-specific, that matching
usernames do not prove common ownership, and that measurement degradation is
not an account-state change. It does not include supporting observation IDs,
raw evidence, response bodies, cookies, credentials, or unrelated profile
data. There is no HTML alternative or tracking pixel.

Every gateway POST has:

| Header | Meaning |
| --- | --- |
| `content-type` | `application/json` |
| `authorization` | Operator-supplied bearer credential |
| `socialname-email-id` | Stable logical delivery ID |
| `socialname-email-attempt` | One-based fenced attempt |
| `idempotency-key` | The same stable delivery ID for gateway deduplication |

The complete request body is limited to 32 KiB. Retries reuse the same body
and delivery ID; only the attempt header changes.

## Confidentiality and outbound safety

Email destinations have no plaintext database column. Provisioning seals the
address with XChaCha20-Poly1305. Associated data uses the distinct
`socialname/email-destination/v1` domain and binds tenant ID, endpoint ID, and
encryption-key ID. Email ciphertext therefore cannot be replayed as a webhook
destination or moved between endpoints.

The gateway URL, bearer credential, sender, decrypted recipient, and request
body are redacted from `Debug`, errors, ordinary output, audit, attempt
history, and lineage. Secret-owned strings and request bytes are zeroized on
drop. Completed attempts persist only the SHA-256 digest of the canonical
`EmailNotification`, status/error class, bounded worker label, and time.
Neither the recipient-bearing gateway body nor any response body is stored.

The managed gateway client:

- accepts only HTTPS without credentials or fragments;
- disables environment proxies, redirects, and response decompression;
- revalidates every connection through the public-only DNS policy, rejecting
  private, loopback, link-local, metadata, multicast, documentation,
  transition, mixed, empty, and oversized answer sets;
- bounds connection establishment to two seconds, the complete request to at
  most 30 seconds, headers to 16 KiB, and the body to 32 KiB;
- observes only the response status and discards the response body.

These controls keep redirects, DNS rebinding, private-network SSRF, response
content, and ambient proxy credentials outside the delivery capability.

## Claims, retry, and dead letter

The non-owner `NOBYPASSRLS` email worker claims one due email only through
`socialname_worker_claim_email_delivery`, then returns to tenant-local forced
RLS. The email and webhook coordinators filter different endpoint channels.
An endpoint's channel is immutable after creation, preventing ciphertext or
queued work from being reinterpreted under the other channel.
A claim increments the attempt and holds a one-to-30-second lease. Completion
must match delivery, channel, attempt, worker, and unexpired lease.

`408`, `425`, `429`, `5xx`, timeout, connection failure, and other transport
failure retry. Other statuses and rejected destinations/requests fail
permanently. Exponential backoff starts at five seconds and is capped at
15 minutes; the operator chooses one through ten attempts. An inactive
endpoint is cancelled and an expired final lease is dead-lettered.

Claim, lease-expiry, completion, retry, permanent-failure, and cancellation
events are append-only. `confirmed_email` and `email_attempt` lineage keep the
channel ancestry distinct from `confirmed_webhook` and `webhook_attempt`.

## Operator entry point

Run email delivery as a separate workload from managed probing and webhook
delivery. It needs the non-owner worker database credential, one endpoint
encryption key, and gateway-specific values:

```powershell
$env:SOCIALNAME_WORKER_DATABASE_URL = "postgres://WORKER:SECRET@HOST:5432/DB"
$env:SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_ID = "endpoint-key-1"
$env:SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_HEX = "<64 lowercase hex characters>"
$env:SOCIALNAME_EMAIL_GATEWAY_URL = "https://approved-gateway.example/v1/send"
$env:SOCIALNAME_EMAIL_GATEWAY_TOKEN = "<secret from the platform secret store>"
$env:SOCIALNAME_EMAIL_FROM = "alerts@socialname.example"

cargo run --locked -p socialname-worker -- deliver-email-one `
  --worker-id email-worker `
  --lease-seconds 15 `
  --maximum-attempts 5 `
  --request-timeout-seconds 10 `
  --allow-live
```

The timeout must be shorter than the lease. One invocation claims at most one
email and sends at most one request. Output contains only status, opaque
delivery ID, and attempt.

Do not share the webhook signing key with this workload. Supply secrets from
the deployment secret store, not an image, repository, command line, or log.
The current worker accepts one active destination-encryption key; rotate by
re-encrypting active endpoints before retiring it.

## Verification and external gate

Unit and real PostgreSQL 18 tests prove:

- confirmed-only DTO construction and exact protocol/schema roots;
- channel-specific envelope and logical-key domains;
- gateway URL, token, body, and debug redaction;
- public-only outbound policy and closed request bounds;
- separate email/webhook claim selection;
- timeout then success with identical delivery ID and body;
- permanent 4xx behavior;
- append-only attempts, audit, and complete `email_attempt` lineage;
- absence of recipient, gateway token, and body material from persisted
  operational metadata.

The repository test uses an injected transport and does not claim external
delivery. Keep production email disabled until an operator has:

1. verified endpoint ownership through an approved administration process;
2. configured and verified the sending domain;
3. deployed an approved gateway adapter with stable ID deduplication;
4. exercised bounce, complaint, unsubscribe, rate-limit, retry, and incident
   handling without sensitive log content; and
5. retained a controlled end-to-end delivery result for the reviewed source
   revision and configuration.
