# Lineage-backed deletion workflows

This boundary implements the repository-completable contributor-deletion and
verified target-person request slice. It deliberately stops after current
PostgreSQL support withdrawal, assertion recomputation, and primary deletion.
Analytics rebuild completion, deletion receipts, restore-ledger replay,
backup-expiry proof, daily drills, and production scheduling remain the next
ordered roadmap item.

## Guarantees and deadlines

Every software-created request uses one database timestamp and the exact
accepted deadlines:

| Phase | Deadline | Current behavior |
| --- | ---: | --- |
| Hide | 5 minutes | Completed in the creation transaction |
| Withdraw support | 1 hour | Performed by the deletion worker |
| Delete primary data | 24 hours | Performed atomically with support withdrawal and recomputation |
| Rebuild derived stores | 7 days | Task is durable but not completed by this slice |
| Expire backups | 35 days | Task is durable but not completed by this slice |

Creation writes immutable lineage tombstones before returning. Product reads
exclude matched observations, Evidence Capsules, search events, assertions,
transitions, and deliveries immediately, even while physical rows still
exist. Active matched probe jobs, search targets, and notification deliveries
are cancelled and their target-bearing job/search fields are replaced with
opaque `deleted-target-<uuid>` markers.

The public request resource exposes only IDs, scope, state, deadlines, matched
counts, and completion timestamps. It never returns a contributor selector,
username, verification reference, HMAC, or tenant-global target list.

## Contributor API

An authenticated contributor creates a request with:

```http
POST /v1/deletion-requests/contributor
Authorization: Bearer <key with data:delete>
Content-Type: application/json

{
  "schema": "socialname.dev/api/v1",
  "consent_grant_id": "<owned account or installation grant>"
}
```

The server accepts only a grant owned by the active membership: an account
grant for that membership, or an installation grant whose immutable grant
event names that membership as the original actor. The selected grant defines
the contributor subject and purpose. In one tenant-RLS transaction the server:

1. serializes the subject/purpose selector with a transaction advisory lock;
2. returns the existing request for an exact replay;
3. revokes every still-active grant for the same subject and purpose and
   appends immutable withdrawal events;
4. selects all observations carrying those grants and traverses generic
   lineage to their downstream resources;
5. materializes immutable `deletion_resource_matches` tombstones;
6. hides reads and cancels/redacts active jobs, targets, and deliveries;
7. creates primary, analytics, and backup tasks; and
8. stores only a three-year contributor-reingestion suppression token.

`201 Created` identifies a new request and `200 OK` an exact replay. Both
include a `Location` header. Only the creating membership can read it:

```http
GET /v1/deletion-requests/{deletion_request_id}
Authorization: Bearer <same owner's key with data:delete>
```

Foreign tenants and other memberships receive `not_found`. A key without the
exact scope receives `forbidden`. Once contributor suppression is active, a
new grant for that subject and purpose receives `conflict` rather than
silently allowing reingestion.

## Verified target-person operator

Target-person requests are not accepted from a self-asserted public HTTP
body. Identity or control verification and alias resolution occur outside
SocialName's normal request logs. An authorized operator then supplies a
bounded, already-verified case through stdin:

```powershell
$env:SOCIALNAME_DATABASE_URL = "postgres://SCHEMA_OWNER:...@HOST/DATABASE"
$env:SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX = "<64 lowercase hex characters>"
$env:SOCIALNAME_TARGET_DELETION_VERIFIED = "true"
@'
{
  "schema": "socialname.dev/verified-target-deletion/v1",
  "verification_reference": "opaque-case-reference",
  "selectors": [
    {
      "site_id": "github",
      "normalized_username": "verified-alias"
    }
  ]
}
'@ | cargo run --locked -p socialname-server -- request-target-deletion
```

The input is capped at 32 KiB and 64 deduplicated canonical
`(site_id, normalized_username)` selectors. The case-management layer must
include every verified alias in that selector set. The raw verification
reference and selectors are never stored in a deletion request. PostgreSQL
retains only a SHA-256 verification-reference digest, tenant-separated HMAC
selector identities, request/group IDs, deadlines, counts, and payload-free
audit details.

The transaction renews target-reingestion suppression in every current tenant
and creates one grouped request per tenant that has an exact matching
**shared** observation. Private tenant observations are intentionally retained:
they may have another controller, contract, legal basis, or hold and require
explicit routing outside this shared-pool command. Output reports only group
and request IDs plus counts. Repeating the selector set returns the same group
and request IDs, including after primary rows have been deleted. A selector
with no current shared observation still creates suppression so a later
shared job cannot reintroduce it.

## Suppression before network access

`SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX` is a 256-bit secret shared by the HTTP
server, target operator, and managed job worker. HMAC inputs are
length-framed and domain-separated by tenant, purpose, and selector. The
database stores only a 32-byte token and a nonsecret key fingerprint.

The key must remain stable for the lifetime of every unexpired token and be
protected and restored as deletion-control state. A legacy token or active
token from another key fingerprint makes the affected operation fail closed:

- contributor grant creation and contributor deletion return `unavailable`;
- the target operator refuses the transaction; and
- shared managed execution reports authorization unavailable and sends no
  network request.

This prevents an accidental secret replacement from silently disabling prior
suppression. Rotation requires a separately reviewed multi-key migration
before changing the configured value; this slice does not claim online key
rotation.

The managed worker checks exact target suppression before starting a shared
request, every 250 milliseconds while it is in flight, and again under the
ingestion transaction lock. Private jobs do not use target-person suppression.
When suppression wins a race with a live shared search, the worker:

- drops the network future;
- creates no observation;
- replaces the search/job target and work hash with opaque markers;
- records a nonretryable `blocked` operational event containing only the
  marker; and
- completes the search stream instead of leaving it pending.

## Primary deletion worker

An operator runs one bounded fenced unit with the non-owner worker role:

```powershell
$env:SOCIALNAME_WORKER_DATABASE_URL = "postgres://WORKER:...@HOST/DATABASE"
cargo run --locked -p socialname-worker -- process-deletion `
  --worker-id deletion-worker-1 `
  --lease-seconds 60 `
  --allow-live
```

The lease is 5–300 whole seconds. A fixed-search-path
`SECURITY DEFINER` coordinator claims at most one due request and returns only
tenant/request IDs and an incremented attempt fence. The runtime role then
sets transaction-local tenant RLS and atomically:

1. validates the current lease fence;
2. marks all selected resources support-withdrawn;
3. removes assertion, regional-assertion, and transition support;
4. withdraws selected current assertions and clears affected watch baselines;
5. recomputes each exact target/rule from remaining nondeleted observations;
6. removes matched delivery attempts/deliveries, transitions, assertions,
   Evidence Capsules and retention receipts, search events, observations, and
   selected lineage;
7. replaces watch-run observation references with deletion tombstones;
8. marks primary tasks complete and the request `rebuilding`; and
9. appends a target-free audit event.

The deletion transaction is all-or-nothing. A stale lease cannot mutate data,
and replay after commit returns idle rather than duplicating work. Probe-job,
search-target, request, task, match, suppression, and audit rows remain as
payload-free or target-redacted operational receipts; they preserve replay,
deadline, and withdrawal lineage without retaining the deleted identifier.

## Least privilege and failure behavior

Migration `0012_lineage_backed_deletion.sql` adds the match tombstone table,
ordered state/deadline/progress constraints, target-redaction coordinator, and
cross-tenant deletion claim coordinator. `PUBLIC` execution is revoked.

The application role can create and inspect only tenant-local contributor
requests and call the exact redaction function. The worker remains
`LOGIN NOSUPERUSER NOBYPASSRLS`; it receives column-limited updates and delete
rights only for the primary resources exercised by the PostgreSQL integration
fixture. It cannot read API credentials or bypass tenant policies. The target
operator uses the explicit schema-owner URL because it must apply a verified
shared-pool request across tenants; it is not part of the HTTP runtime.

Database/configuration errors do not convert to `not_found`, an account
verdict, or a false completion receipt. A failed primary transaction retains
its durable request/tasks and lease-expiry retry path. Analytics and backup
tasks remain pending, so the public state remains `rebuilding` and this slice
does not claim the 7-day or 35-day external gates.

## Verification

The real PostgreSQL 18 integration test uses separate owner, application, and
worker credentials and proves:

- exact deadline relations, immutable identity, monotonic progress, and
  tenant/owner scope denial;
- immediate physical-row hiding and active-delivery/job cancellation;
- exact contributor replay, grant withdrawal, and future-consent suppression;
- fail-closed key-fingerprint mismatch behavior;
- support removal, remaining-support recomputation, sole-support withdrawal,
  primary purge, and idempotent worker replay;
- target-group replay before and after physical purge;
- shared target deletion while an identical private observation remains;
- future-target suppression before network execution, target/work-hash
  redaction, zero observation writes, a redacted `blocked` event, and a
  terminal search; and
- restricted runtime privileges and forced-RLS isolation.

No test claims external identity verification, legal disposition of private
tenant data, production scheduling, analytics rebuild, recipient
notification, deletion-receipt completion, restore-ledger replay, or encrypted
backup expiry.
