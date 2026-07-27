# Private search history and export

## Purpose and boundary

The Developer API keeps managed searches useful after the caller loses an
in-memory search ID. It exposes a tenant-local history index and a portable,
bounded projection of one terminal search:

```http
GET /v1/searches
GET /v1/searches/{search_id}/export
```

History requires `search:read`. Export independently requires `data:export`.
Neither scope substitutes for the other, for purpose-specific consent, or for
`evidence:read`. The existing `GET /v1/searches/{search_id}` and SSE operations
remain unchanged.

## History semantics

`SearchHistoryPage` contains at most 50 complete `SearchResource` values,
ordered by immutable `(created_at, search_id)` descending. The default page is
20. A continuation cursor is the last returned search UUID and is accepted
only when it still names a visible search in the authenticated tenant.

This is a live history view, not a frozen snapshot: an accepted or running
resource can advance while a caller pages. Its ordering key does not change.
Malformed, foreign-tenant, unknown, or deletion-hidden cursors are
`invalid_request`; they never broaden the query or echo a supplied value.

## Export semantics

`SearchExportPage` is a `socialname.dev/search-export/v1` document containing:

- the complete terminal `SearchResource`;
- an ascending page of at most 50 validated `SearchEvent` values;
- the immutable total event count;
- an explicit completion flag;
- an Event ID continuation cursor when more data remains.

Export is refused with `conflict` while a search is accepted or running. A
terminal search has a `started` event, exactly one matching `finished` event,
and no later application event. This makes Event ID pagination stable without
creating a second payload store or snapshot lifecycle.

The closed search request allows at most 512 target pairs. One target produces
at most one result and one assertion update, so an export fails closed above
1,026 total events (`started` + 512 results + 512 assertion updates +
`finished`). Event payloads retain their existing 128 KiB database bound.
Consumers stream pages rather than accumulating the worst case in memory.

The export contains requested usernames, public profile URLs when present,
observation IDs, evidence digests, provenance, uncertainty, and operational
failures. It does not add HTTP bodies, credentials, cookies, arbitrary headers,
or a new Evidence Capsule slot. A caller with `evidence:read` can separately
retrieve an unexpired Capsule by an exported observation ID.

## Privacy, deletion, and isolation

Both operations authenticate before their own forced-RLS transaction. A
foreign search is indistinguishable from a missing search. The history index
and export preflight reject a search when any of its targets or events has a
lineage-backed deletion tombstone. Export queries therefore cannot reconstruct
a partially hidden target from the remaining event set.

The export is a stateless response projection. SocialName does not persist a
duplicate export body or create a new retention clock. A caller that stores the
response becomes responsible for protecting and deleting that copy. Product
deletion, Evidence Capsule expiry, and consent withdrawal continue to govern
the source rows.

Migration `0019_search_history_export.sql` adds only the tenant/creation-time
history index. It creates no table or RLS policy and grants no new database
privilege; the application role already had the narrow reads needed for search
polling and SSE.

## Adoption examples and SDK decision

[`examples/api-v1`](../examples/api-v1/README.md) contains dependency-free
Node.js 24 examples for:

- idempotent creation plus strict resumable SSE;
- complete history traversal plus terminal export traversal.

Keys come only from the environment and request/selection input comes from
stdin, avoiding bearer or target values in argv and ordinary shell history.
The examples enforce HTTPS except for loopback HTTP, refuse redirects, bound
JSON and SSE frames, validate schema/search/event identity, deduplicate replay,
and never include untrusted response bodies in errors. Their deterministic
tests run in the Quality workflow.

No generated SDK is committed in this slice. OpenAPI already supports
exploratory generation, while there is no hosted origin, package-distribution
decision, compatibility telemetry, or observed language-specific friction to
justify a maintained generated package. The examples cover the behavior that
generic REST generation does not: SSE resumption, secret placement, and
bounded export pagination.

## Verification and remaining gates

Protocol tests cover cursor binding, terminal-state matching, strict sequence
order, event identity, bounds, and exact wire shape. Router tests bind both new
operations to their published scopes. The PostgreSQL 18 gate covers stable
history pagination, independent `search:read`/`data:export` authorization,
pre-terminal conflict, full Event ID traversal, invalid and foreign cursors,
tenant hiding, and deletion-tombstone exclusion.

The committed OpenAPI, JSON Schemas, and digest manifest include both
operations. Hosted availability, production export handling, package
distribution, and observed adoption measurements remain external evidence;
the repository does not claim them.
