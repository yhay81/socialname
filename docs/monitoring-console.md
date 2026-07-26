# Minimal monitoring console

## Scope

The Milestone 2 console is a small operator-facing web client for the existing
monitoring loop. It lets an authenticated workspace:

- list bounded watch summaries;
- create a watch from an already provisioned consent grant and notification
  endpoint;
- pause or resume a watch with revision fencing;
- select one watch and inspect its account/measurement transition history;
- distinguish confirmation state from delivery state and retry/dead-letter
  outcomes.

Endpoint provisioning, destination verification, consent administration,
account login, billing, Team review workflow, and production hosting remain
outside this slice. The console cannot make a discovery-only rule eligible or
turn measurement failure into account change.

## Topcoat evaluation

The accepted architecture required evaluating Topcoat first at a replaceable
web boundary. On 2026-07-26 the current official
[Topcoat 0.4.0 documentation](https://docs.rs/topcoat/0.4.0/topcoat/) describes
the framework as early-stage and experimental. Its primary productivity model
allows server-rendered components to query a database directly, while
authentication, SSE, and OpenAPI support remain roadmap work.

That model is a poor fit for this milestone's existing Axum authentication,
versioned protocol DTO, transaction-local tenant, and forced-RLS boundaries.
The console therefore remains React/TypeScript/Vite as already recorded in the
architecture. Topcoat is rejected for this slice rather than introduced beside
Axum or allowed to read product tables. It may be re-evaluated after its API
stabilizes, but it must still consume the public API rather than become a
second authorization path.

## API boundary

The console uses only same-origin `/v1` JSON endpoints. Development uses a Vite
proxy to the loopback server; the SocialName server does not enable browser
CORS or serve a second unversioned data contract.

Two bounded read resources complete the existing single-watch API:

```text
GET /v1/watches?limit=50&after=<watch-id>
GET /v1/watches/{watch-id}/transitions?limit=50&after=<transition-id>
```

Pages are closed `socialname.dev/api/v1` DTOs with at most 50 items. A cursor is
the last opaque ID returned from the same tenant-scoped ordering; the server
loads the cursor under forced RLS and rejects malformed or foreign cursors as a
closed invalid request. It queries one extra row to determine whether a next
cursor exists.

Each transition entry carries the complete typed transition plus its
zero-or-more delivery resources. Transition support, confirmation, account
versus measurement class, logical delivery ID, attempt count, retry time,
delivered time, acknowledgement time, and bounded error code remain distinct.
The endpoint
destination, signing material, attempt body digest, worker label, audit
details, tenant ID, and database IDs not already in the public resources are
not returned.

`watch:read` protects both page routes. Existing `watch:write` protects create
and revisioned pause/resume operations. Reads begin a normal authorized
transaction, set the tenant locally, and execute through the non-owner runtime
role; the UI never receives database access.

## Browser credential and data policy

The first console has no app-owned authentication or refresh-token lifecycle.
An operator pastes an already issued scoped API key. It is held only in the
current JavaScript component/ref state:

- no URL, query string, local storage, session storage, IndexedDB, cookie,
  service worker, analytics, or console logging;
- every request uses `cache: "no-store"` and a relative URL;
- disconnect or page reload drops the key;
- error rendering uses only the closed API code/request ID and never reflects
  a request body or credential.

The production build assumes same-origin delivery behind an operator-selected
TLS and security-header boundary. A hosted domain, session authentication, CSP,
deployment credential, and external accessibility review are external gates,
not repository evidence.

## Presentation and accessibility

The initial viewport centers the monitored coverage rather than generic
navigation chrome. It presents:

- active/paused/deleting counts for loaded watch pages;
- account-change and measurement-health counts for the loaded selected
  timeline;
- delivered, acknowledged, retrying, and permanently failed counts for that
  loaded timeline;
- a keyboard-selectable watch list with target/site scope and next run;
- a chronological timeline whose visual language keeps account state,
  measurement health, confirmation, and delivery separate;
- a compact create form and revision-safe pause/resume action.

The labels explicitly say "loaded" because the API is paginated; the console
does not present a partial page as a workspace-wide total.

All actions have explicit labels, status does not rely on color alone, focus is
visible, motion respects `prefers-reduced-motion`, layouts collapse for narrow
screens, and timestamps use the browser locale while preserving exact machine
values in the API.

## Verification

Protocol tests lock the exact page JSON shape and cross-resource relations.
The real PostgreSQL 18 integration test proves:

- two-tenant isolation and `watch:read` scope enforcement;
- deterministic ordering, limits, and cursor continuation;
- account and measurement transitions remain separate;
- delivery state and bounded retry/dead-letter metadata are exposed without
  destination/body/signature/attempt-audit data.

The console runs deterministic model tests, TypeScript checking, and a
production Vite build. The PostgreSQL gate also proves delivered-only,
idempotent acknowledgement and private audit attribution. Browser automation,
deployed TLS/CSP, endpoint ownership, and production accessibility evidence
remain external gates.
