# SocialName

SocialName is being rebuilt as a Rust-based public-identifier observability
platform. The current implementation provides private local clients, one
shared probe/classification engine, strict rule and trust artifacts, a local
cache, authenticated managed search persistence, and a signed worker connected
through fenced PostgreSQL jobs and atomic observation ingestion, plus a
same-origin monitoring console over the versioned API.

> Turn public-identifier presence and change into fast, continuous,
> evidence-backed, privacy-respecting, actionable knowledge.

Read the authoritative [ultimate goal](docs/ultimate-goal.md) and the active
[execution roadmap](ROADMAP.md) before planning new work.

The product direction is:

- local-first, fast CLI searches;
- a developer API using exactly the same engine and rule pack;
- paid continuous monitoring, history, and notifications;
- an opt-in central quality network that distinguishes verified,
  corroborated, conflicted, stale, and blocked results.

A matching username across sites is not proof that the accounts belong to one
person.

## Implemented

- Rust workspace with domain, schema, compiler, engine, cache, application,
  protocol, server, worker, CLI, desktop, and testkit crates.
- Deterministic `found`, `not_found`, `inconclusive`, and conflict
  classification with matcher traces and evidence digests.
- Context-safe path, query, and subdomain URL templates.
- HTTPS and per-rule host allowlists, bounded redirects, timeouts, and body
  inspection.
- Canonical JSON rule compilation and deterministic SHA-256 rule-pack hashes.
- Independent typed canary manifests with review, expiry, policy compatibility,
  and deterministic content hashes.
- A cancellable production-engine canary runner with preflight request,
  concurrency, wall-time, and inspected-byte budgets.
- Content-addressed Canary Report v1 output with rational precision/coverage,
  latency and response-class metrics, expiry, duplicate detection, and strict
  ingestion-policy validation.
- Canary Aggregate v1 with an exact 24-hour window and per-region run count,
  precision, coverage, conflict, and p95-latency gates.
- Canary Shadow v1 paired execution against last-known-good rules with one
  combined budget and typed precision, coverage, conflict, and case regression
  rejection.
- Regional rule-health state transitions with quarantined initialization,
  evidence-bound recovery, operational degradation, immediate drift
  quarantine, and account-notification suppression.
- Ed25519 regional rule promotions with exact pack/predecessor/evidence
  binding, expiry, sequence replay protection, last-known-good retention, and
  rollback.
- Threshold-signed rule-pack metadata with exact embedded site promotions,
  canary/regional/general rollout, 24-hour expiry, durable replay floors,
  staged trust rotation, and signed retained-pack rollback.
- Assertion v1 trust thresholds for managed and opt-in shared observations.
- A user-owned SQLite cache with freshness/source policy, pruning, export,
  migration, quarantine, and deletion.
- An Axum/PostgreSQL server with private workspaces, hashed scoped API keys,
  consent-bound idempotent searches, polling/cancellation, and ordered
  resumable SSE under forced tenant RLS.
- Purpose/profile/notice-versioned account and installation consent resources
  with bounded reads, installation non-override, and immutable immediate
  withdrawal.
- A closed 64 KiB `evidence-capsule/v1` stored atomically with managed
  observations, scoped inspection, database-time visibility deadlines,
  bounded irreversible purge, and payload-free retention receipts.
- Owner-authorized contributor deletion and externally verified target-person
  workflows with immediate lineage-backed hiding, HMAC-only future
  suppression, remaining-support recomputation, primary purge, and explicit
  private-target routing.
- A signed-metadata-only managed worker with per-connection DNS validation,
  DNS-rebinding/SSRF rejection, independent response byte limits,
  cancellation, and a live-acknowledged stdin-only one-shot probe.
- Consent/visibility-isolated managed job expansion, `SKIP LOCKED` claims,
  attempt fencing, bounded retry, continuous authorization checks, and
  idempotent observation/event/lineage ingestion under forced tenant RLS.
- Revisioned watch scheduling, assertion/transition recomputation, signed
  deduplicated webhook delivery, provider-neutral HTTPS email delivery, and
  bounded retry/dead-letter audit lineage.
- A React/TypeScript/Vite monitoring console using tenant-RLS watch and
  transition/delivery pages plus a target-free operational report without
  direct database access or browser key persistence.
- Database-time 24-hour, 7-day, and 30-day operational reporting with an
  independent scope, current backlog, explicit no-data state,
  channel-separated delivery success/latency, and deletion deadline health.
- Ten representative site rules and 30 minimized offline fixture cases.
- Discovery-only quarantine for rules that are not yet live-canary qualified.
- Tauri 2 desktop application for Windows and macOS with explicit research
  consent, site selection, streaming evidence, and cancellation.

Milestone 3's repository-completable software is now implemented. Real
regional deployment, retained production SLO history, and production
notification evidence remain external gates. The next ordered repository
slice publishes the stable versioned REST/JSON and SSE contracts for
Milestone 4 without changing the local-first engine semantics.

## Build and verify

Rust stable is pinned through `rust-toolchain.toml`.

```console
cargo build --workspace --exclude socialname-desktop
cargo test --workspace --exclude socialname-desktop --all-targets
cargo clippy --workspace --exclude socialname-desktop --all-targets --all-features -- -D warnings
```

Validate the complete rule pack and its deterministic fixtures:

```console
cargo run -p socialname-cli -- rules validate
cargo run -p socialname-cli -- rules list --all
cargo run -p socialname-cli -- canaries validate
cargo run -p socialname-cli -- fixtures
```

Run an explicitly local live probe:

```console
cargo run -p socialname-cli -- search github --site github --allow-disabled --json
```

Run the desktop application (Node.js 24 and the native Tauri prerequisites are
required):

```console
cd apps/desktop
npm ci
npm run tauri -- dev
```

Windows and macOS CI compile the complete native desktop target separately.

Run the local monitoring console against the loopback server (Node.js 24):

```console
cd apps/console
npm ci
npm run dev
```

The Vite development server proxies relative `/v1` requests to
`127.0.0.1:8080`; production hosting, TLS, CSP, and session authentication are
not claimed by the repository build.

All representative rules remain `discovery` until the external managed
multi-region live-canary gate passes. Local probing requires the deliberate
`--allow-disabled` override; the managed worker has no equivalent bypass and
requires valid threshold-signed pack metadata containing the site promotion.

## Workspace

```text
crates/
  socialname-app-core/       UI-independent local search orchestration
  socialname-cache/          user-owned SQLite observations and freshness
  socialname-canary/         typed canary manifests and strict validation
  socialname-domain/         observations and assertion/v1 derivation
  socialname-rule-schema/    strict Site Rule v1 source types
  socialname-rule-compiler/  validation and canonical compilation
  socialname-engine/         HTTP probing and deterministic classification
  socialname-protocol/       versioned REST, SSE, watch, deletion, delivery DTOs
  socialname-server/         authenticated Axum/PostgreSQL managed boundary
  socialname-worker/         signed-only managed probe boundary
  socialname-cli/            local command-line entry point
  socialname-testkit/        offline fixture verification
apps/
  desktop/                   Tauri 2 + React application for Windows and macOS
  console/                   same-origin React/Vite monitoring console
rules/
  sites/                     one reviewed YAML rule per site
  canaries/                  time-bounded reviewed controls (currently empty)
  fixtures/                  minimized deterministic response cases
docs/                        product, architecture, trust, and governance records
```

Start with the [ultimate goal](docs/ultimate-goal.md), the
[execution roadmap](ROADMAP.md), the [design index](docs/README.md), the
[accepted decisions](docs/decisions-2026-07-24.md), and the
[Site Rule v1 validation record](docs/site-rule-v1-validation.md).
The managed update trust and rollout contract is in
[Signed Rule-Pack Distribution v1](docs/rule-pack-distribution-v1.md).
The desktop boundary and platform policy are recorded in
[Desktop application](docs/desktop-application.md). The web monitoring
boundary is recorded in [Minimal monitoring console](docs/monitoring-console.md).

## Legacy implementation

The existing Python package under `socialname/` remains only as a migration and
behavioral reference while v2 is built. New implementation work belongs in the
Rust workspace.
