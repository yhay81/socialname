# SocialName

SocialName is being rebuilt as a Rust-based public-identifier observability
platform. The first implementation slice provides a private local CLI, one
shared probe/classification engine, a strict Site Rule v1 compiler, and
explainable assertion derivation.

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

- Rust workspace with domain, schema, compiler, engine, application core, CLI,
  desktop, and testkit crates.
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
- Assertion v1 trust thresholds for managed and opt-in shared observations.
- Ten representative site rules and 30 minimized offline fixture cases.
- Discovery-only quarantine for rules that are not yet live-canary qualified.
- Tauri 2 desktop application for Windows and macOS with explicit research
  consent, site selection, streaming evidence, and cancellation.

The central server, SQLite cache, signed rule-pack publication, managed
canaries, and monitoring pipeline are the next implementation slices.

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

All representative rules remain `discovery` until the managed multi-region
live-canary gate exists. They are blocked from live execution unless
`--allow-disabled` is supplied deliberately.

## Workspace

```text
crates/
  socialname-app-core/       UI-independent local search orchestration
  socialname-canary/         typed canary manifests and strict validation
  socialname-domain/         observations and assertion/v1 derivation
  socialname-rule-schema/    strict Site Rule v1 source types
  socialname-rule-compiler/  validation and canonical compilation
  socialname-engine/         HTTP probing and deterministic classification
  socialname-cli/            local command-line entry point
  socialname-testkit/        offline fixture verification
apps/
  desktop/                   Tauri 2 + React application for Windows and macOS
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
The desktop boundary and platform policy are recorded in
[Desktop application](docs/desktop-application.md).

## Legacy implementation

The existing Python package under `socialname/` remains only as a migration and
behavioral reference while v2 is built. New implementation work belongs in the
Rust workspace.
