# Contributing to SocialName

Thank you for helping improve SocialName. The active product is the Rust
workspace, desktop application, monitoring console, and typed site-rule pack.
The Python package under `socialname/` is retained as a legacy reference and
is not the implementation foundation for new product work.

## Start with the product contract

Before proposing product or implementation work, read these in order:

1. [`docs/ultimate-goal.md`](docs/ultimate-goal.md)
2. [`ROADMAP.md`](ROADMAP.md)
3. the dated records under `docs/decisions-*.md`
4. the focused design document for the area you want to change

Open an issue before a broad product, protocol, trust, privacy, retention, or
roadmap change. Small fixes with an obvious contract can go directly to a pull
request.

Do not open a public issue for a suspected vulnerability. Follow
[`SECURITY.md`](SECURITY.md) instead.

## Privacy and safety

- Do not put private usernames, credentials, cookies, complete HTTP bodies, or
  unrelated profile data in issues, fixtures, logs, screenshots, or commits.
- Keep `found`, `not_found`, operational failure, and uncertainty distinct.
- Do not infer common ownership from matching usernames.
- Do not bypass authentication, CAPTCHA, paywalls, robots protections, or
  third-party access controls.
- Keep new site rules declarative, typed, bounded, and disabled until their
  documented live evidence gate passes.
- Never claim credentials, signing, deployment, regional behavior, or
  production validation that repository tests cannot prove.

## Development setup

Use the pinned Rust stable toolchain. The desktop and console use Node.js 24
and the checked-in npm lockfiles. On Windows, use PowerShell 7 and the MSVC
toolchain. PostgreSQL integration tests require the explicit test URLs
documented by the test output; ordinary unit tests remain offline.

Common entry points:

```console
cargo build --locked --workspace --exclude socialname-desktop
cargo test --locked --workspace --exclude socialname-desktop --all-targets
cargo run --locked -p socialname-cli -- rules validate
cargo run --locked -p socialname-cli -- fixtures
cd apps/desktop
npm ci
npm run check
```

For the local server, worker, database, and console integration harness, see
[`deploy/compose.yaml`](deploy/compose.yaml). It is a development harness, not
a supported self-hosted product.

## Site-rule changes

Read [`docs/site-rules.md`](docs/site-rules.md) and the relevant canary design
before editing `rules/sites/` or `rules/canaries/`.

A site-rule change must include:

- a strict source rule with the filename matching its stable site ID;
- minimized deterministic fixtures for important positive, negative, blocked,
  failure, and conflict paths;
- explicit HTTPS hosts, redirect policy, and response budgets;
- no arbitrary-code escape hatch or authenticated scraping; and
- `metadata.enabled: false` unless the complete signed live gate is already
  evidenced in the repository.

Run `rules validate`, `canaries validate`, and `fixtures` after rule or canary
changes. Live checks are explicit, bounded canary operations; do not use a
private person's identifier as a test target.

## Verification

Run the checks relevant to the change. The normal full gate is:

```console
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo run --locked -p socialname-cli -- rules validate
cargo run --locked -p socialname-cli -- fixtures
cd apps/desktop
npm ci
npm run check
npm run build
```

On a platform without Tauri prerequisites, exclude `socialname-desktop` from
the Rust workspace commands and rely on the Windows and macOS CI jobs for the
native targets.

## Pull requests

Keep each pull request focused on one coherent, verified outcome. In the
description, state:

- the behavior or problem being addressed;
- the important trust, privacy, compatibility, or failure decisions;
- the exact checks you ran; and
- any external evidence gate that remains.

Update user-facing documentation and API examples with the implementation.
Update `ROADMAP.md` only when a command, test, report, run, or artifact supports
the new status. CI must pass before merge.

All participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
