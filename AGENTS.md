# SocialName agent instructions

These instructions apply to the whole repository.

## Read before acting

Read these sources in order before planning product or implementation work:

1. `docs/ultimate-goal.md` — the stable mission, product promise, North Star,
   boundaries, and decision filter.
2. `ROADMAP.md` — the current milestone, ordered deliverables, acceptance
   gates, and recorded evidence.
3. `docs/decisions-2026-07-24.md` and the later dated decision records —
   accepted architectural and governance decisions.
4. The focused design document for the area being changed.

The ultimate goal governs *why*. The roadmap governs *what is next*. Detailed
design documents govern *how*. If they conflict, stop implementation long
enough to reconcile the documents instead of silently choosing one.

## Execution contract

- Continue the current roadmap milestone until its software acceptance gate is
  complete. Do not start a later milestone merely because it is easier or more
  interesting.
- Convert the selected roadmap item into a short working plan with observable
  completion criteria before making broad changes.
- Prefer a complete vertical slice over disconnected scaffolding. A slice
  includes domain behavior, interfaces, failure handling, tests, documentation,
  and an operable entry point where applicable.
- Make safe, local assumptions when they do not change product intent. Record a
  durable decision when an assumption affects trust, privacy, compatibility,
  retention, external behavior, or roadmap order.
- Distinguish software gates from external evidence gates. Implement everything
  that can be completed locally; never fabricate credentials, deployments,
  multi-region evidence, signing, notarization, or production validation.
- When an external gate remains, leave the system safely disabled or
  quarantined, document the exact evidence still required, and continue with
  independent roadmap work.
- Update `ROADMAP.md` only when repository evidence supports the new status.
  Include the validating command, test, report, or artifact.

## Product invariants

- A result is a time- and vantage-specific observation, not timeless truth.
- `found`, `not_found`, operational failure, and uncertainty remain distinct.
- Matching public usernames do not prove common ownership.
- Ordinary local execution works without a SocialName service.
- No search target or observation leaves the device without an explicit sync
  policy or purpose-specific consent grant.
- Shared client evidence cannot become `verified` by itself. Shared-only
  absence cannot trigger a disappearance notification.
- Site rules stay discovery-only or region-quarantined until their documented
  live acceptance gate passes.
- Measurement degradation is not an account-state change.
- Do not bypass authentication, CAPTCHA, paywalls, robots protections, or
  third-party access controls.
- Do not store complete HTTP bodies, credentials, cookies, or unrelated profile
  data in normal evidence.
- Central-server work must preserve lineage so assertions, transitions,
  analytics contributions, and artifacts can be withdrawn or recomputed.

## Engineering workflow

- Preserve unrelated and uncommitted user changes. Never use destructive Git
  operations to simplify the worktree.
- Use the pinned Rust stable toolchain. On Windows, use PowerShell 7 and the
  MSVC toolchain. Use Node.js 24 and the existing npm lockfile for the desktop
  application.
- Keep dependency direction inward: applications depend on protocol, domain,
  rules, and engine crates; the engine does not depend on applications,
  persistence, or cloud APIs.
- Keep the rule language closed, typed, bounded, and declarative. Do not add an
  arbitrary-code escape hatch for one site.
- Treat usernames and public identifiers as sensitive product data in logs,
  metrics, traces, fixtures, and error reports.
- Prefer deterministic offline tests. Live network checks are explicit canary
  operations with strict request, time, and byte budgets.

Run the checks relevant to the changed scope. The normal full gate is:

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

On a platform without Tauri system prerequisites, exclude
`socialname-desktop` from the Rust workspace commands and rely on the Windows
and macOS CI jobs for the native target.

## Commit and push policy

The repository owner has explicitly requested small, frequent direct updates to
`main`.

- Commit one coherent, verified unit at a time; avoid both per-line commits and
  large unrelated batches.
- Before committing, inspect the staged diff and run `git diff --check`.
- Before pushing, fetch `origin/main` and confirm the local branch is not behind.
  Do not force-push or rewrite published history.
- Push verified commits directly to `origin/main`. If the remote diverged,
  tests fail, the worktree contains unrelated changes, or required authority is
  missing, stop and report the exact blocker rather than overriding it.
- After pushing, confirm `HEAD` equals `origin/main` and report the triggered CI
  run when available.

## Definition of done

A roadmap item is done only when:

- the user-visible or operator-visible behavior exists end to end;
- failure, cancellation, security, and privacy behavior is explicit;
- deterministic tests cover the important success and failure paths;
- relevant formatting, tests, linting, builds, rules, and fixtures pass;
- documentation and API examples match the implementation;
- `ROADMAP.md` records the evidence and any remaining external gate;
- the verified unit is committed and pushed according to the repository policy.
