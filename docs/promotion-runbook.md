# First rule promotion runbook

Status: **Canary fleet running; promotion not yet performed**

This records the exact path from a running canary fleet to a rule that
managed workers will execute. It exists because the steps span three
artifacts and two trust boundaries, and getting them out of order produces
errors that look like configuration problems but are really ordering
problems.

Nothing here promotes anything on its own. Each step refuses to proceed on
evidence it cannot verify.

## What is already in place

| Piece | State |
| --- | --- |
| Site rules | 460, all `enabled: false` |
| Canary manifests | `github`, `gitlab`, `mastodon-social`; controls verified by real probes |
| Canary fleet | ENAM, WNAM, WEUR Cloudflare Containers; Cloudflare cron plus an independently scheduled authenticated trigger |
| Report store | R2 `socialname-canary-reports`, keyed by scheduled slot |
| Trust root | generation 1, threshold 1, expires 2028-01-01 |
| Signing key | generated locally, held by the operator, never in the repository |
| API server | `api.socialname.net`, managed PostgreSQL, console on the same origin |

The signing key is the one artifact with no backup path. Losing it means
issuing a new trust root and redistributing it to every worker; leaking it
means anyone can promote any rule. It belongs in a password manager, not in
the scratchpad directory it was generated into.

## Ordering

Each step consumes the previous step's output, so they cannot be reordered.

1. **Accumulate reports.** The gate needs three managed regions and at least
   three runs each inside one exact 24-hour window. Each region's first and
   last completions must be at least 18 hours apart. An aligned window offers
   up to 13 boundary-inclusive slots per region so best-effort cron misses do
   not immediately make the window impossible.
   Reports are addressable without listing the bucket:
   `canary/<site>/<region>/<YYYY-MM-DD>/<HH>.json`.

2. **Aggregate.** `socialname canaries aggregate` consumes only
   validator-produced reports and enforces the window, the per-region run
   count, 100% conclusive precision, at least 95% conclusive coverage, zero
   conflicts, and the reviewed p95 latency in every required region. Global
   volume cannot hide a missing or failing region.

3. **Assess health.** Regional records start quarantined. Two distinct fresh
   passes move a region `quarantined -> recovering -> healthy`, so a single
   good day is deliberately not enough.

4. **Sign the promotion.** `socialname canaries promote` binds the accepted
   evidence, the candidate rule, the exact pack hash, the manifest, the
   engine, the required regions, and an expiry of at most 24 hours under a
   domain-separated Ed25519 signature.

5. **Sign the pack metadata.** `socialname rules sign-metadata` threshold-signs
   the exact pack, its predecessor, the rollout stage, and every embedded
   site promotion, against the trust root from the ceremony.

6. **Activate.** `socialname-server apply-rule-pack` verifies the signature
   against an out-of-band trust pin, recompiles the real pack, enforces the
   monotonic sequence and exact predecessor, and retains the previous pack
   for rollback.

Only after step 6 does a rule become `enabled` for managed execution, and
only in the regions its promotion names.

## What is deliberately not automated

Promotion is not wired into CI. A pipeline that can promote a rule is a
pipeline whose compromise promotes arbitrary rules, and the signing key would
have to live where the pipeline can read it. The steps above are operator
commands run against a key the operator holds.

## Known gaps

- Cloudflare places containers only in ENAM, WNAM, EEUR, and WEUR, so the
  fleet has no APAC vantage and cannot observe region-specific behaviour
  there. Adding one is a second-provider decision, not a code change.
- Shadow comparison against a last-known-good rule has no predecessor for a
  first promotion, so the aggregate thresholds carry that first decision
  alone.
- The deployed database is PostgreSQL 17 while the core gate runs 18; the
  PostgreSQL 17 job covers the deployed version.
