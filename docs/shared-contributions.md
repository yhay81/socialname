# Shared contribution ingestion v1

Status: **Implemented acceptance boundary; calibration and corroboration
pending**

This document defines the `socialname.dev/shared-contribution/v1` acceptance
boundary: how an explicitly consented client installation submits one
minimized shared observation and how replay, quota, anomaly, diversity, and
reputation controls govern admission. The admission-gate, evidence-class,
reputation, and independence design it implements is
[the assertion trust model](assertion-trust.md); the collection profile is
[the data-governance shared-observation profile](data-governance.md).

## Boundary summary

- Client-contributed shared observations are stored in their own untrusted
  `shared_contributions` table. They are never written to the managed
  `observations` table, never create `assertion_support` rows, and therefore
  cannot influence `verified` truth or any account-state transition in this
  slice. Quorum-based `corroborated` derivation is the next ordered roadmap
  item and will consume this table read-only.
- Submission requires an authenticated API key with the new
  `contribution:write` scope, an active-role membership that is not `viewer`,
  and an installation-subject consent grant with the exact
  `shared_observation` purpose that was active both at observation time and at
  submission time.
- The wire contract is minimized by construction: target, exact rule identity,
  engine hash, coarse vantage, typed outcome, evidence class and digest,
  bounded sanitized probe summaries, and bounded matcher traces. There is no
  field for bodies, headers, cookies, credentials, client IP, or telemetry,
  and operational transport failure is not submittable because it is not an
  observation.

## API v1 operations

| Operation | Scope | Behavior |
| --- | --- | --- |
| `POST /v1/shared-contributions` | `contribution:write` | Admit one submission; exact replay returns the original resource |
| `GET /v1/shared-contributions` | `contribution:read` | Bounded tenant-local keyset page in received order |
| `GET /v1/shared-contributions/{contribution_id}` | `contribution:read` | Read one tenant-local contribution |

The resource reports the normalized target, rule hash, coarse region and
claimed network class, outcome, evidence class and digest, sequence number,
influence scope, the contributor's current site-family reputation tier, and
observed/received/expiry times. Deletion-hidden rows disappear from every
read before physical purge.

## Admission pipeline

Order matters; every rejection is typed and never echoes the submitted value.

1. **Protocol validation.** Closed DTO, unknown fields rejected, definitive
   verdicts require `E2`..`E4` evidence plus at least one probe, `E0` must be
   uncertain, and the serialized submission is bounded at 32 KiB.
2. **Freshness windows.** `observed_at` may lead the database clock by at most
   5 minutes. Uploads within 15 minutes of observation are eligible for
   current influence; up to 24 hours they are retained `history_only`
   (`stale_upload`); older uploads are rejected.
3. **Consent.** The presented installation must already exist with an active
   grant of purpose `shared_observation` bound to that exact client row, with
   `granted_at <= observed_at`. Failures are uniform conflicts.
4. **Recognized rule.** The `(site, rule_hash)` pair must resolve to a stored
   `rule_versions` row. The server recompiles the stored source rule and
   normalizes the submitted username through the site's exact username
   policy; a username outside the policy is invalid.
5. **Reputation gate.** The `(installation, site-family)` reputation record is
   created as `new` on first contact and locked; a `suspended` record rejects
   before any other work. Site family is initially the site ID.
6. **Replay control.** A per-installation sequence high-water mark is locked.
   Exact replay (same sequence, same content digest) returns the original
   resource. A used or regressed sequence with different content is a counted
   replay violation that is committed even though the submission is rejected;
   the third violation suspends the site-family reputation
   (`replay_abuse`) with a target-free audit event.
7. **Probe-plan agreement.** Every submitted probe must name a probe in the
   compiled plan, and any final URL host must be inside that probe's
   `allowed_hosts`. Disagreement is fabricated-plan evidence: the reputation
   is suspended immediately (`fabricated_plan_evidence`) and the suspension
   commits despite the rejection.
8. **Deletion suppression (fail closed).** An active `target_reingestion`
   token for the normalized target refuses the submission before any
   target-bearing row is written. An active token under a different
   suppression-key fingerprint makes ingestion unavailable rather than
   silently forgetting the erasure.
9. **Quota.** Tenant-day and installation-day accepted counters increment
   atomically inside the transaction; exceeding either initial software limit
   (5,000 tenant, 1,000 installation, UTC day) rolls the submission back with
   a retryable quota error and consumes nothing.
10. **Acceptance.** One immutable row commits with the verdict-specific
    expiry (`found` 24 h, `not_found` 15 m, uncertain 5 m from observation),
    the influence scope, the coarse independence-group token, the advanced
    high-water mark, and the reputation activity day.

## Influence scope

`current` requires both the 15-minute upload window and a fresh `healthy`
rule-health record for the exact rule version and claimed region; anything
else is `history_only` with a closed reason. Because every repository rule is
discovery-only without live canary evidence, real submissions remain
`history_only` until the external rule-health gate passes. The scope is
recorded at admission and never widens later.

## Diversity and independence facts

Each accepted contribution stores a 32-byte keyed independence-group token
derived from the claimed coarse region, claimed network class, and a weekly
rotation window under a dedicated HMAC domain of the configured server
secret. It is a population bucket for at-most-one-vote-per-group counting,
not an identifier: the client IP is never stored, ASN-level grouping requires
transient production ingress data that does not exist in the repository, and
the protocol has no network-group field.

## Reputation model

`contributor_reputation` rows are tenant-scoped per installation and site
family with the closed tiers `new`, `calibrated`, `trusted`, and `suspended`.
Database triggers enforce monotonic counters, exact revision increments, and
the closed transition matrix (`new -> calibrated -> trusted` ascent, decay
one step down, any tier to `suspended`, and `suspended` terminal). This slice
implements creation, activity accounting, and violation-driven suspension.
The calibration ascent — validated overlaps against managed or
controlled-canary truth with the documented 20/98%/7-day and
100/99%/30-day/5-family thresholds — is the next slice inside the same
roadmap item and is required before any contribution can enter a
corroboration quorum.

## Deletion and lineage

- Contributor deletion (`data:delete`) selected by the owning grant matches
  `shared_contribution` resources exactly like observations: reads hide them
  immediately, and the fenced deletion worker physically deletes matched rows
  during primary purge.
- Verified target-person deletion matches shared contributions by exact
  `(site, normalized username)` selectors across tenants, counts them in the
  operator output, installs the suppression tokens that block future
  re-ingestion, and purges them through the same worker path.
- Restore-ledger replay rescans `shared_contributions` for both suppression
  purposes so rows restored from an older backup are re-hidden before a
  restored runtime can serve traffic.
- Sequence, quota, and reputation control rows contain no target data and are
  intentionally retained.

## Explicit non-goals of this slice

- No contribution can create or support an assertion, transition, or
  notification yet; the quorum `corroborated` path is separate ordered work.
- No client signature envelope exists yet; source continuity relies on the
  authenticated API key, the tenant-separated installation digest, and the
  monotonic sequence. A signed envelope may be added with the calibration
  slice without changing the storage contract.
- Engine hashes are recorded and format-validated but not yet matched against
  a registry of client engine builds, because no such registry exists.
- CLI and desktop submission wiring remains future client work; the server
  boundary is complete and testable without it.

## Evidence

The real PostgreSQL 18 boundary test covers scope denial, consent conflicts,
history-only acceptance with exact normalization, exact replay convergence,
counted replay violations and third-violation suspension, suspended-submission
denial, green-health current influence, stale-upload history, window and
unknown-rule rejection without target echo, immediate fabricated-plan
suspension, tenant isolation, cursor validation, seeded quota exhaustion with
retry-after, append-only and guard-trigger enforcement, target-person
hiding/suppression/purge, contributor-deletion hiding and purge, and the
retained target-free control rows.
