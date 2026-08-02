# Decisions: 2026-08-02

This record extends [Decisions: 2026-07-29](decisions-2026-07-29.md). The
[ultimate goal](ultimate-goal.md) remains the authoritative product charter and
[`ROADMAP.md`](../ROADMAP.md) remains the live implementation order.

## Accepted

- Canary aggregation keeps one **exact 24-hour policy window** and requires at
  least three accepted reports from each of at least three managed regions.
- Within that window, each region's first and last report completions must be
  at least **18 hours apart**. Requiring a full 24-hour first-to-last span would
  make acceptance depend on runs landing on both window edges to the
  millisecond, so normal scheduler jitter would make every real rule
  unpromotable.
- The managed fleet runs every two hours. An aligned 24-hour window has up to
  13 boundary-inclusive opportunities per region, allowing best-effort cron
  deliveries to be missed while the 18-hour coverage and three-run gates
  remain achievable.
- This changes no precision, conclusive-coverage, conflict, latency, shadow,
  signing, regional-health, or rollback threshold. Global volume still cannot
  compensate for a missing or failing region.
- `api.socialname.net` remains an operator-provisioned Cloudflare custom
  domain. The checked-in Worker configuration uses `workers_dev: false` and
  omits `routes`, Cloudflare's documented dashboard-managed mode, so routine
  CI deployment needs Worker and Container permissions but not continuing Zone
  Workers Routes authority. The existing domain is checked after deployment;
  changing or recreating it remains an explicit operator action.
