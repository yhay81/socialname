# Assertion trust model

## Decision

Shared observations may create a useful shared assertion without a managed
worker only after strict evidence, reputation, and independence thresholds are
met. Such an assertion is `corroborated`, never `verified`.

Managed execution is not treated as magic truth. It still requires a healthy
rule, strong evidence, freshness, and conflict checks. The model is asymmetric:
claiming presence is generally easier to support than claiming absence, and a
disappearance notification requires more confirmation than an interactive
lookup.

The initial derivation algorithm is versioned as `assertion/v1`.

## Processing stages

```text
signed upload
  -> admission gates
  -> evidence classification
  -> producer reputation
  -> independence grouping
  -> freshness and rule health
  -> assertion derivation
  -> transition confirmation
```

No unbounded weighted average or latest-writer-wins step exists.

## Admission gates

A shared observation is eligible to influence an assertion only when all of
the following hold:

- The installation is authenticated and the signed envelope has a valid
  monotonic sequence number or server challenge.
- The referenced consent grant was active at observation time.
- The upload schema, engine version, and rule hash are recognized.
- The URL, host, redirect, method, response limits, and matcher trace agree
  with the compiled probe plan.
- The shared upload arrives within 15 minutes for current-state influence.
  Uploads up to 24 hours old may be retained as history but cannot establish
  the current assertion.
- Clock skew is within five minutes or a server-issued time anchor makes the
  ordering usable.
- Evidence is complete for the claimed evidence class.
- The observation is not a replay, duplicate, impossible-duration result, or
  known generic WAF/challenge response.
- The site rule is not quarantined in the relevant region.

Private observations may be stored with weaker admission because they are the
tenant's own record, but weak observations remain visibly weak.

## Evidence classes

Evidence strength is derived by the compiler and engine, not selected freely by
a site author or client:

| Class | Meaning | Examples |
| --- | --- | --- |
| `E4 structured_identity` | Site-owned structured response names the exact identifier or returns a typed absence error | Exact JSON handle plus stable public ID; WebFinger subject |
| `E3 explicit_endpoint` | Endpoint semantics plus an identity/error marker are definitive | 404 on a profile route with healthy positive control; canonical profile URL plus exact handle |
| `E2 differential_template` | Stable difference from positive and negative controls | Reviewed soft-404 body marker; redirect and DOM-fingerprint combination |
| `E1 weak_signal` | Plausible but not independently definitive | Bare 200, response length, generic title, one redirect |
| `E0 no_account_evidence` | Transport or intermediary state | Timeout, DNS error, rate limit, CAPTCHA, WAF, generic block page |

`E0` observations influence site health, not account presence.

A status code alone is not universally strong. A bare `200` is normally `E1`
because many sites return generic or soft-404 pages. A `404` can reach `E3`
only when live positive controls and fixtures show that the route is
account-specific and the response is not an intermediary block.

## Producer reputation

Reputation is scoped to an installation and site family, decays with a 60-day
half-life, and is based only on overlaps that later receive managed or
controlled-canary truth:

| Tier | Minimum evidence | Shared influence |
| --- | --- | --- |
| `new` | Fewer than 20 validated overlaps | Hint and verification scheduling only |
| `calibrated` | At least 20 overlaps, 98% agreement, 7 active days | Counts in corroboration quorum |
| `trusted` | At least 100 overlaps, 99% agreement, 30 active days, 5 site families | Counts in quorum; may reduce recheck priority |
| `suspended` | Invalid signatures, replay, fabricated-plan evidence, or rolling agreement below 90% | None |

One surprising disagreement does not automatically punish a client; it may
reveal a real regional difference. Reputation updates wait until rule health
and managed rechecks distinguish source error from site variation.

The thresholds are initial calibration parameters and must be replayed against
labeled canary history before production. They are never shown as a vague
end-user confidence percentage.

## Independence groups and Sybil resistance

Counting installations is insufficient. Corroboration counts at most one vote
per:

- Installation key.
- Tenant or billing identity.
- Short-lived network group derived from country, ASN/network class, and a
  rotating keyed token.
- Active server challenge.

The derivation records only coarse independence facts. Exact client IP is not
stored in the observation. Many observations from one tenant, one ASN, or one
response fingerprint cannot manufacture diversity.

Datacenter, anonymizer, and residential vantages are useful but distinct. A
mixture is reported rather than silently pretending that all vantages sample
the same population.

## Freshness and rule health

The central policy owns assertion TTLs; site rules provide measured capability
hints but cannot extend retention or trust by themselves.

Initial current-state defaults:

| Verdict | Default assertion TTL |
| --- | ---: |
| `found` | 24 hours |
| `not_found` | 15 minutes |
| `inconclusive` / blocked | 5 minutes |

Monitoring can demand a shorter maximum age. A rule change invalidates older
support unless compatibility is explicitly proven. Regional rule health caps
quality:

- `healthy` (green): normal definitive derivation.
- `degraded` or `recovering` (yellow): evidence may remain visible as
  provisional history, but it cannot establish a definitive assertion.
- `quarantined` (red): no definitive assertion in that region.

The persisted transition policy is defined in
[`rule-health-v1.md`](rule-health-v1.md).

## Derivation rules

### Found

`verified` requires:

- One fresh managed `E3` or `E4` observation.
- Green health in that region.
- A passing positive and negative control in the applicable health window.
- No fresh opposing `E3` or `E4` observation.

`corroborated` without managed support requires:

- At least three `calibrated` or `trusted` independence groups.
- At least two network groups and two coarse regions.
- `E3` or `E4` evidence from every counted group.
- Compatible identity fields and response-fingerprint families.
- Green rule health and no strong conflict.

One eligible observation becomes `single_vantage`.

### Not found

`verified` current state requires a fresh managed `E3` or `E4` observation,
green health, passing controls, and no fresh strong positive.

Shared-only absence may become `corroborated` only with:

- At least five `calibrated` or `trusted` independence groups.
- At least three network groups and two coarse regions.
- A minimum ten-minute span between the first and last counted observations.
- `E3` or `E4` evidence from every counted group.
- No strong positive and no regional degradation.

Shared-only absence is useful for cache ranking and managed-work scheduling,
but cannot by itself trigger a disappearance notification.

### Conflict

Any fresh opposing `E3` or `E4` evidence makes the assertion `conflicted`.
Managed evidence does not silently overwrite client evidence. The system:

1. Separates mismatched rule hashes and observation times.
2. Tests for a regional split.
3. Compares controls and response-fingerprint clusters.
4. Schedules managed verification from a useful missing vantage.
5. Suppresses account-state transitions while preserving a distinct
   measurement-degradation event.

## Transition confirmation

An assertion answers "what is best supported now." A paid notification has a
higher bar:

| Candidate transition | Required confirmation |
| --- | --- |
| `not_found -> found` | One managed `E4`, or managed `E3` followed by a second observation; shared quorum schedules this verification |
| `found -> not_found` | Two managed `E3/E4` observations from independent regions, or two separated by at least five minutes where only one region is valid |
| Any state -> `inconclusive` | Emit site/rule degradation, not account removal |
| Conflicting regions | Preserve regional assertions; no global account-state alert |

Customers may opt into early "candidate appeared" notifications from a
corroborated shared result. The default paid alert stream remains verified.

## Advanced reliability techniques

### Paired controls

Reuse recent positive and generated-negative canaries from the same
site/region/network class. A target response that is indistinguishable from both
controls is inconclusive. This catches generic `200` pages and WAF templates.

### Response equivalence classes

Store bounded header, redirect, body-token, and DOM-structure fingerprints.
Cluster them by site, rule, and region. A new cluster or a collision between
known-positive and known-negative clusters triggers rule degradation.

### Exact identity binding

Prefer evidence that binds the returned stable public object ID and normalized
handle to the request. A profile-shaped page without the requested identity is
not enough.

### Shadow evaluation

Workers evaluate a staged rule against live Evidence Capsules without using its
verdict in production. Promotion requires lower conflict and inconclusive rates
without a canary precision regression.

### Active verification

Managed capacity is allocated to observations with the greatest information
gain: fresh conflicts, new response clusters, region gaps, high-value watched
targets, and newly calibrated contributors. Rechecking unanimous low-risk
results has lower priority.

### Explainability before machine learning

Statistical and machine-learning models may detect anomalies, cluster response
templates, and prioritize verification. They do not directly emit
`found`/`not_found`. The final assertion remains reproducible from versioned
rules, evidence classes, quorum facts, freshness, and health.

## Public assertion explanation

Every API result exposes facts rather than a synthetic confidence score:

```text
quality: corroborated
evidence_class: E4
observed_at: ...
expires_at: ...
regions: [jp, us]
support_groups: 3
managed_support: false
rule_health: green
conflicts: 0
derivation_version: assertion/v1
```

Producer IDs, tenant identities, ASNs, and raw evidence remain private.
