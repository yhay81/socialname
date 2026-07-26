# Assertion recomputation and transition persistence

## Scope

Migration `0006_assertion_recomputation.sql` and the managed worker connect the
existing `assertion/v1` trust model to PostgreSQL. A successful managed job now
commits the immutable observation, current assertion generation, explicit
support, search assertion event, watch baseline or transition, and generic
lineage in one tenant transaction.

This slice does not add shared-observation upload, producer-reputation
admission or a public transition route. Shared rows
without independently persisted reputation facts remain ineligible for a
corroboration quorum. The separate
[signed webhook delivery](webhook-delivery.md) slice consumes confirmed
transitions without re-deriving account state.

## Eligible evidence

Recomputation reads only observations that match the exact:

- tenant;
- normalized username and site;
- rule version and rule hash;
- active purpose-specific consent boundary.

An observation must also be current at the database evaluation time, have
green rule health at observation time, contain a definitive `found` or
`not_found`, and carry compiler-derived `E3` or `E4` evidence. Superseded
rules, weak evidence, uncertainty, expired evidence, withdrawn consent, and
operational job failures cannot support a definitive assertion.

Managed observations use the central assertion TTLs:

- `found`: 24 hours;
- `not_found`: 15 minutes;
- typed uncertainty: 5 minutes.

An assertion expires at the earliest supporting or conflicting observation
expiry. That is the first point at which the same immutable support set and
quality can no longer be re-derived; a later probe then creates or reuses the
appropriate current generation.

The database schema does not yet persist the reputation and independence facts
needed to elevate shared clients. Until that admission slice exists, shared
rows are treated as untrusted rather than receiving an inferred reputation.

## Current assertion generations

The worker acquires a transaction-scoped advisory lock over a length-framed
`(tenant, normalized username, site)` key before inserting a new observation
or replaying fresh watch evidence. This serializes interpretations across
regions and rule workers without placing a target in logs or errors.

`derive_assertion` runs over the complete eligible exact-rule set:

- one or more unopposed managed `E3/E4` observations produce `verified`;
- opposing fresh strong verdicts produce an inconclusive `conflicted`
  assertion and retain every conflicting observation ID;
- no eligible evidence leaves the previous assertion generation in history
  and creates no new account meaning.

An unchanged replay reuses the exact current assertion. A changed evidence set
marks the previous row non-current, inserts a new immutable interpretation,
and writes `assertion_support` plus observation-to-assertion lineage. Historical
assertions are retained; recomputation is not withdrawal or deletion.

Each managed search consumer receives an ordered `assertion_updated` event
after its typed result and before the terminal event. The event is constructed
from the same persisted derivation. Its source, regions, support count,
freshness, managed support, and observation IDs remain explicit.

## Per-watch account baseline

The tenant-wide current assertion is not itself a watch transition baseline.
Two watches may consume the same observation but have different histories.
Migration `0006` therefore adds a nullable triple to each `watch_target`:

- `account_state`;
- `account_assertion_id`;
- `account_state_since`.

The triple is either entirely empty or entirely populated and references a
tenant-local assertion. The first eligible definitive assertion establishes a
baseline without creating a transition. This preserves the protocol rule that
an initial observation has no `from` state.

Later definitive assertions are compared with that watch-local baseline:

- the same state refreshes the supporting assertion pointer;
- a different state creates or advances one account-state candidate;
- a conflicted assertion suppresses a pending candidate as
  `conflicting_evidence` and never changes the baseline;
- uncertainty and operational failure never enter the account-state path.

Only a confirmed candidate advances the stored baseline. A pending or
suppressed candidate remains durable but non-deliverable.

## Account transition confirmation

The worker applies the closed confirmation rules from the assertion trust
model:

| Candidate | Confirmation |
| --- | --- |
| `not_found -> found` | one managed `E4`, or two ordered managed `E3` observations |
| `found -> not_found` | two managed `E3/E4` observations from distinct regions, or two in one region separated by at least five minutes |
| shared-only `found -> not_found` | suppressed as `shared_only_absence` |
| any candidate with fresh opposing evidence | suppressed as `conflicting_evidence` |

Evidence predating the watch's current baseline cannot confirm its next
transition. Pending rows can advance to confirmed when later evidence meets
the threshold. `transition_basis` remains append-only and generic lineage
connects the assertion to the transition.

## Measurement degradation

Measurement state is a separate transition class for an exact watch target,
rule version, and region:

- a definitive observation is `healthy`;
- typed classification uncertainty or fresh strong conflict is `degraded`;
- terminal transport, capacity, or rule-execution failure is `unavailable`.

The first scheduled probe has an implicit `healthy` measurement baseline
because scheduling and claim require a fresh healthy promoted rule. A state
change inserts a confirmed `measurement_health` transition. Repeated identical
measurement state is idempotent.

An uncertain result is an immutable observation and may appear in
`transition_basis`. An operational failure remains job state, so
`supporting_observation_ids` may be empty for a measurement transition; the
probe-job-to-transition lineage is the evidence. The protocol still requires
at least one observation for every account transition.

Neither `degraded` nor `unavailable` changes the watch's account baseline.
They cannot become a disappearance, and a notification worker must preserve
the transition class when it later constructs a delivery.

## Cancellation, consent, and least privilege

Recomputation happens only after the fenced lease, exact signed rule, active
consent, live search/watch consumers, watch revision, watch state, and active
endpoint links have been rechecked under row locks. A stale lease, paused or
revised watch, withdrawn consent, disabled endpoint, or quarantined rule
commits no observation, assertion generation, or watch transition.

The worker remains `LOGIN NOSUPERUSER NOBYPASSRLS`. It receives tenant-table
access only after a narrow coordinator returns an opaque tenant/job ID, sets
the transaction-local tenant, and uses column-limited mutation grants.
Assertion and transition writes therefore remain behind forced tenant RLS.

## Verification

Deterministic unit tests cover:

- unanimous support extending assertion expiry;
- E4 and E3-follow-up appearance confirmation;
- independent-region and time-separated disappearance confirmation;
- shared-only absence suppression;
- operational measurement transitions without fabricated observations.

The PostgreSQL 18 integration test uses real non-owner application and worker
roles and proves:

- exact-rule, active-consent `verified` assertion persistence;
- append-only support and generic lineage;
- ordered search `assertion_updated` output;
- first-observation watch baseline without a transition;
- E4 appearance confirmation, including fresh-observation replay;
- opposing strong observations becoming `conflicted` without account change;
- conflict or typed uncertainty becoming `healthy -> degraded`;
- terminal operational failure becoming `degraded -> unavailable` with
  probe-job lineage and no observation basis;
- account state remaining unchanged through measurement degradation;
- fenced retry, pause/revision, consent, endpoint, and RLS boundaries from the
  managed-job and watch-scheduling tests.

The test does not claim live-site correctness, production health evidence,
multi-region deployment, shared-client reputation admission, external webhook
ownership, or external retention evidence.
