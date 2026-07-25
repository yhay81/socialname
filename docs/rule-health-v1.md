# Regional Rule Health v1

## Purpose

Rule health describes whether one exact `(site, rule hash, managed region)` can
support definitive assertions. It is runtime quality state, not an account
observation and not a field in Site Rule YAML.

The four persisted states are:

- `healthy` — the only state that permits definitive assertion derivation;
- `degraded` — a recent operational failure makes measurement unreliable;
- `quarantined` — the rule is disabled for definitive use in this region;
- `recovering` — fresh acceptance evidence exists, but the rule has not yet
  earned healthy status.

Every new record starts `quarantined`. A software implementation, discovery
check, or previously healthy state in another region cannot initialize it as
healthy.

## Evidence admission

`CanaryHealthAssessor` accepts only:

- an opaque `EvaluatedCanaryAggregate` produced by the report aggregator; and
- an opaque `ValidatedCanaryShadow` produced by strict shadow validation.

The aggregate and shadow must bind the same site, manifest, candidate rule,
engine, selected region, and measurement window. The shadow run must finish
inside the aggregate's exact 24-hour window. Health evidence expires no later
than both the nested shadow report and 24 hours after aggregation.

The assessor evaluates each region independently. A missing or failed
`region-b` does not degrade an otherwise accepted `region-a`, while a selected
region cannot be omitted silently.

Evidence is mapped conservatively:

- precision loss, conflicting evidence, and wrong-verdict shadow regressions
  are classification failures;
- missing/insufficient runs, short windows, insufficient coverage, blocking,
  rate limits, timeouts, and excessive latency are operational failures;
- only a region with no applicable aggregate or shadow issue produces
  acceptance-passed evidence.

## State transitions

The default policy is:

| Current state | Evidence | Next state |
| --- | --- | --- |
| `quarantined` | fresh aggregate + shadow acceptance | `recovering` |
| `recovering` | second distinct fresh acceptance | `healthy` |
| `healthy` | first operational failure | `degraded` |
| `degraded` | second consecutive operational failure | `quarantined` |
| `degraded` | fresh acceptance | `recovering` |
| `recovering` | any operational failure | `quarantined` |
| any state | classification failure | `quarantined` |
| `healthy` | fresh acceptance | `healthy` |

Recovery and operational thresholds are bounded policy values from 2 through
32. The defaults are both 2. A pass cannot jump directly from quarantine to
healthy, and failure during recovery discards recovery progress.

## Replay and persistence contract

Each event carries:

- the exact regional key;
- the next contiguous sequence number;
- the manifest and executing-engine hashes admitted with the evidence;
- observation and evidence-expiry timestamps;
- one content identity for failure evidence, or distinct aggregate and shadow
  identities for acceptance.

The record retains the latest admitted manifest and engine hashes, evidence
identities, and evidence expiry. The pure state machine rejects mismatched keys,
skipped or replayed sequences, out-of-order/future/expired evidence, malformed
evidence IDs, and invalid persisted counters. A persisted record can therefore
be validated before an operator applies its next event, and a later promotion
gate can reject stale or version-mismatched health.

The operator command revalidates source reports and shadow evidence, rebuilds
the aggregate, validates an optional current record, and emits the next record
plus its audit transition:

```console
cargo run --locked -p socialname-cli -- canaries health --reports-dir <reports> --shadow-report <shadow.json> --site <site-id> --manifest-hash <sha256> --candidate-rule-hash <sha256> --last-known-good-rule-hash <sha256> --engine-hash <sha256> --region <region-a> --required-region <region-a> --required-region <region-b> --required-region <region-c> --window-start <rfc3339> --window-end <rfc3339> --json
```

Pass the prior JSON output back through `--current-record <record.json>` for a
subsequent event; a bare record object is also accepted. The command does not
overwrite the record. An operator or later transactional service persists the
returned JSON.

## Notification and promotion boundary

A rule-health transition is always a measurement-system event.
`allows_account_state_notification()` is false for every health transition.
Degradation or quarantine must not become an account disappearance.

Only `healthy` permits definitive assertions. `degraded` and `recovering`
correspond to provisional/yellow measurement quality; `quarantined` corresponds
to red. None of these states publishes or activates a candidate. Signed
promotion, activation, and rollback remain separate later gates.

Deterministic tests cover recovery, healthy-to-degraded-to-quarantined
operation, immediate classification quarantine, failure during recovery,
replay/staleness/cross-region rejection, persisted-record validation,
partial-region isolation, reprocessing-stable evidence identity, and
health-only notification behavior.

The repository still contains no production canary manifests or real managed
health evidence. All representative rules remain discovery-only.
