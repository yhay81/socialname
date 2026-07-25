# Canary workflow operations

## Safe default

The manual and scheduled GitHub Actions workflows are templates for a reviewed
managed-vantage deployment. Both are disabled unless the repository variable
`SOCIALNAME_CANARY_ENABLED` is exactly `true`. The repository does not set that
variable, contain production manifests, declare production runner labels, or
hold production credentials.

Enabling the variable is not enough to make a rule healthy or active. These
workflows only produce minimized Canary Report v1 artifacts. They do not
aggregate reports, change regional health, sign a promotion, activate a pack,
send an account-state notification, or publish target identities.

## Vantage and secret prerequisites

Each real target needs:

1. a self-hosted Linux runner whose labels include `self-hosted`, `linux`, and a
   purpose-specific label tied to the declared managed vantage;
2. a protected GitHub environment whose name is a lowercase label;
3. environment reviewers and branch/deployment restrictions appropriate for
   live third-party requests;
4. an environment secret named `SOCIALNAME_CANARY_MANIFEST_B64`, containing
   exactly one reviewed Canary Manifest v1 YAML document encoded as base64;
5. a purpose-specific consent/sync policy covering the positive controls,
   target service, managed runner, and short-lived GitHub report artifact.

The manifest secret is injected only into the materialization step, written
with owner-only permissions under the runner temporary directory, and removed
in an `always()` cleanup step. It is not placed in a job-wide environment. The
report excludes usernames, profile URLs, bodies, and matcher details and is
retained as a GitHub artifact for three days.

GitHub-hosted runner location is not accepted as regional proof. Configure a
runner label only after its actual vantage and network controls have been
reviewed.

## Fixed execution budgets

Both workflows pass the same non-configurable upper bounds to the production
CLI:

| Boundary | Limit |
| --- | ---: |
| Planned requests per rule | 64 |
| In-flight requests per run | 4 |
| CLI wall time | 120,000 ms |
| Inspected response bytes | 16,777,216 |
| Workflow job timeout | 10 minutes |
| Concurrent scheduled target jobs | 3 |
| Same site/region running jobs | 1; the running job is not cancelled |

The runner performs a worst-case request and byte preflight before network
work. A partial, cancelled, timed-out, blocked, or otherwise failed run is not
silently accepted. The workflow remains failed after uploading any minimized
partial output that was produced.

## Manual workflow

`Manual canary` requires:

- site, region, protected environment, and reviewed self-hosted runner label;
- an explicit `acknowledge_live` checkbox;
- the repository-wide enable variable.

A lightweight GitHub-hosted preparation job validates only non-sensitive
labels. The live job then waits for any protected-environment approval and runs
on the selected self-hosted vantage. Per-site/region concurrency prevents a
manual run from overlapping a scheduled run. GitHub Actions retains at most one
pending job per concurrency group by default, so a newer pending invocation can
replace an older pending invocation while the running job continues.

## Scheduled workflow

`Scheduled canaries` evaluates every 12 hours at minute 17. That cadence can
contribute three samples spanning a 24-hour aggregation window without
weakening the aggregator's exact window and regional gates.

The non-sensitive repository variable `SOCIALNAME_CANARY_SCHEDULE` is a JSON
array. Each entry has exactly these fields:

```json
[
  {
    "site": "approved-site-id",
    "region": "managed-region-a",
    "runner_label": "canary-region-a",
    "environment": "canary-region-a"
  }
]
```

The preparation job rejects an empty list, more than 64 targets, unknown
fields, invalid labels, and duplicate `(site, region)` entries. The protected
environment supplies the target-specific secret; the repository variable
contains no usernames or credentials.

Configure runners, environments, reviewer policy, secrets, and the schedule
JSON first. Set `SOCIALNAME_CANARY_ENABLED=true` last. Disable that variable
first during incident response or maintenance.

## Validation and downstream handling

The repository test suite parses both workflow YAML files and asserts their
trigger, read-only permission, secret scope, concurrency, explicit budgets,
artifact retention, and non-promotion contract. Operators still need to
download reports and run the separate validation, aggregation, shadow, health,
promotion, and activation gates described in the focused canary documents.

Live multi-region execution, environment protection, consent, signing custody,
and elapsed 24-hour evidence remain external evidence gates. None is claimed by
the checked-in templates.
