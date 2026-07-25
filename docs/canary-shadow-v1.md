# Canary Shadow v1

## Purpose

`socialname.dev/canary-shadow/v1` compares a staged candidate rule with the
last-known-good rule without letting the candidate affect production account
state. It is an additional promotion gate after ordinary Canary Report and
Canary Aggregate acceptance, not a replacement for either gate.

The same Canary Manifest v1 source is compiled independently against both
rules. Its canonical manifest hash stays the same while each compiled manifest
retains the rule hash against which username-policy compatibility was checked.

## Paired execution

Negative controls are generated once for the pair. The runner then sends the
same private positive and generated-negative target set through both rules.
This avoids treating two unrelated generated usernames as if they were a
shadow pair.

The operator command takes explicit candidate, last-known-good, and manifest
files:

```console
cargo run --locked -p socialname-cli -- canaries shadow --candidate-rule <candidate.yml> --last-known-good-rule <last-known-good.yml> --manifest <canary.yml> --region <managed-region> --allow-live --json
```

`--allow-live` is mandatory. `max_requests`, `max_concurrency`,
`max_elapsed_ms`, and `max_response_bytes` apply to the combined work of both
rules. Request and inspected-byte budgets are checked before network work; the
two rules also share one concurrency limiter, deadline, and cancellation
token.

Cancellation, deadline, request-budget, and response-byte-budget outcomes
remain explicit partial diagnostics. An incomplete pair cannot be sealed as a
shadow comparison.

## Artifact and validation

The content-addressed envelope contains:

- one independently content-addressed Canary Report v1 for the candidate;
- one independently content-addressed Canary Report v1 for the
  last-known-good rule;
- exact comparison metrics, typed issues, and an `accepted` or `rejected`
  disposition.

Strict validation recomputes both nested reports and the comparison summary. It
also requires:

- the policy-selected candidate and last-known-good rule hashes to be
  different and in their declared roles;
- the same site, manifest, engine, region, start, finish, expiry, case IDs, and
  expectations on both sides;
- complete nested runs and a canonical comparison SHA-256;
- a fresh report validity window and a non-duplicate comparison ID.

The runner never writes target usernames, profile URLs, complete bodies,
matcher traces, cookies, or credentials into the artifact. Positive-control
IDs and generated-negative sequence IDs are retained so paired cases can be
compared without exposing the identifier values.

Until a later signed promotion artifact authenticates the producer, a
content-addressed comparison proves integrity but not who performed the paired
execution.

## Acceptance semantics

The comparison rejects a candidate when any paired region/run shows:

- lower exact conclusive precision than last-known-good;
- lower exact conclusive coverage, which means a higher inconclusive rate;
- more conflicting-evidence cases;
- a previously correct conclusive case becoming inconclusive or changing to
  the wrong conclusive verdict.

Equal metrics are non-regressing and therefore acceptable. A candidate that
turns a last-known-good inconclusive result into the expected conclusive
verdict is recorded as an improvement.

Shadow acceptance alone does not establish sufficient quality. The candidate
must still independently satisfy the 100% precision, 95% conclusive coverage,
zero-conflict, latency, repeated-run, and multi-region Canary Aggregate gate.
It also does not publish a rule or emit an account-state notification. A
validated shadow becomes one input to the separate regional health policy; it
cannot change health by itself.

Deterministic tests cover identical private target sets, accepted parity and
improvement, coverage/precision/conflict regression, combined-budget preflight,
cancellation, summary tampering, duplicate comparison rejection, and absence
of target usernames from serialized output.

There are no production canary manifests or real shadow reports in the
repository. No site rule has been promoted by this software slice.
