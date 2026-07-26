# Regional managed-worker deployment boundary

This document defines the repository-completable deployment unit for
Milestone 3. It does not claim that a registry image, managed database, live
rule promotion, canary vantage, or worker exists in any real region.

The regional canary templates remain documented in
[Canary workflow operations](canary-workflows.md). The worker artifact here is
provider-neutral because hosting-provider selection is intentionally not an
architecture commitment.

## OCI artifact

`deploy/worker/Dockerfile` builds `socialname-worker` with a digest-pinned
Dockerfile frontend and digest-pinned official Rust and Debian images. The
final image's application payload:

- contains only the release binary, the CA bundle, and `rules/sites`;
- runs as numeric UID/GID `10001:10001`;
- has no runtime package-install step;
- contains no database URL, signing key, promotion, canary manifest, or
  delivery key;
- declares `SIGTERM` as its stop signal; and
- runs `--help` by default, so starting the image without an explicit command
  cannot mutate PostgreSQL or contact a third party.

Build and inspect the local artifact from the repository root:

```console
docker build --file deploy/worker/Dockerfile --tag socialname-worker `
  --build-arg VCS_REF=$(git rev-parse HEAD) .
docker run --rm --network none socialname-worker --help
docker image inspect socialname-worker
```

The quality workflow performs the same build, verifies the numeric user and
entry point, and proves under `--network none` that `process-one` without
`--allow-live` fails before reading its promotion, key, or database
configuration. It does not log in to a registry or publish the image.

## One-shot workload model

One `process-one` invocation is one bounded scheduler work unit for exactly one
site and one region. It plans at most one due watch, expands a bounded batch,
claims at most one fenced job, and then exits. A regional scheduler may invoke
the same immutable image repeatedly; it must not add an unbounded loop around
failed configuration.

Deploy a separate workload for each accepted site/region tuple. The deployment
must identify the image by its built manifest digest, not by a mutable tag.
The exact embedded `/opt/socialname/rules/sites` pack is recompiled and matched
against the signed promotion before any job can execute.

The probe workload receives only:

- `SOCIALNAME_WORKER_DATABASE_URL`, injected at runtime for the documented
  non-owner, `NOBYPASSRLS` worker role;
- one read-only promotion JSON artifact;
- one read-only trusted Ed25519 public-key file;
- the expected manifest and engine hashes, predecessor, sequence floor, site,
  region, and required-region set as explicit non-secret arguments; and
- a closed lowercase worker ID that contains no target or tenant data.

Do not mount the endpoint-encryption or webhook-signing keys into this
workload. `deliver-one` is a separate workload with separate secrets and
operator access even if it uses the same immutable binary.

The runtime shape is:

```console
docker run --rm --read-only `
  --cap-drop ALL `
  --security-opt no-new-privileges=true `
  --mount type=bind,source=<approved-artifact-dir>,target=/run/socialname,readonly `
  --env SOCIALNAME_WORKER_DATABASE_URL `
  <registry>/socialname-worker@sha256:<manifest-digest> process-one `
  --site <site-id> `
  --region <worker-region> `
  --rules-dir /opt/socialname/rules/sites `
  --promotion /run/socialname/promotion.json `
  --manifest-hash <sha256> `
  --engine-hash <sha256> `
  --required-region <policy-region> `
  --previous-rule-pack-hash <active-pack-sha256> `
  --minimum-sequence-exclusive <highest-seen-sequence> `
  --key-id <trusted-key-id> `
  --verifying-key-file /run/socialname/verifying-key.hex `
  --worker-id <closed-lowercase-label> `
  --lease-seconds 60 `
  --maximum-attempts 3 `
  --expansion-limit 32 `
  --allow-live
```

First activation omits `--previous-rule-pack-hash`. The example deliberately
passes only the environment-variable name; the value must come from the
platform secret store, never the image, manifest, command line, or repository.
The production egress policy must allow only the managed PostgreSQL endpoint
and the signed rule's hosts. The engine's HTTPS, host, resolver, redirect, and
byte checks remain mandatory defense in depth.

## Termination and operator output

During an in-flight managed request, Ctrl-C or `SIGTERM` cancels the shared
token. A cancelled request cannot commit a target result; the fenced lease
expires safely for a later claimant. A hard kill has the same lease-recovery
path. Give the workload at least 15 seconds of termination grace so bounded
database cleanup can normally finish.

`process-one` writes one target-free JSON status object on success. Its normal
logs and metrics may include only status, counts, opaque job ID, attempt, rule
hash, promotion ID, region, timings, and fixed error classes. Never include a
username, normalized target, tenant-provided URL, database URL, key material,
or promotion bytes. The direct `probe` result intentionally contains a public
target and is therefore a diagnostic artifact, not ordinary service output.

## External evidence required to close the roadmap item

Keep “Deploy managed canaries and workers in the required regions” unchecked
until all of the following evidence exists:

1. An approved CI run built the reviewed source revision and the registry
   records its immutable image manifest digest.
2. Every policy-required region has an approved protected canary vantage and a
   worker workload whose scheduler and network vantage match its declared
   region.
3. The deployed worker uses the migration-tested non-owner role and cannot
   read API credentials, bypass RLS, or call undeclared coordinator functions.
4. Egress controls permit only PostgreSQL plus signed rule hosts, and a DNS,
   redirect, size, timeout, and cancellation exercise records the expected
   operational outcomes without target data in logs.
5. A production-trusted promotion for the exact image rule pack, engine,
   manifest, predecessor, sequence, and region set activates; missing,
   expired, replayed, or cross-region artifacts remain rejected.
6. A bounded canary report and a one-shot worker result are retained with
   region, source revision, image digest, rule/pack hash, promotion ID, and
   timestamps.
7. `SIGTERM` during an in-flight controlled request produces no observation or
   false account transition, and the expired lease is reclaimed once.
8. The production retention, acceptable-use, abuse, incident-response, secret
   rotation, and rollback owners have approved the deployment.

These are external observations. Repository tests and a local container build
are necessary software evidence, but cannot substitute for them.
