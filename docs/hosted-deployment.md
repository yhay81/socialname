# First hosted deployment runbook

Status: **Path defined; no hosted deployment exists yet**

The managed capability ships as one operated multi-tenant service
([decision](decisions-2026-07-28.md)). This runbook turns that decision into
an ordered, checkable path from the published container images to the external
evidence gates in
[Regional managed-worker deployment boundary](regional-worker-deployment.md).
Nothing in this document claims that any step has been performed; evidence
belongs in [`ROADMAP.md`](../ROADMAP.md) when it exists.

## Provider evaluation

### Database

The server and worker require managed PostgreSQL 18: the embedded migrations,
forced tenant RLS, non-owner `NOBYPASSRLS` roles, `FOR UPDATE SKIP LOCKED`
job claims, and advisory-lock serialization are PostgreSQL semantics that the
PostgreSQL 18 integration gate tests directly.

- **Cloudflare D1 is not eligible.** D1 is SQLite. Adopting it would abandon
  the tested PostgreSQL boundary and rewrite the persistence layer.
- **Cloudflare Hyperdrive is not a database.** It is a connection
  pooler/cache in front of an external PostgreSQL, usable from Workers. The
  native Axum server holds its own SQLx pool, so Hyperdrive adds nothing on
  this path.
- **Neon (serverless PostgreSQL) is the leading candidate.** PostgreSQL 18 is
  supported, pricing is usage-based, and roles can be created with plain SQL.
  Use the **direct connection string, not the pooler**, for both server and
  worker: forced RLS with transaction-local settings, advisory locks, and
  `SKIP LOCKED` should not sit behind transaction pooling. Scale-to-zero is
  neutralized by scheduler polling, so estimate compute as always-on.

Any managed PostgreSQL 18 with role creation and direct connections is an
acceptable substitute; the choice remains an implementation decision.

### Compute

- **Cloudflare Containers** can run OCI images and pin placement, but its
  regions are currently ENAM, WNAM, EEUR, and WEUR only. The canary gate
  needs three managed regions with declared vantages, and an APAC vantage is
  desirable, so Containers alone cannot host the worker fleet today.
- **Small always-on machines** (for example Fly.io, or equivalent) fit the
  API server and the per-region workers. Regional canary runners can share
  the worker hosts as GitHub Actions self-hosted runners with region labels.
- **Cloudflare stays in front**: DNS, TLS, and the product page use the
  existing `yhay81.com` zone; R2 is available later for encrypted evidence
  artifacts.

## Image source

Every push to `main` publishes verified images with immutable digests
recorded in the Quality run summary:

- `ghcr.io/yhay81/socialname-server` — API server with the same-origin
  monitoring console.
- `ghcr.io/yhay81/socialname-worker` — signed-metadata-only managed worker.

Deployments must pin the manifest digest, never a mutable tag.

## Ordered path

1. **Operator accounts and secrets (human).** Create the database project
   (PostgreSQL 18) and the compute account. Add `CLOUDFLARE_API_TOKEN` and
   `CLOUDFLARE_ACCOUNT_ID` repository secrets so the product page deploys on
   push. No credential is ever committed.
2. **Schema.** Run `socialname-server migrate` against the schema-owner URL.
3. **Runtime roles.** Provision the non-owner application and worker roles
   with the same column-limited grants the PostgreSQL 18 integration test
   applies. Those grants currently live only in
   `crates/socialname-server/tests/postgres_migrations.rs`; extracting them
   into an audited operator command is the next repository-completable item
   so production roles cannot drift from the tested ones.
4. **API server.** Deploy the server image by digest with the application
   role URL and `SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX` from the platform
   secret store, behind Cloudflare TLS on the chosen origin
   (`api.socialname.yhay81.com` unless branding decides otherwise). The
   console is served on the same origin. Run `bootstrap-workspace` for the
   first workspace and key. At this point the service is a hosted API with
   zero promoted rules: searches are accepted, no probe executes.
5. **Regional workers.** Deploy the worker image by digest to three regions
   with the worker role URL, egress restricted to PostgreSQL plus signed rule
   hosts, and the read-only metadata/trust artifacts described in the
   deployment boundary.
6. **Canary evidence and promotion.** Stand up region-labelled self-hosted
   runners, author reviewed canary manifests (start with two or three sites,
   not ten), pass the 24-hour three-region gate, perform the threshold-key
   ceremony, and promote the first rules.
7. **Delivery and governance.** Email gateway, webhook destination
   verification, retention/deletion schedules, acceptable-use and abuse
   response, then billing reconciliation once value is proven.

Steps 2–5 are mechanical once step 1 exists; step 6 contains the real elapsed
time and human review. The indicative running cost of the minimal always-on
posture (database, one API machine, three worker machines) is a few tens of
US dollars per month.
