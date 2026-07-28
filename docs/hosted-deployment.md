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
- **Neon is the decided database provider
  ([2026-07-29](decisions-2026-07-29.md)).** PostgreSQL 18 is supported,
  pricing is usage-based with a free tier, and roles can be created with
  plain SQL. Use the **direct connection string, not the pooler**, for both
  server and worker: forced RLS with transaction-local settings, advisory
  locks, and `SKIP LOCKED` should not sit behind transaction pooling. Neon
  requires TLS, so the workspace `sqlx` dependency enables
  `tls-rustls-ring`.
- Under the scheduled one-shot worker model below the database can suspend
  between runs, so the free tier's compute allowance is the honest starting
  point; an equivalent managed PostgreSQL 18 would be reconsidered only if
  Neon cannot meet a gate.

### Compute — Cloudflare Containers (decided 2026-07-29)

- Containers run the published OCI images on the Workers Paid plan:
  $5/month including 25 GiB-hours of memory, 375 vCPU-minutes, and 200
  GB-hours of disk, with CPU billed on active usage only. A sleeping
  container costs nothing.
- The API server runs as a small (`lite`, 256 MiB) container that sleeps
  between requests. Managed workers run as scheduled one-shot `process-one`
  invocations driven by the Container `schedule()` API or a cron Worker,
  which is exactly the documented one-shot workload model.
- Placement regions are currently ENAM, WNAM, EEUR, and WEUR. Three distinct
  regions from that set satisfy the three-region canary requirement; an
  APAC vantage is deferred and would later be one small machine elsewhere
  without changing this posture.
- Container images deploy through Cloudflare's managed registry via
  wrangler, fed from the digest-pinned GHCR images Quality publishes.
- Open question for the canary phase: region-labelled GitHub Actions
  self-hosted runners do not map cleanly onto sleeping containers; resolve
  it per the 2026-07-29 decision record before any live canary run.
- **Cloudflare stays in front**: DNS, TLS, and the product page use the
  `socialname.net` zone (`socialname.yhay81.com` stays attached for existing
  links); R2 is available later for encrypted evidence artifacts.

## Image source

Every push to `main` publishes verified images with immutable digests
recorded in the Quality run summary:

- `ghcr.io/yhay81/socialname-server` — API server with the same-origin
  monitoring console.
- `ghcr.io/yhay81/socialname-worker` — signed-metadata-only managed worker.

Deployments must pin the manifest digest, never a mutable tag.

## Ordered path

1. **Operator accounts and secrets (human).** Add the `socialname.net` zone
   to the Cloudflare account, subscribe to Workers Paid, create the Neon
   project (PostgreSQL 18), and add the `CLOUDFLARE_API_TOKEN` and
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
   secret store, behind Cloudflare TLS on `api.socialname.net`. The
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
time and human review. The indicative running cost of the chosen
scale-to-zero posture is on the order of five to ten US dollars per month
before real usage: the Workers Paid base fee plus small overages, with the
database inside its free or low usage tier.
