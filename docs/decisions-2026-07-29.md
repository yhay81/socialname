# Decisions: 2026-07-29

This record extends [Decisions: 2026-07-28](decisions-2026-07-28.md), which
committed to one operated multi-tenant service. It concretizes the domain and
the hosting providers under an explicit lowest-cost posture.

## Accepted

- **`socialname.net` is the product domain.** The product page serves at
  `https://socialname.net/` and the service origin is `api.socialname.net`.
  The original `socialname.yhay81.com` custom domain stays attached so
  existing links keep resolving.
- **Exactly two providers host the first deployment: Neon and Cloudflare.**
  - Neon provides managed PostgreSQL 18 with direct (non-pooler)
    connections. TLS is mandatory on that path, so the workspace `sqlx`
    dependency now enables `tls-rustls-ring`, matching the engine's existing
    rustls stack.
  - Cloudflare provides DNS, TLS, the static product page, and — on the
    Workers Paid plan — Containers that run the published server and worker
    OCI images. R2 remains available later for encrypted evidence artifacts.
- **Lowest-cost posture: scale to zero everywhere.** The API server container
  sleeps between requests; managed workers run as scheduled one-shot
  `process-one` invocations rather than polling daemons, which also lets the
  Neon compute suspend between runs. Nothing in the current workload shape
  requires an always-on process, and the expected steady cost is on the
  order of five to ten US dollars per month before real usage.
- **Initial managed regions come from Cloudflare's container set** (ENAM,
  WNAM, EEUR, WEUR). Three distinct regions from that set satisfy the
  three-region canary requirement; an APAC vantage is explicitly deferred
  and, when required, will be added as one small machine elsewhere rather
  than by abandoning this posture.
- Open question, to resolve when the canary phase starts: the canary
  workflows require region-labelled GitHub Actions self-hosted runners,
  which do not map cleanly onto sleeping containers. Either a runner runs
  inside a scheduled container, or the canary execution path is amended with
  equivalent budgets and vantage labels before any live canary runs.
