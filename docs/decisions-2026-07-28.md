# Decisions: 2026-07-28

This record extends [Decisions: 2026-07-24](decisions-2026-07-24.md). The
[ultimate goal](ultimate-goal.md) remains the authoritative product charter and
[`ROADMAP.md`](../ROADMAP.md) remains the live implementation order.

## Accepted

- SocialName's managed capability is operated as **one multi-tenant hosted
  service**. Self-hosting the server, worker, and console is no longer a
  product surface, a product tier, or a documented installation path.
- Rationale: the service's durable value — managed observations, regional rule
  health, request coalescing, shared corroboration, and the quality network —
  accumulates only when every managed client uses the same service.
  Fragmenting it across isolated self-hosted islands would dilute that value
  while multiplying the support, security, and governance surface.
- The local surfaces are unaffected. The CLI and desktop application remain
  fully useful with no account and no SocialName service; `local` with
  `sync=never` stays the default. That is local-first design, not
  self-hosting.
- The repository stays open source and buildable. Anyone may still compile and
  run the server privately, but SocialName documents, supports, and evolves
  only the operated service.
- `deploy/compose.yaml` is repositioned as a **development and integration
  harness** for server, worker, migration, and console work. It is not a
  distribution, and documentation must not present it as one.
- The product page, README, and installation guide describe the monitoring
  console as part of the future hosted service rather than as a self-hosted
  install path.
- First-deployment hosting direction: managed PostgreSQL 18 (for example
  Neon) plus small managed compute for the API server and the three regional
  workers, behind the existing Cloudflare zone. Exact providers remain
  implementation decisions, not architectural commitments.
