# Decisions: 2026-07-24

This record supersedes conflicting provisional language in `product.md`,
`architecture.md`, and `site-rules.md` until those overview documents are
integrated.

## Accepted

- The web console evaluates Topcoat first at a replaceable UI boundary.
- The public Developer API, SSE, authentication enforcement, and background
  jobs remain Axum/Tower services.
- SocialName collects rich Evidence Capsules when a versioned, purpose-specific
  consent grant permits it.
- Private history, shared observation, and shared research are separate grants.
- Contributor consent does not substitute for a lawful basis or data-subject
  process for a third-party target username.
- Shared structured Evidence Capsules have an initial 400-day retention period.
- Assertions have no independent retention and must be recomputed when support
  is deleted or expires.
- Deletion is lineage-backed, removes production data within 24 hours, and ages
  data out of encrypted backups within 35 days.
- Strict independent shared-client quorum may establish a `corroborated`
  assertion. Only eligible managed evidence can establish `verified`.
- Shared-only absence cannot trigger a disappearance notification.
- Site Rule v1 is proven against ten representative sites, including blocked
  and soft-404 cases; a correct `inconclusive` is part of acceptance.
- The Windows and macOS application uses Tauri 2 with a React/Vite presentation
  layer and the Rust engine linked directly into the process.
- Desktop webviews receive no generic HTTP, filesystem, database, or shell
  capability. Product operations cross explicit typed commands.

## Detailed records

- [Data governance](data-governance.md)
- [Assertion trust](assertion-trust.md)
- [Site Rule v1 representative validation](site-rule-v1-validation.md)
- [Site rule base design](site-rules.md)
- [System architecture](architecture.md)
- [Desktop application](desktop-application.md)

## Implementation order

1. **Partial:** Encode observation and assertion types in
   `socialname-domain`. Consent, deletion, and full Evidence Capsule types move
   into the server/data slice.
2. **Done:** Define strict Site Rule v1 source and compiled schemas.
3. **Done:** Implement deterministic fixtures for the representative ten sites.
4. **Done:** Implement the local probe engine and matcher trace.
5. **Done:** Implement assertion replay with synthetic producers and conflicts.
6. Implement PostgreSQL lineage and deletion-through tests.
7. Add managed live canaries and rule-health quarantine.
8. Build the Axum API and Topcoat monitoring-console vertical slice.
9. Add the local SQLite cache and explicit desktop source-selection policy.
