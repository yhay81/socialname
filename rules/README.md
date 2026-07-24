# Site Rule v1

`sites/` contains strict, human-reviewed YAML source. `fixtures/` contains
minimal offline response examples that prove classification behavior without
contacting third-party services.

Validate both:

```console
cargo run -p socialname-cli -- rules validate
cargo run -p socialname-cli -- fixtures
```

A rule with `metadata.enabled: false` is discovery-only. It must pass fixtures
but is excluded from ordinary live CLI searches until managed positive and
negative canaries satisfy the acceptance gate in
`docs/site-rule-v1-validation.md`.

Important invariants:

- Unknown fields, unsafe YAML features, invalid references, and oversized
  expressions fail compilation.
- URL placeholders declare their escaping context.
- Every request and redirect remains HTTPS and inside `allowed_hosts`.
- `found` and `not_found` conditions are evaluated independently.
- A block, rate limit, transport failure, or ambiguous response is
  `inconclusive`; it is never silently converted to absence.
- Fixtures are minimized evidence fragments, not archived third-party pages.
