# Site Rule v1 representative validation

## Purpose

Site Rule v1 is accepted only when one closed declarative schema can represent
ten materially different, high-value sites without arbitrary code or unsafe
escape hatches.

The ten-site set intentionally contains easy, structured, soft-404,
federated, oversized, rate-limited, and anti-bot cases. A correct
`inconclusive` or regional quarantine is a successful proof for a blocked site;
forcing every site to return a boolean would invalidate the design.

## Discovery run

A single discovery pass was performed on 2026-07-24 from the current
development vantage. It used one official or project account and one
high-entropy candidate username per site, no authentication, no CAPTCHA
bypass, a descriptive User-Agent, and at most one request per URL.

This pass discovers response shapes; it does not certify a production rule.

| Site | Positive / negative discovery | v1 capability being proved | Initial disposition |
| --- | --- | --- | --- |
| GitHub | Public API returned structured identity for `github`; profile negative returned `404`; one profile positive timed out | API JSON identity, status fallback, timeout separation | Candidate after paired API recheck |
| GitLab | API returned `200` with one exact user versus `200 []` | JSON array cardinality and exact-field match | Strong candidate |
| Reddit | Both requests returned the same `403` response class | WAF/block fingerprint; never infer absence from a block | Region degraded/inconclusive |
| npm | Known account returned `403`; negative returned `404` | Asymmetric WAF behavior and one-sided evidence | Not-found may be evidence; found remains inconclusive in this vantage |
| Docker Hub | Known namespace returned `200` and redirected from `/users/` to `/orgs/`; negative returned JSON `404` | Bounded cross-path redirect, structured JSON, user/org namespace distinction | Candidate with explicit `namespace_kind` |
| Bluesky | Public XRPC returned exact handle plus DID with `200`; negative returned typed JSON `400` | Structured identity, stable public ID, typed error | Strong candidate |
| Mastodon.social | WebFinger returned JRD `200`; negative returned `404` | Federated `acct:` query template and JSON/JRD identity | Strong candidate |
| Steam Community | Existing and missing vanity URLs both returned `200` with different body templates | Soft-404 matcher, bounded body fingerprint, canonical identity marker | Fixture and repeated live proof required |
| YouTube | Official handle returned `200` with a very large document; negative returned small `404` | Streaming body limit, early marker extraction, status plus canonical identity | Candidate only if it avoids full-body download |
| X | Official/project profile returned `200`; negative returned `404` in this vantage | Status and canonical identity under anti-bot drift | Region-conditional candidate with strong block detection |

The discovery confirms why the legacy `status_code`, `message`, and
`response_url` split is insufficient. The engine needs a typed matcher algebra,
multi-signal evidence, explicit block classification, bounded streaming, and
separate account and transport verdicts.

## Implemented v1 rule shapes

The ten source rules now live in `rules/sites/`; their minimized response cases
live in `rules/fixtures/`. The descriptions below remain the design rationale.

### GitHub

- Primary probe: `GET https://api.github.com/users/{username:path}`.
- Found: `200`, JSON `/login` equals normalized username, and `/id` exists.
- Not found: `404` with the reviewed API error shape.
- Rate limit or API policy response: inconclusive.
- Optional profile probe supplies the human-facing URL but does not override API
  evidence.

### GitLab

- Probe: `GET https://gitlab.com/api/v4/users?username={username:query}`.
- Found: array contains exactly one active entry whose `/username` equals the
  normalized target.
- Not found: empty array.
- Multiple non-identical entries, block HTML, or invalid JSON: inconclusive.

### Reddit

- Preferred probe remains a reviewed public profile or public JSON endpoint.
- A generic `403`, rate-limit page, or matching positive/negative response
  fingerprint is `Blocked`, never `not_found`.
- The rule is enabled only in regions where both canaries are conclusive.

### npm

- A `404` on the account-specific route may support absence after positive
  controls establish route health.
- `403` cannot support found or not found.
- A future site-owned structured endpoint is preferred over depending on the
  Cloudflare-facing HTML route.

### Docker Hub

- The rule models a claimed Docker namespace, not silently a human user.
- A bounded redirect from `/v2/users/{name}/` to `/v2/orgs/{name}` is allowed
  and records `namespace_kind=organization`.
- Found requires the returned namespace name to equal the target.
- JSON `404` is not found; authentication or throttling responses are
  inconclusive.

### Bluesky

- Probe the public XRPC `app.bsky.actor.getProfile`.
- Found requires exact `/handle` plus a syntactically valid `/did`.
- A reviewed `400` actor-not-found error is not found.
- Handle/DID disagreement is conflicting evidence, not an automatic redirect.

### Mastodon.social

- Probe WebFinger with
  `resource=acct:{username}@mastodon.social`.
- Found requires a JRD `subject` equal to the normalized account and a valid
  self/profile link.
- A route-specific `404` is not found.
- This rule proves query escaping and federated account normalization.

### Steam Community

- Both states may return `200`.
- Found requires an exact canonical vanity URL or stable profile identity
  marker.
- Not found requires the reviewed missing-profile marker and negative-template
  fingerprint.
- Body scanning stops after the required marker or inspection limit.

### YouTube

- Probe the handle route with a strict compressed, decompressed, and inspected
  byte budget.
- A route-specific `404` supports not found.
- Found requires `200` plus an early canonical handle or channel identity
  marker; downloading a multi-megabyte page only to classify it is rejected.
- Consent to shared research does not relax the body limit.

### X

- Found requires `200` plus a canonical identity marker for the requested
  handle.
- Route-specific `404` supports not found only while positive controls are
  healthy.
- Login walls, challenge pages, throttling, and generic app shells are
  `Blocked`.
- Health and assertions are region-specific when response classes differ.

## Schema requirements demonstrated by the set

The ten rules require v1 to support:

- Path and query templates with contextual escaping.
- Exact username/handle normalization per site.
- HTTP status, final URL, content type, and bounded redirects.
- JSON Pointer equality, existence, typed errors, and array cardinality.
- Body contains and safe regular-expression matching.
- Bounded body/DOM fingerprint matching for soft 404s.
- Stable public identity extraction separate from profile content collection.
- Explicit WAF, CAPTCHA, rate-limit, timeout, and oversized-response outcomes.
- Streaming early termination after sufficient evidence.
- Account namespace kind such as person, organization, or federated account.
- Evidence-class assignment and a deterministic matcher trace.

No rule needs downloaded executable code, arbitrary expressions, browser
automation, authentication, or a complete response body.

## Fixture matrix

Every representative rule must include minimized fixtures for:

- Known found.
- Known not found.
- Generic `200`/soft 404.
- WAF or CAPTCHA.
- Rate limit.
- Redirect within and outside the allowlist.
- Timeout at DNS, connect, first byte, and body stages.
- Invalid or changed JSON.
- Oversized compressed and decompressed responses.
- Reflected target string that is not identity evidence.
- Conflicting found and not-found matchers.

Fixtures retain only the minimum headers, structured fields, and body fragments
needed to reproduce classification.

## Live acceptance gate

A rule is globally enabled only after:

1. Static schema, security, and fixture tests pass.
2. At least five reviewed positive canaries and five generated negative
   canaries are valid under the username policy.
3. Three managed regions run each canary at least three times across a 24-hour
   interval.
4. Conclusive canary precision is 100% in the acceptance sample.
5. Conclusive coverage is at least 95% in every enabled region.
6. No block, timeout, generic template, or limit fixture produces a conclusive
   account verdict.
7. The p95 probe completes within the site's reviewed timeout and respects
   byte budgets.
8. A staged rule runs in shadow mode beside the last-known-good rule before
   promotion.

A site may be enabled only for specific regions. Reddit and npm are expected to
prove quarantine and recovery behavior even if the initial development vantage
cannot produce both definitive states.

## Deliverables for the implementation slice

- **Done:** Ten strict YAML source files.
- **Done:** Generated JSON Schema for `socialname.dev/site/v1`.
- **Done:** Deterministic canonical rule-pack hashing.
- **Done:** Thirty deterministic minimized responses with matcher traces.
- **Done:** Independent typed `socialname.dev/canary-manifest/v1` source,
  semantic validation, JSON Schema, and canonical hashing.
- **Done:** A production-engine live canary runner with per-site and per-region
  request, concurrency, wall-time, and inspected-byte budgets.
- **Done:** A privacy-bounded versioned report showing precision, conclusive
  coverage, latency, bytes, response classes, and conflicts, with expiry,
  content-integrity, duplicate, and ingestion-policy validation.
- **Done:** Deterministic aggregation across runs and managed vantages with the
  24-hour interval, three-run, 100% precision, 95% conclusive coverage,
  zero-conflict, and reviewed-p95 gates evaluated per region.
- **Done:** Same-private-target shadow execution between candidate and
  last-known-good rules under a combined request, concurrency, time, and byte
  budget, with typed precision, coverage, conflict, and per-case regression
  rejection.
- **Next:** Explicit rule-health states and safe quarantine/recovery
  transitions.
- **Next:** Signed pack publication and a last-known-good rollback
  demonstration.
