# Site rule design

## Decision

Most sites use a typed declarative HTTP rule. Site-specific executable code is
an explicit, reviewed exception.

The design preserves SocialName's original separation between common site data
and detector-specific configuration while replacing dynamic imports and
untyped option dictionaries with Rust enums and structs.

## Goals

- A contributor can understand and review one site in isolation.
- Invalid combinations fail before a rule pack is published.
- The same compiled rule runs in CLI and managed workers.
- Classification is deterministic and produces evidence.
- A missing or conflicting match becomes inconclusive, not a false positive.
- Rule changes can ship independently from the CLI binary.
- Managed workers can enforce strict network and resource boundaries.
- The schema can evolve without rewriting every rule.

## Non-goals for v1

- An arbitrary expression language.
- General JavaScript, Python, or WASM execution.
- Browser automation or CAPTCHA solving.
- Authenticated scraping using end-user sessions.
- Multi-page profile extraction and identity correlation.
- Compatibility between the internal Rust model and Sherlock's flat JSON
  representation.

Legacy manifests will be imported through a converter.

## Source, compiled form, and runtime state

Do not store all concerns in one file or database row.

### Authoring source

```text
rules/sites/github.yaml
rules/sites/gitlab.yaml
rules/sites/discord.yaml
```

The authoring format is strict YAML 1.2:

- One document per file.
- No custom tags.
- No aliases or anchors.
- No duplicate keys.
- Unknown fields rejected.
- Bounded nesting, scalar size, and total file size.

YAML is chosen for reviewability of nested match conditions. The parser is only
an authoring dependency; clients do not consume arbitrary YAML from the
network.

### Compiled rule pack

The rule compiler:

1. Parses into strongly typed source structs.
2. Applies semantic validation and normalization.
3. Compiles templates and regular expressions.
4. Produces canonical JSON.
5. Builds an index by stable site ID and tags.
6. Compresses the bundle.
7. Produces content hashes and signed update metadata.

The API and CLI identify a rule by the compiled content hash, not by a manually
maintained revision integer.

### Runtime operational state

Transient state is not committed into site YAML:

- Healthy, degraded, quarantined, or recovering.
- Region-specific success rate.
- Last positive and negative canary time.
- Current rollout percentage.
- Emergency exclusions.
- Cache freshness and assertion state.

This belongs to the central quality system and local rule-pack metadata.

## Site Rule v1 source model

The authoritative implementations are the files under `rules/sites/`. The
excerpt below illustrates the shape; omitted policy fields receive typed,
bounded defaults.

```yaml
schema: socialname.dev/site/v1

id: github
name: GitHub
homepage: https://github.com/
profile_url: https://github.com/{username:path}
namespace: person_or_organization

username:
  pattern: '^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$'
  case_sensitive: false
  normalization: lowercase

probes:
  - id: api
    http:
      method: GET
      url: https://api.github.com/users/{username:path}
      allowed_hosts: [api.github.com]
      expected_body: json
      transport_profile: api_json

plan:
  type: single
  probe: api

classification:
  blocked:
    any:
      - status:
          probe: api
          in: [403, 429]
      - transport:
          probe: api
          in: [rate_limited, timeout, connect, tls]
  found:
    all:
      - status:
          probe: api
          in: [200]
      - json:
          probe: api
          pointer: /login
          op: equals_template
          template: '{username}'
  not_found:
    all:
      - status:
          probe: api
          in: [404]
      - json:
          probe: api
          pointer: /message
          op: equals
          value: Not Found
  otherwise: inconclusive

metadata:
  enabled: false
  tags: [developer, source-code, api]
```

## Typed Rust model

The source representation should resemble:

```rust
struct SiteRuleSource {
    schema: SchemaId,
    id: SiteId,
    name: String,
    homepage: Url,
    profile_url: UrlTemplate,
    username: UsernamePolicy,
    probes: Vec<ProbeSource>,
    classification: ClassificationSource,
    metadata: SiteMetadata,
}

enum ProbeSource {
    Http(HttpProbeSource),
    Adapter(AdapterProbeSource),
}

struct HttpProbeSource {
    method: HttpMethod,
    url: UrlTemplate,
    redirects: RedirectPolicy,
    timeout: TimeoutPolicy,
    allowed_hosts: NonEmpty<HostPattern>,
    headers: BTreeMap<SafeHeaderName, Template>,
    body: Option<RequestBody>,
    expected_body: BodyPolicy,
}

enum Verdict {
    Found,
    NotFound,
    InvalidUsername,
    Inconclusive,
}
```

Source structs and compiled runtime structs should be separate. Runtime structs
contain validated URLs, compiled regular expressions, normalized header names,
and precomputed indexes, so the hot path does not repeatedly parse rule data.

## Safe templates

Raw `.replace("{}", username)` is not acceptable. Templates identify their
escaping context:

- `{username:path}` — one URL path segment.
- `{username:query}` — a query parameter value.
- `{username:subdomain}` — validated DNS label.
- `{username}` inside a typed JSON value — escaped by JSON serialization.
- `{username}` inside a typed form value — escaped by form serialization.
- `{username:raw}` — forbidden by default and requires an exceptional review.

The compiler verifies that placeholders only appear in compatible fields.

If a username contains spaces or Unicode, normalization and encoding are
explicit site policies. A rule must not silently change the username in a way
that can identify a different account.

## Probe model

### HTTP methods

Initially support:

- `GET`
- `HEAD`
- `POST`

`PUT` and other methods need a real target and a safety review before support.
The current upstream manifest uses only GET/HEAD behavior and three POST rules.

### Request bodies

Typed body variants:

```rust
enum RequestBody {
    Json(JsonTemplate),
    Form(BTreeMap<String, Template>),
    Text(TextTemplate),
}
```

Arbitrary byte bodies are unnecessary for v1.

### Redirects

Redirect policy is explicit:

- `none`
- `follow` with a bounded hop count
- `same_site`

Every redirect target is checked against the rule's allowed hosts and the
managed worker's network policy.

### Response limits

Every probe has bounded:

- DNS, connect, first-byte, and total time.
- Redirect count.
- Header bytes.
- Compressed bytes.
- Decompressed bytes.
- Matcher-inspected body bytes.

A limit violation produces an inconclusive reason, not `not_found`.

### Transport profiles

A small set of reviewed profiles can supply defaults:

- `minimal`
- `browser_like`
- `api_json`

Rules may add safe static headers, but cannot override security-sensitive
headers or include credentials. User-Agent evolution belongs to transport
profiles rather than hundreds of copied rule values.

## Matcher algebra

The classifier supports a closed set of typed matchers:

- HTTP status membership or range.
- Final URL exact/prefix/host/path match.
- Redirect location match.
- Header exact/contains/regular expression.
- Body contains/not-contains.
- Body regular expression.
- JSON Pointer value existence/equality.
- Response body length range.
- Transport outcome.
- Global or site-specific block/WAF fingerprint.

Boolean composition is structured:

```rust
enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    Status(StatusCondition),
    FinalUrl(UrlCondition),
    Header(HeaderCondition),
    Body(BodyCondition),
    Json(JsonCondition),
    Transport(TransportCondition),
    Blocked(BlockCondition),
}
```

There is no expression string to parse and no access to arbitrary runtime
objects.

### Deterministic classification

The engine evaluates the `found` and `not_found` conditions independently:

| Found condition | Not-found condition | Result |
| --- | --- | --- |
| true | false | `found` |
| false | true | `not_found` |
| false | false | `inconclusive/no_rule_matched` |
| true | true | `inconclusive/conflicting_evidence` |

Transport failure, blocking, and rate limiting prevent a definitive account
verdict unless the rule explicitly supplies independent evidence.

This differs from first-match or last-writer-wins decision lists.

## Multiple probes

The schema permits a list of named probes, but v1 should only add execution
relationships proven necessary by representative sites.

Expected forms:

- One primary probe.
- A fallback GET after HEAD returns 405 or lacks definitive evidence.
- A dedicated API probe separate from the human profile URL.
- Two independent probes whose evidence must agree.

Avoid a general workflow language. A closed execution policy enum is preferable:

```rust
enum ProbePlan {
    Single(ProbeId),
    Fallback { primary: ProbeId, fallback: ProbeId, on: FallbackReason },
    ParallelAll(Vec<ProbeId>),
}
```

## Operational failure model

Account verdict and probe failure are separate:

```rust
enum InconclusiveReason {
    Blocked,
    RateLimited,
    Timeout,
    Dns,
    Connect,
    Tls,
    RedirectRejected,
    ResponseTooLarge,
    Decode,
    SiteChanged,
    NoRuleMatched,
    ConflictingEvidence,
}
```

This enables monitoring to say “GitHub could not be measured from this region”
instead of incorrectly saying an account disappeared.

## Evidence model

Store only the evidence required to explain a verdict:

- Probe ID and method.
- Sanitized requested and final hosts/paths.
- HTTP status.
- Redirect count.
- Matcher IDs and outcomes.
- Selected header names and redacted values when necessary.
- Body matcher identifier and a bounded, sanitized excerpt or digest.
- Transport timing and failure stage.

Do not store:

- Cookies.
- Authorization headers.
- Complete response headers.
- Complete bodies by default.
- Arbitrary debug dumps from client uploads.

## Canary manifests

Canary controls do not live in a site rule. They use the independent,
time-bounded `socialname.dev/canary-manifest/v1` format described in
[`canary-manifest-v1.md`](canary-manifest-v1.md). This keeps acceptance inputs
stable while a candidate and last-known-good rule are compared.

Positive controls include at least five reviewed stable public accounts:

- An official platform account.
- A project-controlled account.
- A long-lived, highly stable account.

The manifest records the normalized username, control kind, review time, and an
HTTPS evidence reference, not copied response content.

Negative controls are generated at execution time from a typed, bounded
generator in the manifest:

- at least five candidates;
- at least 64 bits of random input;
- conformance with the compiled site's username and normalization policy;
- a bounded number of collision attempts.

If a site does not have a safely generatable negative namespace, Canary
Manifest v1 is not compatible with that site and must be revised through a
reviewed schema change rather than an arbitrary escape hatch.

Canary results are stored per managed region. A site can be:

- Healthy globally.
- Healthy only in selected regions.
- Degraded because of WAF/rate limits.
- Quarantined because classification is wrong or contradictory.

Client observations can suggest degradation but cannot automatically publish a
new rule or clear quarantine.

The evidence-driven regional transition rules are defined in
[`rule-health-v1.md`](rule-health-v1.md).

## Validation pipeline

### Static

- Strict YAML parsing.
- Rust deserialization with unknown-field rejection.
- Generated JSON Schema validation.
- Stable ID and filename match.
- URL and host policy.
- Template context validation.
- Regex compilation and size limits.
- Unique probe and matcher IDs.
- Referential integrity.
- Classifier completeness and obvious-overlap linting.
- Canary compatibility with username policy.

### Deterministic

Each matcher and site rule runs against local mock HTTP fixtures:

- Claimed response.
- Unclaimed response.
- WAF response.
- Rate limit.
- Redirect edge cases.
- Oversized and invalid encodings.
- Timeout and connection failure.

Fixtures should be minimized and redacted, not copied full pages.

### Live

- Positive canaries.
- Generated negatives.
- Multiple managed regions where useful.
- Repeated checks to distinguish intermittent failure.
- Comparison with the currently published rule.

### Publication

- Compile the entire pack.
- Run compatibility and performance tests.
- Sign staged metadata.
- Canary rollout to managed workers.
- Publish to opt-in CLI clients.
- Promote after health gates.
- Retain the last-known-good pack for rollback.

## Exceptional adapters

A site may use a built-in Rust adapter only when the declarative model cannot
represent a stable, safe flow.

An adapter:

- Implements a closed trait.
- Is compiled into the CLI and managed worker.
- Has deterministic mock tests.
- Is referenced by a typed adapter ID.
- Cannot be downloaded inside a rule pack.
- Receives the same network policy and evidence limits as HTTP rules.

Possible future examples include a necessary multi-step token exchange or a
protocol other than HTTP. No adapter should exist merely to avoid improving a
generally useful declarative primitive.

## Migration

The migration tool should:

1. Import the current SocialName JSON.
2. Import a selected upstream Sherlock manifest revision.
3. Normalize stable site IDs and preserve source attribution.
4. Convert common detector forms mechanically.
5. Mark ambiguous and invalid records for manual review.
6. Generate initial deterministic fixture requirements.
7. Never enable a converted rule solely because conversion succeeded.

Representative migration set:

- Status-only profile.
- Error-message/soft-404 profile.
- Redirect-based profile.
- Custom status code.
- Separate probe URL.
- Custom header.
- POST JSON payload.
- Strict username syntax.
- WAF-prone site.
- Site requiring an exceptional adapter.

The first schema is accepted only after this set can be expressed without
unsafe escape hatches and with clear deterministic tests.
