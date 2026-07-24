# Product vision and value

## Product statement

SocialName provides fast, evidence-backed knowledge about the presence of a
public username across Internet services and how that presence changes over
time.

The free product is a local-first CLI. The cloud product adds managed
execution, a stable developer API, continuous monitoring, history, and
notifications.

The long-term category is **public identifier observability**, not merely
username enumeration.

## Users and jobs

### CLI users

Security practitioners, developers, journalists, researchers, and individuals
need to answer:

- Where does this public username currently appear?
- Which answers are fresh and which are uncertain?
- Can I run the search without disclosing the target to SocialName?
- Can I reproduce or inspect the evidence behind the verdict?

They value privacy, installation simplicity, speed, transparent output, and
scriptability.

### API developers

Developers integrating username search need:

- A stable, versioned schema.
- Asynchronous batch searches with streaming partial results.
- Explicit freshness, provenance, and uncertainty.
- Idempotency, quotas, predictable errors, and webhooks.
- Consistent results between local testing and production.

They value reliability more than the raw number of nominally supported sites.

### Monitoring customers

Individuals and teams protecting a public identity, product, or brand need:

- A watchlist of exact and permitted variant usernames.
- Detection when an account appears, disappears, or changes state.
- Evidence and timestamps suitable for review and escalation.
- Deduplicated email, webhook, and collaboration notifications.
- A history of what was observed, where, and with which rule.
- Team ownership, audit logs, and retention controls.

They are paying for continuous maintenance and timely state transitions, not
for one HTTP scan.

## Value hierarchy

SocialName should build value in this order:

1. **Correctness** — avoid false positives and explain uncertainty.
2. **Freshness** — state when and where an answer was observed.
3. **Continuity** — detect changes without requiring repeated manual searches.
4. **Coverage** — expand sites only when their rules can be kept healthy.
5. **Workflow** — API, webhooks, teams, exports, and case history.
6. **Network effects** — use consented observations to improve site health,
   regional knowledge, and cache efficiency.

The moat is the combination of versioned rules, health history, observations,
and state transitions. A large static site list is not a moat.

## CLI execution model

The CLI must make the source of every answer visible. Four execution modes are
proposed:

| Mode | Reads | Performs live probes | Sends target to SocialName | Typical use |
| --- | --- | --- | --- | --- |
| `local` | Local cache | On the user's machine | No | Default private search |
| `cache` | Local cache and permitted cloud cache | No | Only if cloud cache is enabled | Fast, no-new-probe lookup |
| `remote` | Private cloud and managed cache | On managed workers | Yes | Stable server vantage/API parity |
| `hybrid` | Local, private cloud, and eligible shared assertions | Locally for stale/missing results | Yes | Fastest complete interactive search |

Illustrative commands:

```console
socialname search alice
socialname search alice --mode cache --max-age 30m
socialname search alice --mode remote --region jp
socialname search alice --mode hybrid --sync private
```

The default is equivalent to:

```console
socialname search alice --mode local --sync never
```

No installation should upload search targets or results until the user signs in
and makes a deliberate choice.

### Result synchronization

Execution and synchronization are independent:

| Sync policy | Behavior |
| --- | --- |
| `never` | No observation or target is sent to SocialName |
| `private` | Observations are stored in the user's private workspace |
| `shared` | Eligible, minimized observations may contribute to the shared pool |

`shared` is explicit opt-in. It is not implied by `hybrid`, telemetry consent,
authentication, or payment.

The active mode and sync policy must be shown in normal CLI output and machine
readable results.

### Source and freshness in output

Every site result should include:

- `source`: `local_cache`, `local_probe`, `private_cloud`,
  `shared_assertion`, or `managed_probe`.
- `observed_at` and `expires_at`.
- `region`, at a deliberately coarse level.
- `rule_version` and `rule_hash`.
- `verdict`, uncertainty reason, and evidence summary.

Cached results must never be presented as if they were live.

## Cache hierarchy

There are four distinct stores:

1. **Local cache** — SQLite on the user's machine.
2. **Private cloud store** — observations visible only to a user or workspace.
3. **Managed observation pool** — results from SocialName-operated workers.
4. **Shared client observation pool** — minimized opt-in contributions.

The global answer is not a row that the latest writer can replace. Shared and
managed observations feed a derived assertion with provenance.

Cache reuse is valuable because it:

- Makes repeated searches nearly instantaneous.
- Reduces traffic sent to third-party sites.
- Lowers managed scan cost.
- Allows history and regional comparison.
- Gives monitoring a natural baseline.

Cache reuse is dangerous when it:

- Hides stale data.
- Leaks who or what a user searched.
- Treats a result from one country as globally true.
- Allows a modified client to poison shared results.
- Retains public-identifier searches longer than users expect.

Freshness therefore varies by site, verdict, rule version, and purpose. A
`not_found` assertion may deserve a shorter lifetime than `found`; a monitoring
customer may request a fresh managed probe even when an interactive lookup
would accept cached data.

## Client-contributed observations

Client observations can create genuine network effects:

- Reveal sites that behave differently by region or network.
- Detect rule degradation before scheduled canaries do.
- Reduce duplicated probes.
- Expand visibility beyond cloud-provider IP ranges.

They must not be treated as trusted truth:

- An installation key identifies a source but cannot prove the binary was not
  modified.
- A client can fabricate HTTP status, body matches, timing, and location.
- Many malicious clients can create a Sybil attack.
- Raw responses can contain cookies, tokens, IP addresses, or personal data.

Initial policy:

1. Private client observations are accepted as the user's own record.
2. Shared client observations are hints and corroborating evidence.
3. One client observation cannot change a shared assertion. A strict quorum of
   independently grouped calibrated clients may establish `corroborated`
   state, never `verified`.
4. Shared-only absence cannot trigger a disappearance notification.
5. Conflicts and high-value candidate transitions trigger a managed probe when
   policy and quota permit.
6. Eligible managed observations may establish `verified` state while
   controlled canaries establish rule health.
7. Source reputation may reduce verification work later, but never replaces
   provenance.

### The CLI must not become an implicit botnet

Normal CLI installations only run searches initiated by their local user.
The central server must not silently dispatch unrelated work to them.

If a community measurement network is ever justified, it must be a separate,
explicitly operated mode or daemon with:

- Informed opt-in and a clear operator agreement.
- Target allowlists and transparent job history.
- Resource, bandwidth, and schedule limits.
- Immediate pause and removal controls.
- No bypass of authentication, CAPTCHA, or access controls.
- Separate credentials and data policy.

This is not part of the first product.

## Monitoring product

A watch contains:

- One or more exact public usernames.
- A selected site set.
- Allowed regions or vantage policy.
- Required maximum age.
- Schedule and budget.
- Notification destinations.
- Retention and visibility policy.

The monitoring loop is:

1. Plan only the probes needed to satisfy freshness.
2. Reuse eligible observations.
3. Coalesce identical live work across watches.
4. Produce new observations.
5. Derive the current assertion.
6. Compare it with the previous assertion.
7. Persist a transition only when meaningful state changes.
8. Notify once, with retries and delivery audit.

Useful transition types include:

- `not_found -> found`
- `found -> not_found`
- `found -> inconclusive`
- `healthy -> degraded` for the site rule
- Material profile URL or identifier changes when extraction is supported

Notifications should distinguish account changes from measurement-system
degradation. A site becoming blocked is not the same event as an account being
removed.

## Product tiers

### Community

- Open-source local CLI.
- Embedded and signed rule pack.
- Local SQLite cache.
- JSON/JSONL/CSV output.
- No account required.

### Developer

- Managed search API.
- Private cloud history.
- Streaming results and webhooks.
- Batch and site-selection controls.
- Usage quotas and service-level reporting.

### Monitor

- Scheduled watches.
- Transition history.
- Email and webhook notifications.
- Freshness policies and regional confirmation.
- Evidence retention controls.

### Team

- Shared workspaces and role-based access.
- Audit logs.
- Review and acknowledgement workflow.
- Organization-wide API keys, quotas, and retention.
- Optional integrations with collaboration and incident systems.

Brand impersonation and variant monitoring are promising later extensions, but
must not be described as proven impersonation from username similarity alone.
They require profile evidence and human review.

## Metrics

### Product quality

- Precision of `found` and `not_found` on healthy canaries.
- Percentage of enabled rules passing all current canaries.
- Median time from rule breakage to quarantine.
- Percentage of results carrying fresh, non-conflicting evidence.
- False transition and duplicate-notification rates.

### Performance

- CLI startup overhead.
- Time to first result.
- Time to requested coverage threshold.
- Cache hit rate by source and freshness class.
- Managed probe request coalescing ratio.
- Target-site requests avoided through valid cache reuse.

### Commercial

- API integrations that reach recurring production use.
- Watches retained after the first month.
- Monitored targets with at least one meaningful transition.
- Notification acknowledgement or webhook success rate.

The number of searches is not sufficient by itself; a product can generate many
cheap searches while producing little durable value.

## Product boundaries

SocialName should not initially provide:

- A public searchable archive of all queried usernames.
- Hidden upload of CLI searches or observations.
- Arbitrary central-server jobs executed by ordinary CLI installations.
- Claims that identical usernames prove a common owner.
- Automatic impersonation accusations based only on string similarity.
- Authentication, CAPTCHA, paywall, or anti-bot bypass.
- Storage of complete HTTP bodies by default.
- User-supplied arbitrary URLs executed by managed workers.
