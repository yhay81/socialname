# Data governance: consent, retention, and deletion

## Decision

SocialName will collect a rich, high-dimensional observation record when the
operator explicitly opts in. The product value comes from retaining enough
structured evidence to re-evaluate results, detect regional differences, and
measure rule drift over time.

Aggressive collection does not mean unrestricted collection. Every persisted
field must belong to a named purpose, retention class, visibility scope, and
deletion path.

These are product and engineering defaults, not a final legal conclusion.
Launch in a jurisdiction requires review of the applicable lawful bases,
notices, data-subject workflows, and third-party site terms.

## Two distinct data relationships

Do not collapse these into one consent checkbox:

1. **Contributor data** describes the CLI installation, network vantage, and
   uploaded observation. The CLI operator can consent to this contribution.
2. **Target data** describes a public username and may relate to a different
   person. Contributor consent does not become consent from that target person.

Publicly accessible identifiers can still be personal data. Shared target data
therefore remains subject to a separate purpose analysis, access and erasure
workflow, abuse controls, and an intentionally narrow product purpose:
measuring public identifier presence. SocialName does not infer common identity
merely because the same string appears on multiple sites.

The design follows the stricter baseline that consent must be specific,
demonstrable, and as easy to withdraw as to grant; retention must be limited to
the stated purpose; and erasure must propagate to recipients and derivatives
where required. See the official [GDPR Articles 5, 7, and
17](https://eur-lex.europa.eu/eli/reg/2016/679/art_17/oj/eng), the
[EDPB consent guidance](https://www.edpb.europa.eu/documents/guideline/guidelines-052020-on-consent-under-regulation-2016679_en),
and the European Commission's [information requirements
summary](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr/what-information-must-be-given-individuals-whose-data-collected_en).

## Consent grants

Consent is a versioned resource, not a boolean on the client row:

```text
ConsentGrant
  id
  subject_kind                 account | installation
  subject_id
  purpose                      private_history | shared_observation | shared_research
  collection_profile_version
  notice_version
  granted_at
  expires_at
  withdrawn_at
  source                       cli | web | api
```

Rules:

- Separate grants are required for private history, shared observations, and
  shared research diagnostics.
- Authentication, payment, `hybrid` mode, and generic telemetry consent do not
  imply any of these grants.
- The CLI shows the exact field categories, purpose, default retention, and
  deletion behavior before opt-in.
- A grant is installation-specific by default. A workspace administrator may
  set a policy, but an installation still displays it and can refuse shared
  execution.
- Changing a notice or adding a materially different purpose requires a new
  grant.
- Withdrawal stops new ingestion immediately. The operator chooses whether to
  delete prior contributions at the same time; account deletion always does.
- The server records the grant ID on every uploaded observation.

Illustrative controls:

```console
socialname consent show
socialname consent set private-history
socialname consent set shared-observation
socialname consent set shared-research
socialname consent revoke shared-observation --delete-contributions
socialname data export
socialname data delete
```

## Collection profiles

### Private history

Private history may contain the complete structured Evidence Capsule described
below. It is tenant-authorized and is never used for an account-independent
assertion unless the operator separately contributes it.

### Shared observation

The shared profile contains the target, verdict, rule identity, coarse region,
evidence class, matcher trace, response fingerprints, and bounded transport
metrics required for assertion derivation and rule health.

It excludes exact client IP, cookies, credentials, full headers, full bodies,
local filenames, process data, and unrelated telemetry.

### Shared research

This separate opt-in adds fields with high rule-improvement value:

- Source ASN and network class, but not the client IP.
- DNS/TLS/CDN classification for the target service.
- Redirect and response-template fingerprints.
- Bounded, allowlisted response headers.
- A sanitized matcher-relevant excerpt of at most 2 KiB.
- More detailed timing and failure-stage measurements.
- Shadow-classifier results for staged rule versions.

The richer profile must remain usable without storing a complete response.

## Evidence Capsule

An observation persists a versioned Evidence Capsule rather than an arbitrary
debug dump:

| Category | Examples | Shared retention |
| --- | --- | --- |
| Target | normalized username, site ID, requested namespace | 400 days |
| Provenance | producer class, pseudonymous producer ID, rule/engine hash | 400 days |
| Vantage | country/managed region, network class | 400 days |
| Transport | DNS/connect/TLS/TTFB/total buckets, outcome, byte counts | 400 days |
| HTTP | method, status, bounded redirect chain, content type | 400 days |
| Identity | canonical URL, exact returned handle, stable public object ID | 400 days |
| Match trace | matcher IDs, outcomes, evidence class | 400 days |
| Fingerprints | selected-header digest, body/DOM similarity sketch | 400 days |
| Research extension | ASN, TLS/CDN traits, sanitized excerpt | 30 days for excerpt; 400 days for non-content traits |

Exact timing values may be bucketed when precision adds fingerprinting risk
without improving the product. Exact client IP is used transiently for abuse
control and coarse derivation, then discarded from the normal observation
pipeline.

Never persist in an Evidence Capsule:

- `Cookie`, `Set-Cookie`, `Authorization`, or proxy credentials.
- Complete request or response headers.
- Complete bodies.
- Browser storage, authenticated pages, or session-derived content.
- Exact client coordinates.
- Metrics labels containing a username.
- Profile fields unrelated to proving the public identifier.

Complete response artifacts are an exceptional managed-debugging facility.
They require a ticketed purpose, encryption, access audit, a seven-day default,
and a hard 30-day maximum. Client uploads never include them.

## Initial retention schedule

Retention is measured from collection unless specified otherwise:

| Data class | Default | Allowed configuration / hard limit |
| --- | ---: | --- |
| Local SQLite cache | User controlled | User can prune or disable it |
| Private interactive observations | 90 days | 1 to 400 days |
| Private monitoring observations | 400 days | 30 to 730 days |
| Managed/shared structured Evidence Capsules | 400 days | Fixed initially |
| Shared-research sanitized excerpts | 30 days | Hard maximum 30 days |
| Exceptional complete response artifacts | 7 days | Hard maximum 30 days |
| Current assertions | No independent term | Removed or recomputed when support expires |
| Watch transitions | Watch lifetime plus 3 years | Shorter tenant policy allowed |
| Notification delivery records | 400 days | Shorter tenant policy allowed |
| Rule-health and non-personal service aggregates | 25 months | Re-evaluated before expansion |
| Consent and deletion receipts without target payload | 3 years | Security/compliance purpose only |
| Encrypted backup generations | 35 days | No restore may bypass deletion replay |

Four hundred days intentionally preserves one annual cycle plus operational
margin. Twenty-five months permits year-over-year site-health comparison. A
longer research dataset must be irreversibly aggregated or receive a separately
reviewed purpose and policy.

## Deletion guarantees

### User or workspace deletion

Deletion is a state machine with observable deadlines:

| Deadline | Guarantee |
| --- | --- |
| Immediate | Revoke grants and credentials; reject new uploads |
| 5 minutes | Hide data from all product reads and shared assertion queries |
| 1 hour | Remove affected support edges and recompute or withdraw assertions |
| 24 hours | Delete primary rows, caches, indexes, queues, and object artifacts |
| 7 days | Rebuild affected analytics and compact derived stores |
| 35 days | Age data out of encrypted immutable backups |

Restoring an older backup must first replay the deletion ledger before the
restored system can serve traffic.

Shared observations retain a source link even after they enter a common pool.
Deleting one contributor removes that contributor's observations. An assertion
may remain only when other non-deleted observations independently support it.
If the deleted contribution was the sole support, the assertion is withdrawn.

### Target-person request

A request concerning a public identifier is different from contributor
deletion. The workflow must:

1. Verify control or identity without collecting excessive new documents.
2. Resolve every normalized target key and alias in scope.
3. Restrict reads while the request is evaluated.
4. Delete eligible shared observations, assertions, excerpts, search indexes,
   and downstream exports.
5. Notify controlled recipients or processors where required.
6. Store only a keyed suppression token and non-payload receipt when needed to
   prevent immediate re-ingestion.

A suppression token is not anonymous merely because it is hashed. It is kept in
a separate restricted store, has a three-year renewable review period, and is
used only for suppression.

Private tenant records may involve a different controller, contract, legal
basis, or legal hold. The product must route those cases explicitly rather than
silently claiming that one shared-pool deletion removed every copy everywhere.

### Technical lineage

Deletion depends on first-class lineage:

```text
observation -> assertion_support
observation -> transition_basis
observation -> rule_health_sample
observation -> analytics_contribution
artifact    -> observation
export      -> search or watch
```

Every derived row records the derivation version and input IDs or a
deletion-addressable contribution bucket. Untraceable aggregates may not consume
personal observation data.

Required central tables include:

- `consent_grants`
- `consent_events`
- `data_lineage_edges`
- `deletion_requests`
- `deletion_tasks`
- `deletion_receipts`
- `suppression_tokens`

## Verification

Deletion is tested like availability:

- Daily synthetic delete-through tests create data in every store and verify
  every deadline.
- Restore drills prove that the deletion ledger is applied before serving.
- Assertion tests remove one support at a time and verify recomputation.
- Metrics report oldest overdue deletion task by store without including the
  target.
- The API returns a deletion receipt listing stores, completion times, and
  remaining backup expiry.
- New stores cannot enter production without export, lineage, retention, and
  deletion adapters.
