# SocialName ultimate goal

Status: **Authoritative product charter**

Accepted: 2026-07-25

## Ultimate goal

SocialName will become the infrastructure that observes the current state and
change of public identifiers across Internet services as quickly and
continuously as practical, converts those measurements into verifiable
knowledge with evidence, freshness, vantage, provenance, and uncertainty, and
enables people and systems to act on meaningful changes.

In one sentence:

> Turn public-identifier presence and change into fast, continuous,
> evidence-backed, privacy-respecting, actionable knowledge.

The long-term category is **public identifier observability**. Replacing
Sherlock with a faster and more reliable implementation is the measurement
foundation, not the destination.

## Product promise

For every supported `(public identifier, site, region policy)` key, SocialName
should be able to say:

- what was observed;
- when and from which coarse vantage it was observed;
- which engine and rule produced the observation;
- what evidence supports the verdict;
- whether the site rule was healthy;
- how fresh, corroborated, conflicted, or uncertain the answer is;
- what changed since the previous trustworthy state;
- whether an action or notification was delivered.

When the requested evidence is stale or missing, SocialName should perform the
minimum safe new work needed to satisfy the requested policy, coalesce
equivalent work, and stream partial results.

## Value system

SocialName creates value in five layers:

1. **Observe** — find public identifiers quickly with a bounded, typed,
   explainable engine.
2. **Understand** — preserve evidence, time, vantage, rule health, and
   uncertainty rather than returning an unexplained boolean.
3. **Continue** — monitor without requiring repeated manual searches and retain
   an auditable history.
4. **Act** — deliver meaningful state transitions through the API, email,
   webhooks, and team workflows without confusing measurement failure with
   account change.
5. **Learn** — improve rule health, regional knowledge, and request efficiency
   through managed canaries and explicitly consented observations.

Correctness precedes freshness; freshness precedes continuity; continuity
creates the first paid value. Coverage expands only when it can be kept
healthy.

## Product surfaces and responsibilities

### Local CLI and desktop application

The local product is a user-owned, private measurement sensor:

- useful without any SocialName service or account;
- fast local probing and streaming;
- a user-controlled SQLite observation cache;
- visible `local`, `cache`, `remote`, and `hybrid` source selection;
- independent `never`, `private`, and `shared` synchronization policies;
- inspectable evidence and reproducible machine-readable output.

The default remains local execution with `sync=never`.

### Developer API

The API is the stable infrastructure surface:

- versioned asynchronous searches and streaming results;
- explicit freshness, source, provenance, region, and uncertainty;
- idempotency, quotas, predictable errors, and webhooks;
- behavior backed by the same engine and rule pack as the local product.

The API is not a hosted boolean wrapper around the CLI.

### Monitoring product

Continuous monitoring, history, and notifications are the first paid value.
A customer pays SocialName to detect important public-identifier changes before
manual discovery, confirm them with the required evidence, and deliver them
reliably into an existing workflow.

The core paid loop is:

```text
Watch
  -> freshness-aware planning
  -> eligible observation reuse
  -> managed measurement when needed
  -> assertion derivation
  -> meaningful transition
  -> deduplicated delivery
  -> evidence and audit history
```

### Central server

The central server exists to create time, trust, coordination, and action that
one local process cannot provide efficiently:

- watch definitions, schedules, budgets, and retention;
- managed and multi-region measurements;
- immutable observations and derived assertions;
- rule registry, canaries, health, quarantine, rollout, and rollback;
- request coalescing and safe cache reuse;
- transitions, notification delivery, retry, and audit;
- authentication, organizations, entitlements, quotas, and API keys;
- consent, lineage, retention, export, and deletion guarantees.

The central server is not a public archive of everyone ever searched.

It is operated as **one multi-tenant SocialName service**. Self-hosting it is
not a product surface: managed observations, rule health, coalescing, and the
quality network create durable value only when they accumulate in a single
operated service, and fragmenting them across isolated installations would
dilute exactly the knowledge the server exists to build. The repository stays
open source, but only the operated service is a supported product.

## Trustworthy knowledge model

An observation is a measurement at a particular time and vantage. An assertion
is a replaceable interpretation derived from eligible observations. A
transition is a durable statement that the trustworthy interpretation changed.

SocialName exposes interpretable quality rather than an unexplained confidence
percentage:

- `verified`
- `corroborated`
- `single_vantage`
- `stale`
- `conflicted`
- `untrusted`

Managed strong evidence may establish `verified`. Strictly independent,
calibrated shared evidence may establish `corroborated`. Client signatures
provide source continuity, not proof that the official binary or claimed
network operation ran.

Automation or machine learning may propose rule changes, detect response drift,
cluster fingerprints, prioritize verification, and summarize evidence. It must
not replace deterministic evidence, provenance, reviewable rules, or the
ability to reproduce a verdict.

## Sustainable advantage

A static site list, high request concurrency, or one-shot hosted search is
commodity functionality. SocialName's durable advantage is the accumulated,
operational combination of:

- typed and versioned site rules;
- canary and regional rule-health history;
- time- and vantage-specific observations;
- provenance-aware assertion derivation;
- confirmed and rejected transition history;
- notification delivery and customer workflow integration;
- consented measurement diversity;
- lower third-party load through trustworthy cache reuse and work coalescing.

The moat is maintained knowledge about how to measure reliably over time, not
the nominal number of supported sites.

## North Star and guardrails

The primary product metric is **Trustworthy Coverage Time**:

> The sum of time during which monitored identifier-site keys are covered by an
> assertion that satisfies the customer's freshness and provenance policy,
> whose rule is healthy, and whose evidence is not unresolved or conflicted.

This metric rewards maintained reliability and continuity instead of cheap
search volume.

Guardrail metrics are:

- precision of conclusive `found` and `not_found` verdicts;
- false-transition and duplicate-notification rate;
- time to first result and time to requested coverage;
- transition-to-notification latency and delivery success;
- time from site-rule failure to quarantine;
- percentage of results with fresh, non-conflicting evidence;
- request coalescing and valid-cache reuse;
- watches retained and meaningful transitions reviewed;
- consent, retention, export, and deletion SLA compliance.

No coverage or revenue metric overrides the trust, safety, or privacy
guardrails.

## Non-goals and hard boundaries

SocialName will not:

- claim that matching usernames prove common ownership;
- silently upload local searches, targets, or observations;
- create a public searchable archive of all queried identifiers;
- offer or support self-hosted deployments of the managed service as a
  product;
- treat a block, timeout, login wall, or changed site as account absence;
- accuse an account of impersonation based only on string similarity;
- bypass authentication, CAPTCHA, paywalls, robots protections, or access
  controls;
- dispatch unrelated central work to ordinary CLI installations;
- store complete bodies, cookies, credentials, or unrelated profile data by
  default;
- allow arbitrary user-provided URLs or executable rule code in managed
  workers;
- let untrusted shared clients independently establish verified truth;
- optimize nominal site count at the expense of measured reliability.

## Decision filter

Every major proposal must answer:

1. Which value layer does it improve: observation, understanding, continuity,
   action, or learning?
2. Does it increase Trustworthy Coverage Time or reduce time to safe action?
3. What evidence will prove the improvement?
4. Does it preserve local usefulness and explicit privacy boundaries?
5. Does it reduce or increase false certainty and third-party load?
6. Can the operational burden and rule quality be maintained?
7. Is it part of the current roadmap milestone?

Features that add screens, nominal coverage, infrastructure, or fashionable
technology without a measurable answer should not displace the current
vertical slice.

## Product ladder

1. **Community** — open-source local CLI and desktop application, signed rules,
   local cache, and inspectable evidence.
2. **Developer** — managed search API, streaming, private history, quotas, and
   webhooks.
3. **Monitor** — scheduled watches, transitions, managed confirmation, history,
   and notifications.
4. **Team** — shared workspaces, roles, acknowledgement, audit, integrations,
   and retention controls.
5. **Quality network** — multi-region managed knowledge plus explicitly
   consented, reputation-aware shared observations.

Later extensions such as permitted username variants, namespace collision
monitoring, and human-reviewed brand protection are valid only when they retain
the same evidence and non-attribution boundaries.

## How this charter is used

This document is deliberately stable. Implementation status and sequencing
belong in `ROADMAP.md`; technical details belong in the focused design
documents. Change this charter only when product intent changes, not when a
milestone is completed or a dependency changes.
