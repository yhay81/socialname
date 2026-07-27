# Remote and remote-assisted clients

This document defines the implemented CLI and desktop boundary for managed
search. It connects the local-first client plane to the existing private search
API without adding an observation-upload route or implying that authentication
changes synchronization policy.

## Closed source and sync combinations

Source and synchronization are separate user choices. The client accepts only
combinations whose behavior is implemented:

| Source | `never` | `private` | `shared` |
| --- | --- | --- | --- |
| `local` | local cache plus a local probe | rejected | rejected |
| `cache` | strict local-cache read | rejected | rejected |
| `remote` | rejected because the target leaves the device | managed search | managed search |
| `hybrid` | local cache, then local probe | local cache, then managed search | local cache, then managed search |

`hybrid` never chooses synchronization on the user's behalf. With
`sync=never`, it remains the existing device-only cached-first flow. With
`private` or `shared`, it becomes remote-assisted: eligible local-cache
observations are emitted first, then one managed search supplies the terminal
per-target result. The current client does not upload a locally produced
observation, because `/v1/client-observations:batch` is still a designed rather
than implemented boundary.

`shared` requires an explicit CLI value or desktop selection, a
purpose-specific consent grant, and an additional desktop acknowledgement. It
does not imply common ownership between matching usernames.

## Managed transport

`socialname-app-core` owns one reusable managed-search client used by both
applications. It:

- accepts HTTPS API origins, with HTTP permitted only for localhost or a
  loopback address during development;
- rejects URL credentials, queries, fragments, non-loopback cleartext, and all
  redirects so a bearer key cannot be forwarded to another origin;
- creates a batch through `POST /v1/searches` with one UUID idempotency key and
  reuses that key for a bounded ambiguous-create retry;
- consumes the typed `search_event` SSE stream in exact sequence, validates the
  event/search IDs and protocol relations, and resumes bounded stream windows
  with `Last-Event-ID`;
- retains definitive, uncertain, and operational-failure results as distinct
  output states with their actual `private_cloud`, `shared_assertion`, or
  `managed_probe` source;
- bounds connect, request, total run, JSON body, SSE buffer, and reconnect
  work; and
- turns local cancellation into `DELETE /v1/searches/{search_id}` and reports
  an error when remote cancellation cannot be confirmed.

API errors expose only the closed error code, retryability, and retry delay.
The API key is redacted from Rust debug output and is never included in an
application error.

## Application boundaries

The CLI requires `--api-url`, `--consent-grant-id`, and an API key read from
`SOCIALNAME_API_KEY` by default. `--api-key-env` can name another environment
variable; the key itself is not a command-line argument. Human and JSON output
both show source and sync. Device-only hybrid output embeds its cache phase
before the local refresh, while managed output preserves the ordered protocol
events and an optional preceding local-cache phase.

The desktop exposes source and sync as independent controls. API origin, API
key, consent grant, and region live only in React/native command memory for the
current application session; they are not written to local storage or the
SQLite observation cache. The password field does not display the key, and
native errors do not echo it. Result cards label the actual managed source and
keep operational failure separate from absence.

The local SQLite cache remains optional and independently owned. A remote
search works when it is unavailable. A remote-assisted hybrid search may emit
an explicit unavailable or ineligible cache phase before continuing to the
managed API. If the managed request itself fails, the retained cache phase
changes from `pending` to `failed`; it is not left implying an active refresh.

## Deterministic evidence and external gates

Unit tests cover the closed policy matrix, API-key debug redaction, URL policy,
chunked SSE decoding, authenticated idempotent creation, protocol validation,
and terminal event consumption against a loopback server. CLI parser tests
cover independent source/sync and connection inputs. Rust workspace checks and
desktop TypeScript/build gates cover the shared IPC shape.

These tests do not claim a hosted SocialName deployment, production
credentials, live multi-region worker execution, production cancellation, or
production TLS/availability evidence. Those remain external gates.
