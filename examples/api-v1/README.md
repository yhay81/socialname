# SocialName API v1 examples

These dependency-free Node.js 24 examples cover the two integration paths that
need behavior beyond generated REST calls: resumable SSE and paginated private
history export. They use only the committed API v1 contract and do not claim a
hosted service origin.

Set the API origin and a purpose-scoped key in the process environment. HTTP is
accepted only for a loopback origin; all other origins must use HTTPS. The key
is never accepted on the command line.

Create a managed search by piping a `SearchCreateRequest` JSON document on
stdin:

```powershell
$env:SOCIALNAME_API_URL = "http://127.0.0.1:8787"
$env:SOCIALNAME_API_KEY = "<search:read,search:write key>"
Get-Content -Raw .\request.json |
  node .\examples\api-v1\create-and-stream.mjs
```

The example creates one random idempotency key unless
`SOCIALNAME_IDEMPOTENCY_KEY` is set, prints the accepted resource, resumes
normal 30-second SSE closures with `Last-Event-ID`, deduplicates event UUIDs,
requires ascending sequence numbers, and stops only on `finished`.

List all tenant-local search-history pages:

```powershell
'{"action":"history"}' |
  node .\examples\api-v1\history-and-export.mjs
```

Export all immutable pages of one terminal search:

```powershell
'{"action":"export","search_id":"<search UUID>"}' |
  node .\examples\api-v1\history-and-export.mjs
```

History requires `search:read`. Export independently requires `data:export`
and returns conflict until the search is terminal. Output is JSON Lines so a
caller can stream it to an access-controlled destination without accumulating
the complete history in memory. The output contains requested usernames and
evidence-bearing events and must be handled as sensitive product data.

Run the deterministic local tests with:

```console
node --test examples/api-v1/client.test.mjs
```
