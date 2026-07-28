# Product page

The public product page for <https://socialname.yhay81.com>, deployed to
Cloudflare Workers static assets by
[`.github/workflows/site.yml`](../.github/workflows/site.yml).

`public/` is the entire site. It is plain HTML and CSS with no build step, no
bundler, and no third-party request at runtime, so what is committed is
exactly what is served. The workflow's verification job fails if a page ever
references an external script, stylesheet, font, or an asset that is not
committed here — a page that claims to run no analytics must not be able to
quietly acquire one.

## Local preview

```bash
python -m http.server 8123 --directory web/public
# then open http://127.0.0.1:8123/
```

## Validate the deployment configuration

```bash
npx wrangler deploy --dry-run --config web/wrangler.jsonc
```

The dry run resolves the asset directory and type-checks the configuration
without contacting the account.

## First-time Cloudflare setup

Deployment is skipped with a notice until both repository secrets exist, so
the checks still run in a fork or an unconfigured clone.

1. In the Cloudflare dashboard, create an API token with **Edit Cloudflare
   Workers** permission for the account, plus **Zone → DNS → Edit** on the
   `yhay81.com` zone so the custom domain record can be created.
2. Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as repository
   secrets.
3. Push a change under `web/`. The first successful deployment creates the
   `socialname-site` Worker and attaches the `socialname.yhay81.com` custom
   domain declared in `wrangler.jsonc`; Cloudflare provisions the DNS record
   and the certificate.

## Content rules

The page describes only what this build actually does. Site counts, evidence
classes, and example output are taken from real runs, and the limits section
states the unsigned builds, the unvalidated site rules, and the absence of a
hosted service rather than leaving a user to discover them after installing.
