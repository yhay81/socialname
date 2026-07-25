# Canary manifests

This directory contains accepted
`socialname.dev/canary-manifest/v1` YAML files, one per site ID. Manifests are
time-bounded, independent of Site Rule v1, and validated against the current
compiled rule.

There are intentionally no production manifests yet. The required five
reviewed positive controls per representative site are an external evidence
gate and must not be invented from discovery notes. Consequently every current
site rule remains discovery-only.

See [`docs/canary-manifest-v1.md`](../../docs/canary-manifest-v1.md) for the
schema, validation contract, trust boundary, and CLI commands.
