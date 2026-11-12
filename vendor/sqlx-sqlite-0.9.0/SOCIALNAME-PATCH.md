# SQLx SQLite driver patch

This is the published SQLx 0.9.0 SQLite driver. Its Rust sources are unchanged.
The build manifest raises the upper bound on `libsqlite3-sys` from `<0.38.0`
to `<0.40.0`, matching the bound accepted in
[SQLx PR 4502](https://github.com/transact-rs/sqlx/pull/4502)
(commit `10462fa4414c6c7f1ed1d39bb31678e3b726878c`).
The workspace locks `libsqlite3-sys` to 0.39.1, which bundles SQLite 3.54.1
and fixes the mismatched WAL page-size vulnerability
[RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html).

The [original crate](https://static.crates.io/crates/sqlx-sqlite/sqlx-sqlite-0.9.0.crate)
has SHA-256 `488e99c397a62007e4229aec669a179816339afc6d2620ca6fa420dbee2e982c`.
`Cargo.toml.orig` preserves the upstream manifest. The upstream standalone
lockfile is omitted. The license files contain the full license texts from
the source revision in `.cargo_vcs_info.json`, replacing the archive's
relative-path references.

Remove this directory and its workspace patch when a published SQLx release
supports a fixed bundled SQLite. [SQLx issue 4516](https://github.com/transact-rs/sqlx/issues/4516)
tracks that release.
