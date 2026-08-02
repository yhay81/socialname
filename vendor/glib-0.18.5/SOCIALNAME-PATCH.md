# SocialName glib 0.18.5 patch provenance

This directory is the published `glib` 0.18.5 crate with one upstream
soundness fix applied. It is used only by Tauri v2's Linux GTK3 dependency
chain.

- Original crate:
  `https://static.crates.io/crates/glib/glib-0.18.5.crate`
- Original SHA-256:
  `233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`
- Advisory: `RUSTSEC-2024-0429` / `GHSA-wrw7-89jp-8q8g`
- Upstream fix: gtk-rs/gtk-rs-core pull request 1343, commit
  `b5a40716c6017e086a7fbc01c39e5d15af28ac01`
- 0.18 backport: gtk-rs/gtk-rs-core pull request 2009, commit
  `ea720152f28e293ef4362ee844ee5cc499f32d2a`

The only source change makes the C out-argument pointer mutable in
`glib/src/variant_iter.rs`: `let p` becomes `let mut p`, and `&p` becomes
`&mut p`. This is byte-identical to the proposed upstream 0.18 backport.

Remove the `[patch.crates-io]` entry and this directory as soon as Tauri's
dependency graph resolves to a published fixed `glib` release. Do not add
unrelated changes to this vendored source.
