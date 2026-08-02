const WORKSPACE_MANIFEST: &str = include_str!("../../../Cargo.toml");
const GLIB_VARIANT_ITER: &str = include_str!("../../../vendor/glib-0.18.5/src/variant_iter.rs");
const PATCH_PROVENANCE: &str = include_str!("../../../vendor/glib-0.18.5/SOCIALNAME-PATCH.md");

#[test]
fn glib_018_soundness_patch_is_pinned_and_auditable() {
    assert!(WORKSPACE_MANIFEST.contains("glib = { path = \"vendor/glib-0.18.5\" }"));
    assert!(GLIB_VARIANT_ITER.contains("let mut p: *mut libc::c_char"));
    assert!(GLIB_VARIANT_ITER.contains("                &mut p,"));
    assert!(!GLIB_VARIANT_ITER.contains("                &p,"));

    for expected in [
        "233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5",
        "b5a40716c6017e086a7fbc01c39e5d15af28ac01",
        "ea720152f28e293ef4362ee844ee5cc499f32d2a",
    ] {
        assert!(PATCH_PROVENANCE.contains(expected));
    }
}
