//! Generates the embedded rule pack from `rules/sites`.
//!
//! The list used to be written by hand, which silently pinned the desktop and
//! CLI to the ten rules someone had remembered to add. Deriving it from the
//! directory means the shipped pack is the pack, and a new rule cannot be
//! published to the pack yet stay invisible in the applications.

use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let rules = manifest
        .join("../..")
        .join("rules")
        .join("sites")
        .canonicalize()
        .expect("rules/sites must exist relative to the workspace root");

    println!("cargo:rerun-if-changed={}", rules.display());

    let mut entries: Vec<(String, PathBuf)> = fs::read_dir(&rules)
        .expect("rules/sites is readable")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .map(|path| {
            let id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("rule file name is Unicode")
                .to_owned();
            (id, path)
        })
        .collect();
    assert!(!entries.is_empty(), "rules/sites contains no rule");
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut generated = String::new();
    generated.push_str(&format!(
        "pub(crate) const EMBEDDED_RULES: [(&str, &str); {}] = [\n",
        entries.len()
    ));
    for (id, path) in &entries {
        // Every rule file is re-read when it changes, and a rename or removal
        // changes the directory listing itself.
        println!("cargo:rerun-if-changed={}", path.display());
        generated.push_str(&format!(
            "    ({id:?}, include_str!({:?})),\n",
            path.to_str().expect("rule path is Unicode")
        ));
    }
    generated.push_str("];\n");

    let out = PathBuf::from(env::var("OUT_DIR").expect("output directory"));
    fs::write(out.join("embedded_rules.rs"), generated).expect("write generated rule pack");
}
