use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use socialname_protocol::api_v1_contract_files;

#[test]
fn committed_api_v1_contracts_match_protocol_generation_exactly() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
        .join("api")
        .join("v1");
    let expected = api_v1_contract_files();
    for (relative_path, expected_contents) in &expected {
        let actual = fs::read(root.join(relative_path)).unwrap_or_else(|error| {
            panic!("cannot read committed contract {relative_path}: {error}")
        });
        assert_eq!(
            &actual, expected_contents,
            "committed contract {relative_path} drifted"
        );
    }

    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(json_paths(&root, &root), expected_paths);
}

fn json_paths(root: &Path, directory: &Path) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for entry in fs::read_dir(directory).expect("contract directory exists") {
        let entry = entry.expect("contract directory entry is readable");
        let path = entry.path();
        let file_type = entry.file_type().expect("contract entry type is readable");
        if file_type.is_dir() {
            paths.extend(json_paths(root, &path));
        } else if file_type.is_file() && path.extension().is_some_and(|value| value == "json") {
            let relative = path.strip_prefix(root).expect("contract stays under root");
            paths.insert(
                relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    paths
}
