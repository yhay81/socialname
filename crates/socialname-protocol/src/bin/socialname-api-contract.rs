use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use socialname_protocol::api_v1_contract_files;

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("api contract error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or_else(usage)?;
    if command == "--help" || command == "-h" {
        return Ok(usage());
    }
    let mut output = default_output();
    while let Some(argument) = arguments.next() {
        if argument != "--output" {
            return Err(usage());
        }
        output = PathBuf::from(arguments.next().ok_or_else(usage)?);
    }

    match command.as_str() {
        "write" => {
            write_contracts(&output)?;
            check_contracts(&output)?;
            Ok(format!(
                "wrote and verified API v1 contracts in {}",
                output.display()
            ))
        }
        "check" => {
            check_contracts(&output)?;
            Ok(format!("verified API v1 contracts in {}", output.display()))
        }
        _ => Err(usage()),
    }
}

fn default_output() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("contracts")
        .join("api")
        .join("v1")
}

fn write_contracts(output: &Path) -> Result<(), String> {
    for (relative_path, contents) in api_v1_contract_files() {
        let path = output.join(relative_path);
        let parent = path
            .parent()
            .ok_or_else(|| "generated contract path has no parent".to_owned())?;
        fs::create_dir_all(parent).map_err(|error| format!("cannot create output: {error}"))?;
        fs::write(&path, contents).map_err(|error| format!("cannot write contract: {error}"))?;
    }
    Ok(())
}

fn check_contracts(output: &Path) -> Result<(), String> {
    let expected = api_v1_contract_files();
    for (relative_path, contents) in &expected {
        let actual = fs::read(output.join(relative_path))
            .map_err(|error| format!("cannot read {relative_path}: {error}"))?;
        if actual != *contents {
            return Err(format!(
                "{relative_path} differs; run the write command and review the result"
            ));
        }
    }

    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    let actual_paths = json_paths(output, output)?;
    let unexpected = actual_paths
        .difference(&expected_paths)
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(format!(
            "unexpected generated JSON files: {}",
            unexpected.join(", ")
        ));
    }
    Ok(())
}

fn json_paths(root: &Path, directory: &Path) -> Result<BTreeSet<String>, String> {
    let mut paths = BTreeSet::new();
    let entries =
        fs::read_dir(directory).map_err(|error| format!("cannot inspect output: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inspect output entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect output type: {error}"))?;
        if file_type.is_dir() {
            paths.extend(json_paths(root, &path)?);
        } else if file_type.is_file() && path.extension().is_some_and(|value| value == "json") {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "generated path escaped output root".to_owned())?;
            paths.insert(
                relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    Ok(paths)
}

fn usage() -> String {
    "usage: socialname-api-contract <write|check> [--output <directory>]".to_owned()
}
