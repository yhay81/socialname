#![forbid(unsafe_code)]

use serde_yaml_ng::{Mapping, Value};

const DOCKERFILE: &str = include_str!("../../../deploy/worker/Dockerfile");
const DOCKERIGNORE: &str = include_str!("../../../.dockerignore");
const QUALITY_WORKFLOW: &str = include_str!("../../../.github/workflows/rust.yml");

#[test]
fn worker_image_is_pinned_non_root_and_inert_by_default() {
    for expected in [
        "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
        "ARG RUST_IMAGE=rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa",
        "ARG RUNTIME_IMAGE=debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df",
        "cargo build --locked --release -p socialname-worker --bin socialname-worker",
        "COPY --chown=10001:10001 rules/sites /opt/socialname/rules/sites",
        "USER 10001:10001",
        "STOPSIGNAL SIGTERM",
        r#"ENTRYPOINT ["/usr/local/bin/socialname-worker"]"#,
        r#"CMD ["--help"]"#,
    ] {
        assert!(
            DOCKERFILE.contains(expected),
            "missing worker image contract: {expected}"
        );
    }

    let runtime = DOCKERFILE
        .split_once("FROM ${RUNTIME_IMAGE} AS runtime")
        .expect("Dockerfile has a distinct runtime stage")
        .1;
    assert!(
        !runtime.contains("\nRUN "),
        "the runtime image must not install or execute mutable build steps"
    );
    for secret_name in [
        "SOCIALNAME_WORKER_DATABASE_URL",
        "SOCIALNAME_ENDPOINT_ENCRYPTION_KEY_HEX",
        "SOCIALNAME_WEBHOOK_SIGNING_KEY_HEX",
    ] {
        assert!(
            !DOCKERFILE.contains(secret_name),
            "runtime secrets must not be Docker build inputs: {secret_name}"
        );
    }
}

#[test]
fn docker_context_excludes_credentials_canaries_and_build_outputs() {
    let patterns = DOCKERIGNORE.lines().collect::<Vec<_>>();
    for expected in [
        ".git",
        ".github",
        ".env",
        ".env.*",
        "**/*.key",
        "**/*.p12",
        "**/*.pem",
        "**/*.pfx",
        "**/node_modules",
        "**/target",
        ".canary-output",
        "rules/canaries",
    ] {
        assert!(
            patterns.contains(&expected),
            "missing Docker context exclusion: {expected}"
        );
    }
}

#[test]
fn quality_workflow_builds_and_smoke_tests_without_publishing() {
    let workflow: Value = serde_yaml_ng::from_str(QUALITY_WORKFLOW).expect("quality YAML parses");
    let jobs = mapping(field(mapping(&workflow), "jobs"));
    let job = mapping(field(jobs, "worker-image"));
    assert_eq!(
        field(job, "timeout-minutes").as_u64(),
        Some(30),
        "image job has a bounded runtime"
    );
    let steps = field(job, "steps")
        .as_sequence()
        .expect("image job steps are a sequence");
    let build = string(
        field(named_step(steps, "Build managed worker image"), "run"),
        "image build command",
    );
    assert!(build.contains("docker build"));
    assert!(build.contains("deploy/worker/Dockerfile"));
    assert!(build.contains("--build-arg VCS_REF=${{ github.sha }}"));
    let verify = string(
        field(named_step(steps, "Verify managed worker image"), "run"),
        "image verification command",
    );
    for expected in [
        "--network none",
        r#"docker run "${runtime_flags[@]}" socialname-worker --help"#,
        "managed job processing requires --allow-live",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges=true",
        ".Config.User",
        ".Config.Entrypoint",
    ] {
        assert!(
            verify.contains(expected),
            "missing image verification contract: {expected}"
        );
    }
    assert!(!QUALITY_WORKFLOW.contains("docker push"));
    assert!(!QUALITY_WORKFLOW.contains("docker login"));
}

fn mapping(value: &Value) -> &Mapping {
    value.as_mapping().expect("value is a mapping")
}

fn field<'a>(mapping: &'a Mapping, key: &str) -> &'a Value {
    mapping
        .get(Value::String(key.to_owned()))
        .unwrap_or_else(|| panic!("missing field {key}"))
}

fn string<'a>(value: &'a Value, label: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{label} is a string"))
}

fn named_step<'a>(steps: &'a [Value], name: &str) -> &'a Mapping {
    steps
        .iter()
        .map(mapping)
        .find(|step| {
            step.get(Value::String("name".to_owned()))
                .and_then(Value::as_str)
                == Some(name)
        })
        .unwrap_or_else(|| panic!("missing step {name}"))
}
