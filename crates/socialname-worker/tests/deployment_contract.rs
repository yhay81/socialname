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

const MAIN_PUSH_GATE: &str = "github.event_name == 'push' && github.ref == 'refs/heads/main'";

#[test]
fn quality_workflow_publishes_verified_images_only_from_main() {
    let workflow: Value = serde_yaml_ng::from_str(QUALITY_WORKFLOW).expect("quality YAML parses");
    let root = mapping(&workflow);
    let workflow_permissions = mapping(field(root, "permissions"));
    assert_eq!(
        workflow_permissions.len(),
        1,
        "workflow-level permissions stay minimal"
    );
    assert_eq!(
        field(workflow_permissions, "contents").as_str(),
        Some("read"),
        "workflow-level permissions remain read-only"
    );

    let jobs = mapping(field(root, "jobs"));
    for (job_key, dockerfile, image, build_name, verify_name, publish_name) in [
        (
            "worker-image",
            "deploy/worker/Dockerfile",
            "socialname-worker",
            "Build managed worker image",
            "Verify managed worker image",
            "Publish managed worker image",
        ),
        (
            "server-image",
            "deploy/server/Dockerfile",
            "socialname-server",
            "Build API server image",
            "Verify API server image",
            "Publish API server image",
        ),
    ] {
        let job = mapping(field(jobs, job_key));
        assert_eq!(
            field(job, "timeout-minutes").as_u64(),
            Some(30),
            "{job_key} has a bounded runtime"
        );
        let permissions = mapping(field(job, "permissions"));
        assert_eq!(
            field(permissions, "contents").as_str(),
            Some("read"),
            "{job_key} keeps read-only repository access"
        );
        assert_eq!(
            field(permissions, "packages").as_str(),
            Some("write"),
            "{job_key} declares the package publication grant explicitly"
        );
        let steps = field(job, "steps")
            .as_sequence()
            .expect("image job steps are a sequence");
        let build = string(
            field(named_step(steps, build_name), "run"),
            "image build command",
        );
        assert!(build.contains("docker build"));
        assert!(build.contains(dockerfile));
        assert!(build.contains("--build-arg VCS_REF=${{ github.sha }}"));
        let verify = string(
            field(named_step(steps, verify_name), "run"),
            "image verification command",
        );
        for expected in [
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges=true",
            ".Config.User",
            ".Config.Entrypoint",
            ".Config.StopSignal",
        ] {
            assert!(
                verify.contains(expected),
                "missing image verification contract: {expected}"
            );
        }
        let publish_step = named_step(steps, publish_name);
        assert_eq!(
            field(publish_step, "if").as_str(),
            Some(MAIN_PUSH_GATE),
            "{job_key} publishes only from a push to main"
        );
        let publish = string(field(publish_step, "run"), "image publish command");
        let ghcr_image = format!("ghcr.io/${{{{ github.repository_owner }}}}/{image}");
        assert!(
            publish.contains(&ghcr_image),
            "{job_key} publishes only its own GHCR image"
        );
        for expected in [
            "docker login ghcr.io",
            "--password-stdin",
            "sha-${{ github.sha }}",
            "RepoDigests",
            "GITHUB_STEP_SUMMARY",
        ] {
            assert!(
                publish.contains(expected),
                "missing image publication contract: {expected}"
            );
        }
    }

    let worker_steps = field(mapping(field(jobs, "worker-image")), "steps")
        .as_sequence()
        .expect("worker image job steps are a sequence");
    let worker_verify = string(
        field(
            named_step(worker_steps, "Verify managed worker image"),
            "run",
        ),
        "worker verification command",
    );
    for expected in [
        r#"docker run "${runtime_flags[@]}" socialname-worker --help"#,
        "managed job processing requires --allow-live",
        "--metadata /missing/metadata.json",
        "--current-trust-file /missing/trust.json",
        "--minimum-metadata-sequence-exclusive 0",
    ] {
        assert!(
            worker_verify.contains(expected),
            "missing worker verification contract: {expected}"
        );
    }
    let server_steps = field(mapping(field(jobs, "server-image")), "steps")
        .as_sequence()
        .expect("server image job steps are a sequence");
    let server_verify = string(
        field(named_step(server_steps, "Verify API server image"), "run"),
        "server verification command",
    );
    for expected in [
        r#"docker run "${runtime_flags[@]}" socialname-server --help"#,
        "Error: CommandError",
        "/opt/socialname/console/index.html",
    ] {
        assert!(
            server_verify.contains(expected),
            "missing server verification contract: {expected}"
        );
    }

    for (job_name, job_value) in jobs {
        let job_name = job_name.as_str().expect("job key is a string");
        let Some(steps) = mapping(job_value)
            .get(Value::String("steps".to_owned()))
            .and_then(Value::as_sequence)
        else {
            continue;
        };
        for step in steps.iter().map(mapping) {
            let run = step
                .get(Value::String("run".to_owned()))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !run.contains("docker push") && !run.contains("docker login") {
                continue;
            }
            let step_name = step
                .get(Value::String("name".to_owned()))
                .and_then(Value::as_str)
                .unwrap_or("");
            assert!(
                step_name == "Publish managed worker image"
                    || step_name == "Publish API server image",
                "job {job_name}: only the named publish steps may touch a registry"
            );
            assert_eq!(
                step.get(Value::String("if".to_owned()))
                    .and_then(Value::as_str),
                Some(MAIN_PUSH_GATE),
                "job {job_name}: registry access is gated to pushes to main"
            );
            assert!(
                !run.contains("secrets."),
                "job {job_name}: registry access uses only the workflow-scoped token"
            );
            assert!(
                run.contains("docker login ghcr.io"),
                "job {job_name}: registry access is limited to ghcr.io"
            );
        }
    }
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
