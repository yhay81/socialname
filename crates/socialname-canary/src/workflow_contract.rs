use serde_yaml_ng::{Mapping, Value};

const MANUAL: &str = include_str!("../../../.github/workflows/canary-manual.yml");
const SCHEDULED: &str = include_str!("../../../.github/workflows/canary-scheduled.yml");

#[test]
fn canary_workflows_are_parseable_bounded_and_non_promoting() {
    let manual = parse(MANUAL);
    let scheduled = parse(SCHEDULED);

    assert_eq!(
        keys(mapping(field(mapping(&manual), "on"))),
        vec!["workflow_dispatch"]
    );
    assert_eq!(
        keys(mapping(field(mapping(&scheduled), "on"))),
        vec!["schedule", "workflow_dispatch"]
    );
    for workflow in [&manual, &scheduled] {
        assert_eq!(
            string(
                field(mapping(field(mapping(workflow), "permissions")), "contents"),
                "contents permission",
            ),
            "read"
        );
        assert_common_run_contract(workflow);
    }

    let manual_dispatch = mapping(field(
        mapping(field(mapping(&manual), "on")),
        "workflow_dispatch",
    ));
    let inputs = mapping(field(manual_dispatch, "inputs"));
    assert!(field(mapping(field(inputs, "acknowledge_live")), "default").is_bool());
    assert!(MANUAL.contains("vars.SOCIALNAME_CANARY_ENABLED == 'true'"));

    let scheduled_jobs = mapping(field(mapping(&scheduled), "jobs"));
    let scheduled_canary = mapping(field(scheduled_jobs, "canary"));
    assert_eq!(
        field(mapping(field(scheduled_canary, "strategy")), "max-parallel").as_u64(),
        Some(3)
    );
    assert!(SCHEDULED.contains("17 */12 * * *"));
    assert!(SCHEDULED.contains("length <= 64"));
    assert!(SCHEDULED.contains("SOCIALNAME_CANARY_SCHEDULE"));
}

fn assert_common_run_contract(workflow: &Value) {
    let jobs = mapping(field(mapping(workflow), "jobs"));
    let canary = mapping(field(jobs, "canary"));
    let environment = mapping(field(canary, "env"));
    assert_eq!(
        string(field(environment, "MAX_REQUESTS"), "MAX_REQUESTS"),
        "64"
    );
    assert_eq!(
        string(field(environment, "MAX_CONCURRENCY"), "MAX_CONCURRENCY"),
        "4"
    );
    assert_eq!(
        string(field(environment, "MAX_ELAPSED_MS"), "MAX_ELAPSED_MS"),
        "120000"
    );
    assert_eq!(
        string(
            field(environment, "MAX_RESPONSE_BYTES"),
            "MAX_RESPONSE_BYTES"
        ),
        "16777216"
    );
    assert!(
        environment
            .get(Value::String("CANARY_MANIFEST_B64".to_owned()))
            .is_none(),
        "the manifest secret must not be job-wide"
    );
    assert_eq!(field(canary, "timeout-minutes").as_u64(), Some(10));
    assert_eq!(
        field(mapping(field(canary, "concurrency")), "cancel-in-progress").as_bool(),
        Some(false)
    );

    let steps = field(canary, "steps")
        .as_sequence()
        .expect("canary steps are a sequence");
    let materialize = named_step(steps, "Materialize approved manifest");
    assert!(
        mapping(field(materialize, "env"))
            .get(Value::String("CANARY_MANIFEST_B64".to_owned()))
            .is_some()
    );
    let run = string(
        field(named_step(steps, "Run privacy-bounded canary"), "run"),
        "canary run command",
    );
    for expected in [
        "--max-requests \"$MAX_REQUESTS\"",
        "--max-concurrency \"$MAX_CONCURRENCY\"",
        "--max-elapsed-ms \"$MAX_ELAPSED_MS\"",
        "--max-response-bytes \"$MAX_RESPONSE_BYTES\"",
        "--allow-live",
    ] {
        assert!(run.contains(expected), "missing run contract: {expected}");
    }
    assert!(!run.contains("promote"));
    let upload = named_step(steps, "Upload minimized report");
    assert_eq!(
        field(mapping(field(upload, "with")), "retention-days").as_u64(),
        Some(3)
    );
}

fn parse(source: &str) -> Value {
    serde_yaml_ng::from_str(source).expect("workflow YAML parses")
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

fn keys(mapping: &Mapping) -> Vec<&str> {
    mapping
        .keys()
        .map(|key| key.as_str().expect("mapping key is a string"))
        .collect()
}
