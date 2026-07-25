use socialname_protocol::{
    API_V1_SCHEMA, AccountState, ConsentGrantId, EventId, NotificationChannel,
    NotificationDelivery, NotificationDeliveryId, NotificationEndpointId, NotificationLogicalKey,
    ObservationId, OperationalFailure, OperationalFailureKind, ProtocolVersion, RegionClass,
    ResultSource, SearchCreateRequest, SearchEvent, SearchEventData, SearchId, SearchMode,
    SearchProgress, SearchResource, SearchState, SiteId, SuppressionReason, SyncPolicy, Target,
    TargetSelection, Transition, TransitionChange, TransitionConfirmation, TransitionId, Username,
    Validate, WatchId,
};

fn target() -> Target {
    Target {
        username: Username::new("alice-private-target").unwrap(),
        site_id: SiteId::new("github").unwrap(),
    }
}

#[test]
fn public_search_request_has_one_exact_v1_wire_shape() {
    let request = SearchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: TargetSelection {
            usernames: vec![Username::new("alice-private-target").unwrap()],
            site_ids: vec![SiteId::new("github").unwrap()],
        },
        mode: SearchMode::Remote,
        sync: SyncPolicy::Never,
        consent_grant_id: None,
        maximum_age_ms: 60_000,
        region_classes: vec![RegionClass::new("jp").unwrap()],
    };
    assert!(request.validate().is_ok());
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "targets": {
                "usernames": ["alice-private-target"],
                "site_ids": ["github"]
            },
            "mode": "remote",
            "sync": "never",
            "consent_grant_id": null,
            "maximum_age_ms": 60_000,
            "region_classes": ["jp"]
        })
    );
    assert!(!format!("{request:?}").contains("alice-private-target"));
}

#[test]
fn accepted_private_search_resource_has_one_exact_v1_wire_shape() {
    let request = SearchCreateRequest {
        schema: ProtocolVersion::ApiV1,
        targets: TargetSelection {
            usernames: vec![Username::new("alice-private-target").unwrap()],
            site_ids: vec![SiteId::new("github").unwrap()],
        },
        mode: SearchMode::Remote,
        sync: SyncPolicy::Private,
        consent_grant_id: Some(ConsentGrantId::new("grant_01").unwrap()),
        maximum_age_ms: 60_000,
        region_classes: vec![RegionClass::new("jp").unwrap()],
    };
    let resource = SearchResource {
        schema: ProtocolVersion::ApiV1,
        search_id: SearchId::new("search_01").unwrap(),
        state: SearchState::Accepted,
        request,
        progress: SearchProgress {
            total_targets: 1,
            completed_targets: 0,
            definitive_results: 0,
            uncertain_results: 0,
            operational_failures: 0,
        },
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 1_000,
    };
    assert!(resource.validate().is_ok());
    assert_eq!(
        serde_json::to_value(&resource).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "search_id": "search_01",
            "state": "accepted",
            "request": {
                "schema": API_V1_SCHEMA,
                "targets": {
                    "usernames": ["alice-private-target"],
                    "site_ids": ["github"]
                },
                "mode": "remote",
                "sync": "private",
                "consent_grant_id": "grant_01",
                "maximum_age_ms": 60_000,
                "region_classes": ["jp"]
            },
            "progress": {
                "total_targets": 1,
                "completed_targets": 0,
                "definitive_results": 0,
                "uncertain_results": 0,
                "operational_failures": 0
            },
            "created_at_unix_ms": 1_000,
            "updated_at_unix_ms": 1_000
        })
    );
    assert!(!format!("{resource:?}").contains("alice-private-target"));
}

#[test]
fn search_event_keeps_operational_failure_outside_verdicts() {
    let event = SearchEvent {
        schema: ProtocolVersion::ApiV1,
        event_id: EventId::new("event_01").unwrap(),
        search_id: SearchId::new("search_01").unwrap(),
        sequence: 1,
        emitted_at_unix_ms: 2_000,
        data: SearchEventData::OperationalFailure {
            failure: OperationalFailure {
                target: target(),
                kind: OperationalFailureKind::Timeout,
                source: ResultSource::ManagedProbe,
                occurred_at_unix_ms: 1_900,
                retryable: true,
                region_class: Some(RegionClass::new("jp").unwrap()),
                rule_hash: None,
            },
        },
    };
    assert!(event.validate().is_ok());
    let json = serde_json::to_value(event).unwrap();
    assert_eq!(json["schema"], API_V1_SCHEMA);
    assert_eq!(json["data"]["type"], "operational_failure");
    assert_eq!(json["data"]["failure"]["kind"], "timeout");
    assert!(json["data"]["failure"].get("verdict").is_none());
    assert!(json["data"]["failure"].get("uncertainty_reason").is_none());
}

#[test]
fn shared_only_absence_cannot_cross_the_delivery_constructor() {
    let transition = Transition {
        schema: ProtocolVersion::ApiV1,
        transition_id: TransitionId::new("transition_01").unwrap(),
        watch_id: WatchId::new("watch_01").unwrap(),
        target: target(),
        change: TransitionChange::AccountState {
            from: AccountState::Found,
            to: AccountState::NotFound,
        },
        confirmation: TransitionConfirmation::Suppressed {
            reason: SuppressionReason::SharedOnlyAbsence,
        },
        supporting_observation_ids: vec![ObservationId::new("observation_01").unwrap()],
        detected_at_unix_ms: 2_000,
    };
    assert!(transition.validate().is_ok());
    assert!(
        NotificationDelivery::queued_for_transition(
            NotificationDeliveryId::new("delivery_01").unwrap(),
            &transition,
            NotificationEndpointId::new("endpoint_01").unwrap(),
            NotificationLogicalKey::new("logical_01").unwrap(),
            NotificationChannel::Webhook,
            2_100,
        )
        .is_err()
    );
}

#[test]
fn public_request_rejects_unversioned_extension_fields() {
    let json = serde_json::json!({
        "schema": API_V1_SCHEMA,
        "targets": {
            "usernames": ["alice"],
            "site_ids": ["github"]
        },
        "mode": "remote",
        "sync": "never",
        "consent_grant_id": null,
        "maximum_age_ms": 60_000,
        "region_classes": ["jp"],
        "raw_http_body": "must never enter this contract"
    });
    assert!(serde_json::from_value::<SearchCreateRequest>(json).is_err());
}
