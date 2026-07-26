use socialname_protocol::{
    API_V1_SCHEMA, AccountState, ConfirmationBasis, ConsentGrantId, EventId, NotificationChannel,
    NotificationDelivery, NotificationDeliveryId, NotificationEndpointId, NotificationLogicalKey,
    ObservationId, OperationalFailure, OperationalFailureKind, ProbeBudget, ProtocolVersion,
    RegionClass, ResultSource, SearchCreateRequest, SearchEvent, SearchEventData, SearchId,
    SearchMode, SearchProgress, SearchResource, SearchState, SiteId, SuppressionReason, SyncPolicy,
    Target, TargetSelection, Transition, TransitionChange, TransitionConfirmation, TransitionId,
    Username, Validate, WatchCreateRequest, WatchId, WatchListPage, WatchResource, WatchSchedule,
    WatchState, WatchTransitionEntry, WatchTransitionPage, WebhookNotification,
};

fn target() -> Target {
    Target {
        username: Username::new("alice-private-target").unwrap(),
        site_id: SiteId::new("github").unwrap(),
    }
}

fn watch_resource() -> WatchResource {
    WatchResource {
        schema: ProtocolVersion::ApiV1,
        watch_id: WatchId::new("watch_01").unwrap(),
        state: WatchState::Active,
        revision: 1,
        configuration: WatchCreateRequest {
            schema: ProtocolVersion::ApiV1,
            targets: TargetSelection {
                usernames: vec![Username::new("alice-private-target").unwrap()],
                site_ids: vec![SiteId::new("github").unwrap()],
            },
            region_classes: vec![RegionClass::new("jp").unwrap()],
            maximum_age_ms: 60_000,
            schedule: WatchSchedule {
                interval_seconds: 300,
                jitter_percent: 0,
            },
            probe_budget: ProbeBudget {
                maximum_probes_per_run: 1,
                maximum_bytes_per_run: 1_024,
            },
            notification_endpoint_ids: vec![NotificationEndpointId::new("endpoint_01").unwrap()],
            private_history_consent_grant_id: ConsentGrantId::new("grant_01").unwrap(),
            retention_days: 30,
        },
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 1_000,
        next_run_at_unix_ms: Some(301_000),
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
fn webhook_notification_has_one_exact_v1_wire_shape() {
    let transition = Transition {
        schema: ProtocolVersion::ApiV1,
        transition_id: TransitionId::new("transition_01").unwrap(),
        watch_id: WatchId::new("watch_01").unwrap(),
        target: target(),
        change: TransitionChange::AccountState {
            from: AccountState::NotFound,
            to: AccountState::Found,
        },
        confirmation: TransitionConfirmation::Confirmed {
            basis: ConfirmationBasis::ManagedE4,
        },
        supporting_observation_ids: vec![ObservationId::new("observation_01").unwrap()],
        detected_at_unix_ms: 2_000,
    };
    let notification = WebhookNotification::for_confirmed_transition(
        NotificationDeliveryId::new("delivery_01").unwrap(),
        transition,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(notification).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "delivery_id": "delivery_01",
            "transition": {
                "schema": API_V1_SCHEMA,
                "transition_id": "transition_01",
                "watch_id": "watch_01",
                "target": {
                    "username": "alice-private-target",
                    "site_id": "github"
                },
                "change": {
                    "class": "account_state",
                    "from": "not_found",
                    "to": "found"
                },
                "confirmation": {
                    "status": "confirmed",
                    "basis": "managed_e4"
                },
                "supporting_observation_ids": ["observation_01"],
                "detected_at_unix_ms": 2_000
            }
        })
    );
}

#[test]
fn monitoring_pages_have_one_exact_v1_wire_shape() {
    let watch_page = WatchListPage {
        schema: ProtocolVersion::ApiV1,
        watches: vec![watch_resource()],
        next_cursor: Some(WatchId::new("watch_01").unwrap()),
    };
    assert!(watch_page.validate().is_ok());
    assert_eq!(
        serde_json::to_value(watch_page).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "watches": [{
                "schema": API_V1_SCHEMA,
                "watch_id": "watch_01",
                "state": "active",
                "revision": 1,
                "configuration": {
                    "schema": API_V1_SCHEMA,
                    "targets": {
                        "usernames": ["alice-private-target"],
                        "site_ids": ["github"]
                    },
                    "region_classes": ["jp"],
                    "maximum_age_ms": 60_000,
                    "schedule": {
                        "interval_seconds": 300,
                        "jitter_percent": 0
                    },
                    "probe_budget": {
                        "maximum_probes_per_run": 1,
                        "maximum_bytes_per_run": 1_024
                    },
                    "notification_endpoint_ids": ["endpoint_01"],
                    "private_history_consent_grant_id": "grant_01",
                    "retention_days": 30
                },
                "created_at_unix_ms": 1_000,
                "updated_at_unix_ms": 1_000,
                "next_run_at_unix_ms": 301_000
            }],
            "next_cursor": "watch_01"
        })
    );

    let transition = Transition {
        schema: ProtocolVersion::ApiV1,
        transition_id: TransitionId::new("transition_01").unwrap(),
        watch_id: WatchId::new("watch_01").unwrap(),
        target: target(),
        change: TransitionChange::AccountState {
            from: AccountState::NotFound,
            to: AccountState::Found,
        },
        confirmation: TransitionConfirmation::Confirmed {
            basis: ConfirmationBasis::ManagedE4,
        },
        supporting_observation_ids: vec![ObservationId::new("observation_01").unwrap()],
        detected_at_unix_ms: 2_000,
    };
    let transition_page = WatchTransitionPage {
        schema: ProtocolVersion::ApiV1,
        watch_id: WatchId::new("watch_01").unwrap(),
        entries: vec![WatchTransitionEntry {
            transition,
            deliveries: Vec::new(),
        }],
        next_cursor: None,
    };
    assert!(transition_page.validate().is_ok());
    let json = serde_json::to_value(transition_page).unwrap();
    assert_eq!(json["schema"], API_V1_SCHEMA);
    assert_eq!(json["watch_id"], "watch_01");
    assert_eq!(
        json["entries"][0]["transition"]["change"]["class"],
        "account_state"
    );
    assert_eq!(json["entries"][0]["deliveries"], serde_json::json!([]));
    assert_eq!(json["next_cursor"], serde_json::Value::Null);
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
