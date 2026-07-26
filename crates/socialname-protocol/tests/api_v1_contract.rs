use socialname_protocol::{
    API_V1_SCHEMA, AccountState, ConfirmationBasis, ConsentCollectionProfileVersion,
    ConsentGrantCreateRequest, ConsentGrantId, ConsentNoticeVersion, ConsentPurpose,
    ConsentSubjectKind, ContributorDeletionCreateRequest, DefinitiveVerdict,
    DeletionReceiptResource, DeletionReceiptState, DeletionRequestId, DeletionRequestResource,
    DeletionRequestState, DeletionScope, DeletionStoreKind, DeletionStoreReceipt,
    DeletionStoreState, EmailNotification, EventId, EvidenceCapsuleId, EvidenceCapsuleProfile,
    EvidenceCapsuleResource, EvidenceCapsuleSchema, EvidenceClass, EvidenceDigest,
    EvidenceMatcherTrace, EvidenceNetworkClass, EvidenceOutcome, EvidenceProbe, EvidenceProvenance,
    EvidenceTransportOutcome, EvidenceVantage, InstallationId,
    NotificationAcknowledgementCreateRequest, NotificationAcknowledgementResource,
    NotificationChannel, NotificationDelivery, NotificationDeliveryId, NotificationEndpointId,
    NotificationLogicalKey, ObservationId, OperationalFailure, OperationalFailureKind, ProbeBudget,
    ProtocolVersion, RegionClass, ResultSource, RuleHash, SearchCreateRequest, SearchEvent,
    SearchEventData, SearchId, SearchMode, SearchProgress, SearchResource, SearchState, SiteId,
    SuppressionReason, SyncPolicy, Target, TargetSelection, Transition, TransitionChange,
    TransitionConfirmation, TransitionId, Username, Validate, WatchCreateRequest, WatchId,
    WatchListPage, WatchResource, WatchSchedule, WatchState, WatchTransitionEntry,
    WatchTransitionPage, WebhookNotification,
};

fn target() -> Target {
    Target {
        username: Username::new("alice-private-target").unwrap(),
        site_id: SiteId::new("github").unwrap(),
    }
}

#[test]
fn installation_consent_has_one_exact_redacted_v1_wire_shape() {
    let request = ConsentGrantCreateRequest {
        schema: ProtocolVersion::ApiV1,
        subject_kind: ConsentSubjectKind::Installation,
        installation_id: Some(InstallationId::new("11111111-1111-4111-8111-111111111111").unwrap()),
        purpose: ConsentPurpose::SharedObservation,
        collection_profile_version: ConsentCollectionProfileVersion::V1,
        notice_version: ConsentNoticeVersion::V1,
        expires_at_unix_ms: None,
    };
    assert!(request.validate().is_ok());
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "subject_kind": "installation",
            "installation_id": "11111111-1111-4111-8111-111111111111",
            "purpose": "shared_observation",
            "collection_profile_version": "profile-v1",
            "notice_version": "notice-v1",
            "expires_at_unix_ms": null
        })
    );
    assert!(!format!("{request:?}").contains("11111111-1111-4111-8111-111111111111"));
}

#[test]
fn contributor_deletion_has_one_selector_free_v1_wire_shape() {
    let request = ContributorDeletionCreateRequest {
        schema: ProtocolVersion::ApiV1,
        consent_grant_id: ConsentGrantId::new("grant_01").unwrap(),
    };
    assert!(request.validate().is_ok());
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "consent_grant_id": "grant_01"
        })
    );

    let resource = DeletionRequestResource {
        schema: ProtocolVersion::ApiV1,
        deletion_request_id: DeletionRequestId::new("deletion_01").unwrap(),
        scope: DeletionScope::Contributor,
        state: DeletionRequestState::Hidden,
        requested_at_unix_ms: 1_000,
        hide_by_unix_ms: 301_000,
        support_withdrawal_by_unix_ms: 3_601_000,
        primary_delete_by_unix_ms: 86_401_000,
        derived_rebuild_by_unix_ms: 604_801_000,
        backup_expiry_by_unix_ms: 3_024_001_000,
        matched_observations: 2,
        hidden_resources: 5,
        support_withdrawn_at_unix_ms: None,
        primary_completed_at_unix_ms: None,
        completed_at_unix_ms: None,
    };
    assert!(resource.validate().is_ok());
    assert_eq!(
        serde_json::to_value(resource).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "deletion_request_id": "deletion_01",
            "scope": "contributor",
            "state": "hidden",
            "requested_at_unix_ms": 1_000,
            "hide_by_unix_ms": 301_000,
            "support_withdrawal_by_unix_ms": 3_601_000,
            "primary_delete_by_unix_ms": 86_401_000,
            "derived_rebuild_by_unix_ms": 604_801_000,
            "backup_expiry_by_unix_ms": 3_024_001_000_i64,
            "matched_observations": 2,
            "hidden_resources": 5,
            "support_withdrawn_at_unix_ms": null,
            "primary_completed_at_unix_ms": null,
            "completed_at_unix_ms": null
        })
    );
}

#[test]
fn deletion_receipt_has_one_store_complete_v1_wire_shape() {
    let receipt = DeletionReceiptResource {
        schema: ProtocolVersion::ApiV1,
        deletion_request_id: DeletionRequestId::new("deletion_01").unwrap(),
        state: DeletionReceiptState::Pending,
        evaluated_at_unix_ms: 2_000,
        stores: vec![
            DeletionStoreReceipt {
                store: DeletionStoreKind::Primary,
                state: DeletionStoreState::Completed,
                deadline_at_unix_ms: 1_500,
                completed_at_unix_ms: Some(1_800),
            },
            DeletionStoreReceipt {
                store: DeletionStoreKind::Derived,
                state: DeletionStoreState::Completed,
                deadline_at_unix_ms: 3_000,
                completed_at_unix_ms: Some(1_800),
            },
            DeletionStoreReceipt {
                store: DeletionStoreKind::Backup,
                state: DeletionStoreState::Pending,
                deadline_at_unix_ms: 5_000,
                completed_at_unix_ms: None,
            },
        ],
        primary_completed_at_unix_ms: Some(1_800),
        backup_expiry_by_unix_ms: 5_000,
        remaining_backup_expiry_ms: 3_000,
        completed_at_unix_ms: None,
    };
    assert!(receipt.validate().is_ok());
    assert_eq!(
        serde_json::to_value(receipt).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "deletion_request_id": "deletion_01",
            "state": "pending",
            "evaluated_at_unix_ms": 2_000,
            "stores": [
                {
                    "store": "primary",
                    "state": "completed",
                    "deadline_at_unix_ms": 1_500,
                    "completed_at_unix_ms": 1_800
                },
                {
                    "store": "derived",
                    "state": "completed",
                    "deadline_at_unix_ms": 3_000,
                    "completed_at_unix_ms": 1_800
                },
                {
                    "store": "backup",
                    "state": "pending",
                    "deadline_at_unix_ms": 5_000,
                    "completed_at_unix_ms": null
                }
            ],
            "primary_completed_at_unix_ms": 1_800,
            "backup_expiry_by_unix_ms": 5_000,
            "remaining_backup_expiry_ms": 3_000,
            "completed_at_unix_ms": null
        })
    );
}

#[test]
fn evidence_capsule_has_one_bounded_body_free_v1_wire_shape() {
    let capsule = EvidenceCapsuleResource {
        schema: ProtocolVersion::ApiV1,
        capsule_schema: EvidenceCapsuleSchema::V1,
        evidence_capsule_id: EvidenceCapsuleId::new("capsule_01").unwrap(),
        observation_id: ObservationId::new("observation_01").unwrap(),
        profile: EvidenceCapsuleProfile::PrivateHistory,
        target: target(),
        outcome: EvidenceOutcome::Definitive {
            verdict: DefinitiveVerdict::Found,
        },
        provenance: EvidenceProvenance {
            rule_hash: RuleHash::new("1".repeat(64)).unwrap(),
            rule_pack_hash: "2".repeat(64),
            engine_hash: "3".repeat(64),
            rule_pack_metadata_id: "4".repeat(64),
            rule_promotion_id: "5".repeat(64),
        },
        vantage: EvidenceVantage {
            region_class: RegionClass::new("jp").unwrap(),
            network_class: EvidenceNetworkClass::Managed,
        },
        evidence_class: EvidenceClass::E4StructuredIdentity,
        evidence_digest: EvidenceDigest::new("6".repeat(64)).unwrap(),
        profile_url: None,
        probes: vec![EvidenceProbe {
            probe_id: "api".to_owned(),
            transport: EvidenceTransportOutcome::Completed,
            status: Some(200),
            final_url: None,
            content_type: Some("application/json".to_owned()),
            body_bytes: 128,
            body_truncated: false,
            latency_bucket_ms: 100,
        }],
        matcher_trace: vec![EvidenceMatcherTrace {
            path: "found.all[0]".to_owned(),
            matched: true,
            detail: "status Some(200)".to_owned(),
        }],
        collected_at_unix_ms: 1_000,
        structured_retained_until_unix_ms: 1_000 + 90 * 24 * 60 * 60 * 1_000,
        research_extension: None,
        research_retained_until_unix_ms: None,
    };
    assert!(capsule.validate().is_ok());
    assert_eq!(
        serde_json::to_value(capsule).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "capsule_schema": "socialname.dev/evidence-capsule/v1",
            "evidence_capsule_id": "capsule_01",
            "observation_id": "observation_01",
            "profile": "private_history",
            "target": {
                "username": "alice-private-target",
                "site_id": "github"
            },
            "outcome": {
                "kind": "definitive",
                "verdict": "found"
            },
            "provenance": {
                "rule_hash": "1111111111111111111111111111111111111111111111111111111111111111",
                "rule_pack_hash": "2222222222222222222222222222222222222222222222222222222222222222",
                "engine_hash": "3333333333333333333333333333333333333333333333333333333333333333",
                "rule_pack_metadata_id": "4444444444444444444444444444444444444444444444444444444444444444",
                "rule_promotion_id": "5555555555555555555555555555555555555555555555555555555555555555"
            },
            "vantage": {
                "region_class": "jp",
                "network_class": "managed"
            },
            "evidence_class": "e4_structured_identity",
            "evidence_digest": "6666666666666666666666666666666666666666666666666666666666666666",
            "profile_url": null,
            "probes": [{
                "probe_id": "api",
                "transport": "completed",
                "status": 200,
                "final_url": null,
                "content_type": "application/json",
                "body_bytes": 128,
                "body_truncated": false,
                "latency_bucket_ms": 100
            }],
            "matcher_trace": [{
                "path": "found.all[0]",
                "matched": true,
                "detail": "status Some(200)"
            }],
            "collected_at_unix_ms": 1_000,
            "structured_retained_until_unix_ms": 7_776_001_000_i64,
            "research_extension": null,
            "research_retained_until_unix_ms": null
        })
    );
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
fn email_notification_has_one_exact_v1_wire_shape() {
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
    let notification = EmailNotification::for_confirmed_transition(
        NotificationDeliveryId::new("delivery_01").unwrap(),
        transition,
    )
    .unwrap();
    let json = serde_json::to_value(notification).unwrap();
    assert_eq!(json["schema"], API_V1_SCHEMA);
    assert_eq!(json["delivery_id"], "delivery_01");
    assert_eq!(
        json["transition"]["target"]["username"],
        "alice-private-target"
    );
    assert_eq!(json["transition"]["confirmation"]["status"], "confirmed");
    assert_eq!(
        json["transition"]["supporting_observation_ids"],
        serde_json::json!(["observation_01"])
    );
}

#[test]
fn notification_acknowledgement_has_one_exact_v1_wire_shape() {
    let request = NotificationAcknowledgementCreateRequest {
        schema: ProtocolVersion::ApiV1,
    };
    let resource = NotificationAcknowledgementResource {
        schema: ProtocolVersion::ApiV1,
        delivery_id: NotificationDeliveryId::new("delivery_01").unwrap(),
        acknowledged_at_unix_ms: 3_000,
    };
    assert!(request.validate().is_ok());
    assert!(resource.validate().is_ok());
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA
        })
    );
    assert_eq!(
        serde_json::to_value(resource).unwrap(),
        serde_json::json!({
            "schema": API_V1_SCHEMA,
            "delivery_id": "delivery_01",
            "acknowledged_at_unix_ms": 3_000
        })
    );
    assert!(
        serde_json::from_value::<NotificationAcknowledgementCreateRequest>(serde_json::json!({
            "schema": API_V1_SCHEMA,
            "review_decision": "approved"
        }))
        .is_err()
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
