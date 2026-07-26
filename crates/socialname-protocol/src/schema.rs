use std::collections::BTreeMap;

use schemars::{Schema, schema_for};

use crate::{
    ApiErrorResponse, ConsentGrantCreateRequest, ConsentGrantListPage, ConsentGrantResource,
    ConsentWithdrawalRequest, ContributorDeletionCreateRequest, DeletionReceiptResource,
    DeletionRequestResource, EvidenceCapsuleResource, NotificationAcknowledgementCreateRequest,
    NotificationAcknowledgementResource, NotificationDelivery, NotificationEndpointCreateRequest,
    NotificationEndpointResource, SearchCreateRequest, SearchEvent, SearchResource, Transition,
    WatchCreateRequest, WatchListPage, WatchPatchRequest, WatchResource, WatchTransitionPage,
    WebhookNotification, WorkspaceResource,
};

#[must_use]
pub fn api_v1_schemas() -> BTreeMap<&'static str, Schema> {
    BTreeMap::from([
        ("api_error_response", schema_for!(ApiErrorResponse)),
        (
            "consent_grant_create_request",
            schema_for!(ConsentGrantCreateRequest),
        ),
        ("consent_grant_list_page", schema_for!(ConsentGrantListPage)),
        ("consent_grant_resource", schema_for!(ConsentGrantResource)),
        (
            "consent_withdrawal_request",
            schema_for!(ConsentWithdrawalRequest),
        ),
        (
            "evidence_capsule_resource",
            schema_for!(EvidenceCapsuleResource),
        ),
        (
            "contributor_deletion_create_request",
            schema_for!(ContributorDeletionCreateRequest),
        ),
        (
            "deletion_request_resource",
            schema_for!(DeletionRequestResource),
        ),
        (
            "deletion_receipt_resource",
            schema_for!(DeletionReceiptResource),
        ),
        (
            "notification_acknowledgement_create_request",
            schema_for!(NotificationAcknowledgementCreateRequest),
        ),
        (
            "notification_acknowledgement_resource",
            schema_for!(NotificationAcknowledgementResource),
        ),
        ("notification_delivery", schema_for!(NotificationDelivery)),
        (
            "notification_endpoint_create_request",
            schema_for!(NotificationEndpointCreateRequest),
        ),
        (
            "notification_endpoint_resource",
            schema_for!(NotificationEndpointResource),
        ),
        ("search_create_request", schema_for!(SearchCreateRequest)),
        ("search_event", schema_for!(SearchEvent)),
        ("search_resource", schema_for!(SearchResource)),
        ("transition", schema_for!(Transition)),
        ("watch_create_request", schema_for!(WatchCreateRequest)),
        ("watch_list_page", schema_for!(WatchListPage)),
        ("watch_patch_request", schema_for!(WatchPatchRequest)),
        ("watch_resource", schema_for!(WatchResource)),
        ("watch_transition_page", schema_for!(WatchTransitionPage)),
        ("webhook_notification", schema_for!(WebhookNotification)),
        ("workspace_resource", schema_for!(WorkspaceResource)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_bundle_contains_every_public_api_v1_root() {
        let schemas = api_v1_schemas();
        assert_eq!(
            schemas.keys().copied().collect::<Vec<_>>(),
            vec![
                "api_error_response",
                "consent_grant_create_request",
                "consent_grant_list_page",
                "consent_grant_resource",
                "consent_withdrawal_request",
                "contributor_deletion_create_request",
                "deletion_receipt_resource",
                "deletion_request_resource",
                "evidence_capsule_resource",
                "notification_acknowledgement_create_request",
                "notification_acknowledgement_resource",
                "notification_delivery",
                "notification_endpoint_create_request",
                "notification_endpoint_resource",
                "search_create_request",
                "search_event",
                "search_resource",
                "transition",
                "watch_create_request",
                "watch_list_page",
                "watch_patch_request",
                "watch_resource",
                "watch_transition_page",
                "webhook_notification",
                "workspace_resource",
            ]
        );
        for schema in schemas.values() {
            let json = serde_json::to_value(schema).unwrap();
            assert_eq!(
                json["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(json["type"], "object");
        }
    }
}
