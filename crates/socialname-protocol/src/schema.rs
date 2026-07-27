use std::collections::BTreeMap;

use schemars::{Schema, schema_for};

use crate::{
    ApiErrorResponse, ConsentGrantCreateRequest, ConsentGrantListPage, ConsentGrantResource,
    ConsentWithdrawalRequest, ContributorDeletionCreateRequest, DeletionReceiptResource,
    DeletionRequestResource, DeveloperReportResource, EmailNotification, EvidenceCapsuleResource,
    NotificationAcknowledgementCreateRequest, NotificationAcknowledgementResource,
    NotificationDelivery, NotificationEndpointCreateRequest, NotificationEndpointResource,
    OperationalReportResource, OrganizationAuditEventPage, OrganizationMemberCreateRequest,
    OrganizationMemberPage, OrganizationMemberPatchRequest, OrganizationMemberResource,
    OrganizationResource, OrganizationRetentionPolicyPatchRequest,
    OrganizationRetentionPolicyResource, PlanEntitlementResource, SearchCompletionWebhook,
    SearchCompletionWebhookCreateRequest, SearchCompletionWebhookResource, SearchCreateRequest,
    SearchEvent, SearchExportPage, SearchHistoryPage, SearchResource, SharedContributionPage,
    SharedContributionResource, SharedContributionSubmitRequest, Transition, TransitionReviewPage,
    TransitionReviewPatchRequest, TransitionReviewResource, WatchCreateRequest, WatchListPage,
    WatchPatchRequest, WatchResource, WatchTransitionPage, WebhookNotification, WorkspaceResource,
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
            "developer_report_resource",
            schema_for!(DeveloperReportResource),
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
        (
            "operational_report_resource",
            schema_for!(OperationalReportResource),
        ),
        (
            "organization_audit_event_page",
            schema_for!(OrganizationAuditEventPage),
        ),
        (
            "organization_member_create_request",
            schema_for!(OrganizationMemberCreateRequest),
        ),
        (
            "organization_member_page",
            schema_for!(OrganizationMemberPage),
        ),
        (
            "organization_member_patch_request",
            schema_for!(OrganizationMemberPatchRequest),
        ),
        (
            "organization_member_resource",
            schema_for!(OrganizationMemberResource),
        ),
        ("organization_resource", schema_for!(OrganizationResource)),
        (
            "organization_retention_policy_patch_request",
            schema_for!(OrganizationRetentionPolicyPatchRequest),
        ),
        (
            "organization_retention_policy_resource",
            schema_for!(OrganizationRetentionPolicyResource),
        ),
        (
            "plan_entitlement_resource",
            schema_for!(PlanEntitlementResource),
        ),
        ("search_create_request", schema_for!(SearchCreateRequest)),
        (
            "search_completion_webhook",
            schema_for!(SearchCompletionWebhook),
        ),
        (
            "search_completion_webhook_create_request",
            schema_for!(SearchCompletionWebhookCreateRequest),
        ),
        (
            "search_completion_webhook_resource",
            schema_for!(SearchCompletionWebhookResource),
        ),
        ("search_event", schema_for!(SearchEvent)),
        ("search_export_page", schema_for!(SearchExportPage)),
        ("search_history_page", schema_for!(SearchHistoryPage)),
        ("search_resource", schema_for!(SearchResource)),
        (
            "shared_contribution_page",
            schema_for!(SharedContributionPage),
        ),
        (
            "shared_contribution_resource",
            schema_for!(SharedContributionResource),
        ),
        (
            "shared_contribution_submit_request",
            schema_for!(SharedContributionSubmitRequest),
        ),
        ("transition", schema_for!(Transition)),
        ("transition_review_page", schema_for!(TransitionReviewPage)),
        (
            "transition_review_patch_request",
            schema_for!(TransitionReviewPatchRequest),
        ),
        (
            "transition_review_resource",
            schema_for!(TransitionReviewResource),
        ),
        ("watch_create_request", schema_for!(WatchCreateRequest)),
        ("watch_list_page", schema_for!(WatchListPage)),
        ("watch_patch_request", schema_for!(WatchPatchRequest)),
        ("watch_resource", schema_for!(WatchResource)),
        ("watch_transition_page", schema_for!(WatchTransitionPage)),
        ("webhook_notification", schema_for!(WebhookNotification)),
        ("email_notification", schema_for!(EmailNotification)),
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
                "developer_report_resource",
                "email_notification",
                "evidence_capsule_resource",
                "notification_acknowledgement_create_request",
                "notification_acknowledgement_resource",
                "notification_delivery",
                "notification_endpoint_create_request",
                "notification_endpoint_resource",
                "operational_report_resource",
                "organization_audit_event_page",
                "organization_member_create_request",
                "organization_member_page",
                "organization_member_patch_request",
                "organization_member_resource",
                "organization_resource",
                "organization_retention_policy_patch_request",
                "organization_retention_policy_resource",
                "plan_entitlement_resource",
                "search_completion_webhook",
                "search_completion_webhook_create_request",
                "search_completion_webhook_resource",
                "search_create_request",
                "search_event",
                "search_export_page",
                "search_history_page",
                "search_resource",
                "shared_contribution_page",
                "shared_contribution_resource",
                "shared_contribution_submit_request",
                "transition",
                "transition_review_page",
                "transition_review_patch_request",
                "transition_review_resource",
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
