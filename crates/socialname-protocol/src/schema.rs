use std::collections::BTreeMap;

use schemars::{Schema, schema_for};

use crate::{
    ApiErrorResponse, NotificationDelivery, NotificationEndpointCreateRequest,
    NotificationEndpointResource, SearchCreateRequest, SearchEvent, SearchResource, Transition,
    WatchCreateRequest, WatchPatchRequest, WatchResource, WebhookNotification, WorkspaceResource,
};

#[must_use]
pub fn api_v1_schemas() -> BTreeMap<&'static str, Schema> {
    BTreeMap::from([
        ("api_error_response", schema_for!(ApiErrorResponse)),
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
        ("watch_patch_request", schema_for!(WatchPatchRequest)),
        ("watch_resource", schema_for!(WatchResource)),
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
                "notification_delivery",
                "notification_endpoint_create_request",
                "notification_endpoint_resource",
                "search_create_request",
                "search_event",
                "search_resource",
                "transition",
                "watch_create_request",
                "watch_patch_request",
                "watch_resource",
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
