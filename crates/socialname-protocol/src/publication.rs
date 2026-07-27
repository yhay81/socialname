use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{API_V1_SCHEMA, ApiKeyScope, api_v1_schemas};

pub const API_V1_CONTRACT_VERSION: &str = "1.0.0";
pub const OPENAPI_VERSION: &str = "3.1.2";

const SEARCH_EVENT_RETRY_MS: u64 = 1_000;
const SSE_QUERY_BATCH_SIZE: u64 = 128;
const SSE_POLL_INTERVAL_MS: u64 = 250;
const SSE_KEEP_ALIVE_INTERVAL_MS: u64 = 10_000;
const SSE_CONNECTION_LIFETIME_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublishedHttpMethod {
    Get,
    Post,
    Patch,
    Delete,
}

impl PublishedHttpMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    const fn openapi_key(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Patch => "patch",
            Self::Delete => "delete",
        }
    }
}

#[derive(Clone, Copy)]
enum PublishedParameter {
    PageLimit,
    PageAfter,
    Window,
    IdempotencyKey,
    LastEventId,
}

#[derive(Clone, Copy)]
enum PublishedResponseKind {
    Json(&'static str),
    SearchEventStream,
}

#[derive(Clone, Copy)]
pub struct PublishedApiOperation {
    pub method: PublishedHttpMethod,
    pub path: &'static str,
    pub operation_id: &'static str,
    pub required_scope: ApiKeyScope,
    tag: &'static str,
    summary: &'static str,
    request_schema: Option<&'static str>,
    parameters: &'static [PublishedParameter],
    success_statuses: &'static [u16],
    response: PublishedResponseKind,
    returns_location: bool,
}

const OK: &[u16] = &[200];
const CREATED: &[u16] = &[201];
const REPLAYABLE_CREATED: &[u16] = &[200, 201];
const NONE: &[PublishedParameter] = &[];
const PAGE: &[PublishedParameter] = &[PublishedParameter::PageLimit, PublishedParameter::PageAfter];
const IDEMPOTENCY: &[PublishedParameter] = &[PublishedParameter::IdempotencyKey];
const RESUMABLE_STREAM: &[PublishedParameter] = &[PublishedParameter::LastEventId];
const WINDOW: &[PublishedParameter] = &[PublishedParameter::Window];

static OPERATIONS: [PublishedApiOperation; 26] = [
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/workspace",
        operation_id: "getWorkspace",
        required_scope: ApiKeyScope::WorkspaceRead,
        tag: "workspace",
        summary: "Read the authenticated workspace and API-key metadata.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("workspace_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/searches",
        operation_id: "createSearch",
        required_scope: ApiKeyScope::SearchWrite,
        tag: "searches",
        summary: "Create or exactly replay one consent-bound managed search.",
        request_schema: Some("search_create_request"),
        parameters: IDEMPOTENCY,
        success_statuses: REPLAYABLE_CREATED,
        response: PublishedResponseKind::Json("search_resource"),
        returns_location: true,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/searches/{search_id}",
        operation_id: "getSearch",
        required_scope: ApiKeyScope::SearchRead,
        tag: "searches",
        summary: "Read one managed search and its current progress.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("search_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Delete,
        path: "/v1/searches/{search_id}",
        operation_id: "cancelSearch",
        required_scope: ApiKeyScope::SearchWrite,
        tag: "searches",
        summary: "Cancel eligible unfinished work for one managed search.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("search_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/searches/{search_id}/events",
        operation_id: "streamSearchEvents",
        required_scope: ApiKeyScope::SearchRead,
        tag: "searches",
        summary: "Stream bounded, resumable, ordered search events.",
        request_schema: None,
        parameters: RESUMABLE_STREAM,
        success_statuses: OK,
        response: PublishedResponseKind::SearchEventStream,
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/searches/{search_id}/completion-webhook",
        operation_id: "createSearchCompletionWebhook",
        required_scope: ApiKeyScope::SearchWrite,
        tag: "searches",
        summary: "Bind one active webhook endpoint to search completion.",
        request_schema: Some("search_completion_webhook_create_request"),
        parameters: NONE,
        success_statuses: REPLAYABLE_CREATED,
        response: PublishedResponseKind::Json("search_completion_webhook_resource"),
        returns_location: true,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/searches/{search_id}/completion-webhook",
        operation_id: "getSearchCompletionWebhook",
        required_scope: ApiKeyScope::SearchRead,
        tag: "searches",
        summary: "Read one target-free search-completion webhook status.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("search_completion_webhook_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Delete,
        path: "/v1/searches/{search_id}/completion-webhook",
        operation_id: "cancelSearchCompletionWebhook",
        required_scope: ApiKeyScope::SearchWrite,
        tag: "searches",
        summary: "Cancel one search-completion webhook subscription.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("search_completion_webhook_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/watches",
        operation_id: "listWatches",
        required_scope: ApiKeyScope::WatchRead,
        tag: "watches",
        summary: "List one bounded tenant-local page of watches.",
        request_schema: None,
        parameters: PAGE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("watch_list_page"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/watches",
        operation_id: "createWatch",
        required_scope: ApiKeyScope::WatchWrite,
        tag: "watches",
        summary: "Create one consent-bound freshness-aware watch.",
        request_schema: Some("watch_create_request"),
        parameters: NONE,
        success_statuses: CREATED,
        response: PublishedResponseKind::Json("watch_resource"),
        returns_location: true,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/watches/{watch_id}",
        operation_id: "getWatch",
        required_scope: ApiKeyScope::WatchRead,
        tag: "watches",
        summary: "Read one tenant-local watch.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("watch_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Patch,
        path: "/v1/watches/{watch_id}",
        operation_id: "updateWatch",
        required_scope: ApiKeyScope::WatchWrite,
        tag: "watches",
        summary: "Apply one revision-fenced watch state or endpoint update.",
        request_schema: Some("watch_patch_request"),
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("watch_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Delete,
        path: "/v1/watches/{watch_id}",
        operation_id: "deleteWatch",
        required_scope: ApiKeyScope::WatchWrite,
        tag: "watches",
        summary: "Mark one watch deleting without claiming immediate erasure.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("watch_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/watches/{watch_id}/transitions",
        operation_id: "listWatchTransitions",
        required_scope: ApiKeyScope::WatchRead,
        tag: "watches",
        summary: "List a bounded transition and delivery timeline page.",
        request_schema: None,
        parameters: PAGE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("watch_transition_page"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/consent-grants",
        operation_id: "listConsentGrants",
        required_scope: ApiKeyScope::ConsentRead,
        tag: "consent",
        summary: "List one bounded page of purpose-specific consent grants.",
        request_schema: None,
        parameters: PAGE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("consent_grant_list_page"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/consent-grants",
        operation_id: "createConsentGrant",
        required_scope: ApiKeyScope::ConsentWrite,
        tag: "consent",
        summary: "Create or exactly replay one purpose-specific consent grant.",
        request_schema: Some("consent_grant_create_request"),
        parameters: NONE,
        success_statuses: REPLAYABLE_CREATED,
        response: PublishedResponseKind::Json("consent_grant_resource"),
        returns_location: true,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/consent-grants/{consent_grant_id}",
        operation_id: "getConsentGrant",
        required_scope: ApiKeyScope::ConsentRead,
        tag: "consent",
        summary: "Read one purpose-specific consent grant.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("consent_grant_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/consent-grants/{consent_grant_id}/withdrawals",
        operation_id: "withdrawConsentGrant",
        required_scope: ApiKeyScope::ConsentWrite,
        tag: "consent",
        summary: "Apply immediate one-way withdrawal to one consent grant.",
        request_schema: Some("consent_withdrawal_request"),
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("consent_grant_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/observations/{observation_id}/evidence-capsule",
        operation_id: "getEvidenceCapsule",
        required_scope: ApiKeyScope::EvidenceRead,
        tag: "evidence",
        summary: "Read one bounded, consent-governed Evidence Capsule.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("evidence_capsule_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/deletion-requests/contributor",
        operation_id: "createContributorDeletion",
        required_scope: ApiKeyScope::DataDelete,
        tag: "deletion",
        summary: "Create or replay deletion for one owned consent contribution.",
        request_schema: Some("contributor_deletion_create_request"),
        parameters: NONE,
        success_statuses: REPLAYABLE_CREATED,
        response: PublishedResponseKind::Json("deletion_request_resource"),
        returns_location: true,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/deletion-requests/{deletion_request_id}",
        operation_id: "getDeletionRequest",
        required_scope: ApiKeyScope::DataDelete,
        tag: "deletion",
        summary: "Read target-free deletion progress and deadlines.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("deletion_request_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/deletion-requests/{deletion_request_id}/receipt",
        operation_id: "getDeletionReceipt",
        required_scope: ApiKeyScope::DataDelete,
        tag: "deletion",
        summary: "Read a completed deletion receipt and backup state.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("deletion_receipt_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Post,
        path: "/v1/notification-deliveries/{delivery_id}/acknowledgement",
        operation_id: "createNotificationAcknowledgement",
        required_scope: ApiKeyScope::NotificationWrite,
        tag: "notifications",
        summary: "Acknowledge one successfully delivered logical notification.",
        request_schema: Some("notification_acknowledgement_create_request"),
        parameters: NONE,
        success_statuses: REPLAYABLE_CREATED,
        response: PublishedResponseKind::Json("notification_acknowledgement_resource"),
        returns_location: true,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/notification-deliveries/{delivery_id}/acknowledgement",
        operation_id: "getNotificationAcknowledgement",
        required_scope: ApiKeyScope::NotificationRead,
        tag: "notifications",
        summary: "Read one delivery-scoped acknowledgement receipt.",
        request_schema: None,
        parameters: NONE,
        success_statuses: OK,
        response: PublishedResponseKind::Json("notification_acknowledgement_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/operations/report",
        operation_id: "getOperationalReport",
        required_scope: ApiKeyScope::OperationsRead,
        tag: "operations",
        summary: "Read a target-free tenant operational snapshot.",
        request_schema: None,
        parameters: WINDOW,
        success_statuses: OK,
        response: PublishedResponseKind::Json("operational_report_resource"),
        returns_location: false,
    },
    PublishedApiOperation {
        method: PublishedHttpMethod::Get,
        path: "/v1/developer/report",
        operation_id: "getDeveloperReport",
        required_scope: ApiKeyScope::UsageRead,
        tag: "developer",
        summary: "Read target-free quota, usage, backlog, and search service objectives.",
        request_schema: None,
        parameters: WINDOW,
        success_statuses: OK,
        response: PublishedResponseKind::Json("developer_report_resource"),
        returns_location: false,
    },
];

#[must_use]
pub fn published_api_v1_operations() -> &'static [PublishedApiOperation] {
    &OPERATIONS
}

#[must_use]
pub fn api_v1_openapi() -> Value {
    let schema_names = api_v1_schemas().into_keys().collect::<BTreeSet<_>>();
    validate_operation_schema_references(&schema_names);

    let mut paths = BTreeMap::<&str, BTreeMap<&str, Value>>::new();
    for operation in published_api_v1_operations() {
        paths
            .entry(operation.path)
            .or_default()
            .insert(operation.method.openapi_key(), openapi_operation(operation));
    }
    let components = schema_names
        .into_iter()
        .map(|name| {
            (
                name,
                json!({"$ref": format!("./schemas/{name}.schema.json")}),
            )
        })
        .collect::<BTreeMap<_, _>>();

    json!({
        "openapi": OPENAPI_VERSION,
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "SocialName Developer API",
            "version": API_V1_CONTRACT_VERSION,
            "description": "Closed, tenant-authenticated SocialName API v1. Runtime relational validation and authorization supplement the published JSON Schemas."
        },
        "tags": [
            {"name": "workspace"},
            {"name": "searches"},
            {"name": "watches"},
            {"name": "consent"},
            {"name": "evidence"},
            {"name": "deletion"},
            {"name": "notifications"},
            {"name": "operations"},
            {"name": "developer"}
        ],
        "paths": paths,
        "components": {
            "schemas": components,
            "parameters": {
                "XRequestId": {
                    "name": "X-Request-ID",
                    "in": "header",
                    "required": false,
                    "description": "Optional opaque request correlation ID. Invalid values are ignored and replaced rather than reflected.",
                    "schema": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[A-Za-z0-9_-]+$"
                    }
                }
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A scoped SocialName API key. Bearer values never appear in request bodies, query strings, resources, or examples."
                }
            }
        },
        "x-socialname-api-schema": API_V1_SCHEMA,
        "x-socialname-contract-manifest": "./manifest.json",
        "x-socialname-sse-contract": "./sse.json"
    })
}

#[must_use]
pub fn api_v1_sse_contract() -> Value {
    json!({
        "schema": "socialname.dev/sse-contract/v1",
        "contract_version": API_V1_CONTRACT_VERSION,
        "api_schema": API_V1_SCHEMA,
        "operation_id": "streamSearchEvents",
        "request": {
            "method": "GET",
            "path": "/v1/searches/{search_id}/events",
            "required_scope": "search:read",
            "headers": {
                "Last-Event-ID": {
                    "required": false,
                    "maximum_instances": 1,
                    "format": "uuid",
                    "meaning": "Resume strictly after this tenant-and-search-local persisted event."
                }
            }
        },
        "response": {
            "status": 200,
            "content_type": "text/event-stream",
            "ordering": "sequence_ascending",
            "delivery": "at_least_once",
            "maximum_events_per_query": SSE_QUERY_BATCH_SIZE,
            "poll_interval_ms": SSE_POLL_INTERVAL_MS,
            "maximum_connection_lifetime_ms": SSE_CONNECTION_LIFETIME_MS,
            "authorization_rechecked_each_poll": true,
            "keep_alive": {
                "kind": "comment",
                "text": "keep-alive",
                "interval_ms": SSE_KEEP_ALIVE_INTERVAL_MS
            }
        },
        "events": {
            "search_event": {
                "persisted": true,
                "event": "search_event",
                "id": {
                    "required": true,
                    "format": "uuid",
                    "replay_cursor": true
                },
                "retry_ms": SEARCH_EVENT_RETRY_MS,
                "data": {
                    "encoding": "json",
                    "schema": {"$ref": "./schemas/search_event.schema.json"}
                }
            },
            "stream_error": {
                "persisted": false,
                "event": "stream_error",
                "id": {"forbidden": true},
                "retry": {"forbidden": true},
                "terminal_for_connection": true,
                "data": {
                    "encoding": "json",
                    "schema": {"$ref": "./schemas/api_error_response.schema.json"}
                }
            }
        },
        "resumption": {
            "header": "Last-Event-ID",
            "cursor": "search_event.id",
            "deduplicate_by": "search_event.id",
            "malformed_duplicate_foreign_or_unknown_cursor": "invalid_request_before_stream"
        }
    })
}

#[must_use]
pub fn api_v1_contract_files() -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert("openapi.json".to_owned(), pretty_json(&api_v1_openapi()));
    files.insert("sse.json".to_owned(), pretty_json(&api_v1_sse_contract()));
    for (name, schema) in api_v1_schemas() {
        files.insert(
            format!("schemas/{name}.schema.json"),
            pretty_json(&serde_json::to_value(schema).expect("JSON Schema serializes")),
        );
    }

    let file_digests = files
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "sha256": sha256_hex(bytes)
            })
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "schema": "socialname.dev/api-contract-manifest/v1",
        "contract_version": API_V1_CONTRACT_VERSION,
        "api_schema": API_V1_SCHEMA,
        "openapi_version": OPENAPI_VERSION,
        "files": file_digests
    });
    files.insert("manifest.json".to_owned(), pretty_json(&manifest));
    files
}

fn openapi_operation(operation: &PublishedApiOperation) -> Value {
    let mut value = serde_json::Map::new();
    value.insert("operationId".to_owned(), json!(operation.operation_id));
    value.insert("summary".to_owned(), json!(operation.summary));
    value.insert("tags".to_owned(), json!([operation.tag]));
    value.insert("security".to_owned(), json!([{"bearerAuth": []}]));
    value.insert(
        "x-socialname-required-scope".to_owned(),
        json!(operation.required_scope.as_str()),
    );
    if operation.parameters.iter().any(|parameter| {
        matches!(
            parameter,
            PublishedParameter::PageLimit
                | PublishedParameter::PageAfter
                | PublishedParameter::Window
        )
    }) {
        value.insert(
            "x-socialname-unknown-query-parameters".to_owned(),
            json!("forbidden"),
        );
    }

    let parameters = openapi_parameters(operation);
    if !parameters.is_empty() {
        value.insert("parameters".to_owned(), Value::Array(parameters));
    }
    if let Some(schema) = operation.request_schema {
        value.insert(
            "requestBody".to_owned(),
            json!({
                "required": true,
                "content": {
                    "application/json": {
                        "schema": external_schema_ref(schema)
                    }
                }
            }),
        );
    }
    value.insert("responses".to_owned(), openapi_responses(operation));
    Value::Object(value)
}

fn openapi_parameters(operation: &PublishedApiOperation) -> Vec<Value> {
    let mut parameters = vec![json!({"$ref": "#/components/parameters/XRequestId"})];
    parameters.extend(
        operation
            .path
            .split('/')
            .filter_map(|segment| {
                segment
                    .strip_prefix('{')
                    .and_then(|value| value.strip_suffix('}'))
            })
            .map(|name| {
                json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": {
                        "type": "string",
                        "format": "uuid"
                    }
                })
            })
            .collect::<Vec<_>>(),
    );
    parameters.extend(
        operation
            .parameters
            .iter()
            .copied()
            .map(|parameter| match parameter {
                PublishedParameter::PageLimit => json!({
                    "name": "limit",
                    "in": "query",
                    "required": false,
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 20
                    }
                }),
                PublishedParameter::PageAfter => json!({
                    "name": "after",
                    "in": "query",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "format": "uuid"
                    }
                }),
                PublishedParameter::Window => json!({
                    "name": "window",
                    "in": "query",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "enum": ["24h", "7d", "30d"],
                        "default": "24h"
                    }
                }),
                PublishedParameter::IdempotencyKey => json!({
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": true,
                    "schema": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[A-Za-z0-9_-]+$"
                    }
                }),
                PublishedParameter::LastEventId => json!({
                    "name": "Last-Event-ID",
                    "in": "header",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "format": "uuid"
                    }
                }),
            }),
    );
    parameters
}

fn openapi_responses(operation: &PublishedApiOperation) -> Value {
    let mut responses = BTreeMap::<String, Value>::new();
    for status in operation.success_statuses {
        let response = match operation.response {
            PublishedResponseKind::Json(schema) => {
                let mut response = serde_json::Map::new();
                response.insert(
                    "description".to_owned(),
                    json!(if *status == 201 {
                        "Created."
                    } else {
                        "Successful response."
                    }),
                );
                response.insert(
                    "content".to_owned(),
                    json!({
                        "application/json": {
                            "schema": external_schema_ref(schema)
                        }
                    }),
                );
                response.insert(
                    "headers".to_owned(),
                    openapi_response_headers(operation.returns_location),
                );
                Value::Object(response)
            }
            PublishedResponseKind::SearchEventStream => json!({
                "description": "Bounded SSE response. Reconnect after normal closure.",
                "headers": openapi_response_headers(false),
                "content": {
                    "text/event-stream": {
                        "schema": {"type": "string"},
                        "x-socialname-sse-contract": "./sse.json"
                    }
                }
            }),
        };
        responses.insert(status.to_string(), response);
    }
    responses.insert(
        "default".to_owned(),
        json!({
            "description": "Closed API error. For SSE, this response occurs before streaming starts.",
            "headers": openapi_response_headers(false),
            "content": {
                "application/json": {
                    "schema": external_schema_ref("api_error_response")
                }
            }
        }),
    );
    serde_json::to_value(responses).expect("response map serializes")
}

fn openapi_response_headers(include_location: bool) -> Value {
    let mut headers = BTreeMap::from([
        (
            "Cache-Control",
            json!({
                "description": "Sensitive API responses are never cacheable.",
                "required": true,
                "schema": {"type": "string", "const": "no-store"}
            }),
        ),
        (
            "X-Content-Type-Options",
            json!({
                "description": "Disable response content-type sniffing.",
                "required": true,
                "schema": {"type": "string", "const": "nosniff"}
            }),
        ),
        (
            "X-Request-ID",
            json!({
                "description": "Validated inbound request ID or a server-generated replacement.",
                "required": true,
                "schema": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9_-]+$"
                }
            }),
        ),
    ]);
    if include_location {
        headers.insert(
            "Location",
            json!({
                "description": "Relative path of the created or replayed resource.",
                "required": true,
                "schema": {"type": "string"}
            }),
        );
    }
    serde_json::to_value(headers).expect("response headers serialize")
}

fn external_schema_ref(name: &str) -> Value {
    json!({"$ref": format!("./schemas/{name}.schema.json")})
}

fn validate_operation_schema_references(schema_names: &BTreeSet<&str>) {
    for operation in published_api_v1_operations() {
        if let Some(request_schema) = operation.request_schema {
            assert!(
                schema_names.contains(request_schema),
                "published request schema must exist"
            );
        }
        if let PublishedResponseKind::Json(response_schema) = operation.response {
            assert!(
                schema_names.contains(response_schema),
                "published response schema must exist"
            );
        }
    }
}

fn pretty_json(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("contract JSON serializes");
    bytes.push(b'\n');
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_has_one_unique_operation_for_every_current_route() {
        assert_eq!(published_api_v1_operations().len(), 26);
        let identities = published_api_v1_operations()
            .iter()
            .map(|operation| (operation.method, operation.path))
            .collect::<BTreeSet<_>>();
        let operation_ids = published_api_v1_operations()
            .iter()
            .map(|operation| operation.operation_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(identities.len(), published_api_v1_operations().len());
        assert_eq!(operation_ids.len(), published_api_v1_operations().len());
        assert!(
            published_api_v1_operations()
                .iter()
                .all(|operation| operation.path.starts_with("/v1/"))
        );
    }

    #[test]
    fn openapi_and_sse_publication_are_closed_and_linked() {
        let openapi = api_v1_openapi();
        assert_eq!(openapi["openapi"], OPENAPI_VERSION);
        assert_eq!(openapi["x-socialname-api-schema"], API_V1_SCHEMA);
        assert_eq!(
            openapi["paths"]["/v1/searches/{search_id}/events"]["get"]["responses"]["200"]["content"]
                ["text/event-stream"]["x-socialname-sse-contract"],
            "./sse.json"
        );
        assert_eq!(
            openapi["paths"]["/v1/workspace"]["get"]["parameters"][0]["$ref"],
            "#/components/parameters/XRequestId"
        );
        assert_eq!(
            openapi["paths"]["/v1/workspace"]["get"]["responses"]["200"]["headers"]["Cache-Control"]
                ["schema"]["const"],
            "no-store"
        );
        assert_eq!(
            openapi["paths"]["/v1/operations/report"]["get"]["x-socialname-unknown-query-parameters"],
            "forbidden"
        );
        let operation_count = openapi["paths"]
            .as_object()
            .unwrap()
            .values()
            .map(|path| path.as_object().unwrap().len())
            .sum::<usize>();
        assert_eq!(operation_count, published_api_v1_operations().len());

        let sse = api_v1_sse_contract();
        assert_eq!(sse["schema"], "socialname.dev/sse-contract/v1");
        assert_eq!(sse["events"]["search_event"]["persisted"], true);
        assert_eq!(sse["events"]["stream_error"]["id"]["forbidden"], true);
        assert_eq!(
            sse["resumption"]["malformed_duplicate_foreign_or_unknown_cursor"],
            "invalid_request_before_stream"
        );
    }

    #[test]
    fn generated_contract_files_are_deterministic_and_digest_bound() {
        let first = api_v1_contract_files();
        let second = api_v1_contract_files();
        assert_eq!(first, second);
        assert!(first.contains_key("openapi.json"));
        assert!(first.contains_key("sse.json"));
        assert!(first.contains_key("manifest.json"));
        assert_eq!(
            first
                .keys()
                .filter(|path| path.starts_with("schemas/"))
                .count(),
            api_v1_schemas().len()
        );

        let manifest: Value = serde_json::from_slice(&first["manifest.json"]).unwrap();
        assert_eq!(manifest["files"].as_array().unwrap().len(), first.len() - 1);
        for file in manifest["files"].as_array().unwrap() {
            let path = file["path"].as_str().unwrap();
            let digest = file["sha256"].as_str().unwrap();
            assert_eq!(digest.len(), 64);
            assert_eq!(digest, sha256_hex(&first[path]));
        }
    }
}
