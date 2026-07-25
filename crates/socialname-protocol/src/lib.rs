#![forbid(unsafe_code)]

mod common;
mod error;
mod notification;
mod schema;
mod search;
mod transition;
mod watch;
mod workspace;

pub use common::{
    API_V1_SCHEMA, ApiKeyId, ConsentGrantId, DefinitiveVerdict, DeliveryErrorCode, EmailAddress,
    EventId, EvidenceClass, EvidenceDigest, Freshness, FreshnessState, HttpsUrl, IdempotencyKey,
    IdentifierError, NotificationDeliveryId, NotificationEndpointId, NotificationLogicalKey,
    ObservationId, ProtocolVersion, RegionClass, RequestId, ResultSource, RuleHash,
    RuleHealthStatus, SearchId, SearchMode, SiteId, SyncPolicy, Target, TargetSelection,
    TransitionId, Username, Validate, ValidationCode, ValidationErrors, ValidationIssue, WatchId,
    WorkspaceId,
};
pub use error::{ApiError, ApiErrorCode, ApiErrorResponse, FieldViolation};
pub use notification::{
    NotificationChannel, NotificationDelivery, NotificationDeliveryState, NotificationDestination,
    NotificationEndpointCreateRequest, NotificationEndpointResource, NotificationEndpointState,
    NotificationKind,
};
pub use schema::api_v1_schemas;
pub use search::{
    Assertion, AssertionOutcome, AssertionQuality, DefinitiveResult, OperationalFailure,
    OperationalFailureKind, SearchCreateRequest, SearchEvent, SearchEventData, SearchProgress,
    SearchResource, SearchState, SearchTerminalState, UncertainResult, UncertaintyReason,
};
pub use transition::{
    AccountState, ConfirmationBasis, MeasurementState, PendingConfirmationReason,
    SuppressionReason, Transition, TransitionChange, TransitionConfirmation,
};
pub use watch::{
    ProbeBudget, WatchCreateRequest, WatchPatchRequest, WatchResource, WatchSchedule, WatchState,
    WatchStateUpdate,
};
pub use workspace::{
    ApiKeyScope, ApiKeyState, AuthenticatedApiKeyResource, WorkspaceResource, WorkspaceState,
};
