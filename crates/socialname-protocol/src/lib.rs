#![forbid(unsafe_code)]

mod common;
mod consent;
mod deletion;
mod developer;
mod error;
mod evidence;
mod monitoring;
mod notification;
mod operations;
mod publication;
mod schema;
mod search;
mod transition;
mod watch;
mod workspace;

pub use common::{
    API_V1_SCHEMA, ApiKeyId, ConsentGrantId, ConsentSubjectId, DefinitiveVerdict,
    DeletionRequestId, DeliveryErrorCode, EmailAddress, EventId, EvidenceCapsuleId, EvidenceClass,
    EvidenceDigest, Freshness, FreshnessState, HttpsUrl, IdempotencyKey, IdentifierError,
    InstallationId, NotificationDeliveryId, NotificationEndpointId, NotificationLogicalKey,
    ObservationId, ProtocolVersion, RegionClass, RequestId, ResultSource, RuleHash,
    RuleHealthStatus, SearchId, SearchMode, SiteId, SyncPolicy, Target, TargetSelection,
    TransitionId, Username, Validate, ValidationCode, ValidationErrors, ValidationIssue, WatchId,
    WorkspaceId,
};
pub use consent::{
    ConsentCollectionProfileVersion, ConsentGrantCreateRequest, ConsentGrantListPage,
    ConsentGrantResource, ConsentGrantState, ConsentNoticeVersion, ConsentPurpose, ConsentSource,
    ConsentSubjectKind, ConsentWithdrawalRequest, MAX_CONSENT_PAGE_ITEMS,
};
pub use deletion::{
    ContributorDeletionCreateRequest, DeletionReceiptResource, DeletionReceiptState,
    DeletionRequestResource, DeletionRequestState, DeletionScope, DeletionStoreKind,
    DeletionStoreReceipt, DeletionStoreState, MAXIMUM_DELETION_MATCH_COUNT,
};
pub use developer::{
    DEVELOPER_FIRST_RESULT_P95_TARGET_MS, DEVELOPER_SEARCH_SUCCESS_TARGET_BASIS_POINTS,
    DEVELOPER_TERMINAL_P95_TARGET_MS, DeveloperQuotaCounter, DeveloperQuotaSnapshot,
    DeveloperReportResource, DeveloperReportWindow, DeveloperSearchBacklog,
    DeveloperServiceObjectives, DeveloperUsageSummary,
};
pub use error::{ApiError, ApiErrorCode, ApiErrorResponse, FieldViolation};
pub use evidence::{
    EVIDENCE_CAPSULE_V1, EvidenceCapsuleProfile, EvidenceCapsuleResource, EvidenceCapsuleSchema,
    EvidenceMatcherTrace, EvidenceNetworkClass, EvidenceOutcome, EvidenceProbe, EvidenceProvenance,
    EvidenceResearchExtension, EvidenceTransportOutcome, EvidenceVantage,
    MAX_EVIDENCE_CAPSULE_BYTES, MAX_EVIDENCE_MATCHER_TRACES, MAX_EVIDENCE_PROBES,
};
pub use monitoring::{
    MAX_MONITORING_PAGE_ITEMS, WatchListPage, WatchTransitionEntry, WatchTransitionPage,
};
pub use notification::{
    EmailNotification, NotificationAcknowledgementCreateRequest,
    NotificationAcknowledgementResource, NotificationChannel, NotificationDelivery,
    NotificationDeliveryState, NotificationDestination, NotificationEndpointCreateRequest,
    NotificationEndpointResource, NotificationEndpointState, NotificationKind, WebhookNotification,
};
pub use operations::{
    ChannelSlo, DELETION_MAX_OVERDUE_MILESTONES, DELIVERY_SUCCESS_TARGET_BASIS_POINTS,
    DeletionDeadlineSlo, DeletionOverdueMilestones, LatencySlo, OperationalBacklog,
    OperationalObjectives, OperationalReportResource, OperationalReportWindow, RatioSlo, SloStatus,
    TRANSITION_TO_DELIVERY_P95_TARGET_MS, WATCH_RUN_SUCCESS_TARGET_BASIS_POINTS,
};
pub use publication::{
    API_V1_CONTRACT_VERSION, OPENAPI_VERSION, PublishedApiOperation, PublishedHttpMethod,
    api_v1_contract_files, api_v1_openapi, api_v1_sse_contract, published_api_v1_operations,
};
pub use schema::api_v1_schemas;
pub use search::{
    Assertion, AssertionOutcome, AssertionQuality, DefinitiveResult, OperationalFailure,
    OperationalFailureKind, RegionalAssertion, SearchCreateRequest, SearchEvent, SearchEventData,
    SearchProgress, SearchResource, SearchState, SearchTerminalState, UncertainResult,
    UncertaintyReason,
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
