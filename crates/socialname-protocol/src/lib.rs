#![forbid(unsafe_code)]

mod common;
mod consent;
mod deletion;
mod error;
mod evidence;
mod monitoring;
mod notification;
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
    NotificationChannel, NotificationDelivery, NotificationDeliveryState, NotificationDestination,
    NotificationEndpointCreateRequest, NotificationEndpointResource, NotificationEndpointState,
    NotificationKind, WebhookNotification,
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
