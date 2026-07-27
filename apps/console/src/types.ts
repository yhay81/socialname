export const API_SCHEMA = "socialname.dev/api/v1";

export type ApiKeyScope =
  | "workspace:read"
  | "search:read"
  | "search:write"
  | "watch:read"
  | "watch:write"
  | "notification:read"
  | "notification:write"
  | "operations:read"
  | "data:export"
  | "data:delete";

export interface WorkspaceResource {
  schema: typeof API_SCHEMA;
  workspace_id: string;
  slug: string;
  display_name: string;
  state: "active";
  authenticated_api_key: {
    api_key_id: string;
    key_prefix: string;
    scopes: ApiKeyScope[];
    state: "active";
    expires_at_unix_ms: number | null;
  };
}

export interface WatchCreateRequest {
  schema: typeof API_SCHEMA;
  targets: {
    usernames: string[];
    site_ids: string[];
  };
  region_classes: string[];
  maximum_age_ms: number;
  schedule: {
    interval_seconds: number;
    jitter_percent: number;
  };
  probe_budget: {
    maximum_probes_per_run: number;
    maximum_bytes_per_run: number;
  };
  notification_endpoint_ids: string[];
  private_history_consent_grant_id: string;
  retention_days: number;
}

export interface WatchResource {
  schema: typeof API_SCHEMA;
  watch_id: string;
  state: "active" | "paused" | "deleting";
  revision: number;
  configuration: WatchCreateRequest;
  created_at_unix_ms: number;
  updated_at_unix_ms: number;
  next_run_at_unix_ms: number | null;
}

export interface WatchListPage {
  schema: typeof API_SCHEMA;
  watches: WatchResource[];
  next_cursor: string | null;
}

export type TransitionChange =
  | {
      class: "account_state";
      from: "found" | "not_found";
      to: "found" | "not_found";
    }
  | {
      class: "measurement_health";
      region_class: string;
      rule_hash: string;
      from:
        | "healthy"
        | "degraded"
        | "quarantined"
        | "recovering"
        | "unavailable";
      to:
        | "healthy"
        | "degraded"
        | "quarantined"
        | "recovering"
        | "unavailable";
    };

export type TransitionConfirmation =
  | {
      status: "confirmed";
      basis:
        | "managed_e4"
        | "managed_e3_follow_up"
        | "two_managed_independent_regions"
        | "two_managed_separated_in_time"
        | "corroborated_shared_candidate_opt_in"
        | "measurement_health_evidence";
    }
  | {
      status: "pending";
      reason:
        | "managed_verification_required"
        | "second_managed_observation_required"
        | "regional_conflict";
    }
  | {
      status: "suppressed";
      reason:
        | "shared_only_absence"
        | "conflicting_evidence"
        | "watch_paused"
        | "supporting_evidence_deleted";
    };

export interface Transition {
  schema: typeof API_SCHEMA;
  transition_id: string;
  watch_id: string;
  target: {
    username: string;
    site_id: string;
  };
  change: TransitionChange;
  confirmation: TransitionConfirmation;
  supporting_observation_ids: string[];
  detected_at_unix_ms: number;
}

export type DeliveryState =
  | "queued"
  | "delivering"
  | "retry_scheduled"
  | "delivered"
  | "permanently_failed"
  | "cancelled";

export interface NotificationDelivery {
  schema: typeof API_SCHEMA;
  delivery_id: string;
  transition_id: string;
  endpoint_id: string;
  logical_notification_key: string;
  kind: "account_state" | "measurement_health";
  channel: "email" | "webhook";
  confirmation_basis: string;
  state: DeliveryState;
  attempt_count: number;
  created_at_unix_ms: number;
  next_attempt_at_unix_ms: number | null;
  delivered_at_unix_ms: number | null;
  acknowledged_at_unix_ms: number | null;
  last_error_code: string | null;
}

export interface NotificationAcknowledgementResource {
  schema: typeof API_SCHEMA;
  delivery_id: string;
  acknowledged_at_unix_ms: number;
}

export type OperationalReportWindow = "24h" | "7d" | "30d";
export type SloStatus = "no_data" | "meeting" | "breached";

export interface RatioSlo {
  status: SloStatus;
  good_events: number;
  total_events: number;
  target_basis_points: number;
}

export interface LatencySlo {
  status: SloStatus;
  samples: number;
  p95_ms: number | null;
  target_ms: number;
}

export interface DeletionDeadlineSlo {
  status: SloStatus;
  open_requests: number;
  failed_requests: number;
  overdue: {
    hide: number;
    support_withdrawal: number;
    primary_delete: number;
    derived_rebuild: number;
    backup_expiry: number;
  };
  target_max_overdue_milestones: number;
}

export interface OperationalReportResource {
  schema: typeof API_SCHEMA;
  window: OperationalReportWindow;
  generated_at_unix_ms: number;
  window_started_at_unix_ms: number;
  backlog: {
    active_watches: number;
    paused_watches: number;
    deleting_watches: number;
    planned_watch_runs: number;
    running_watch_runs: number;
    queued_probe_jobs: number;
    leased_probe_jobs: number;
    retry_wait_probe_jobs: number;
    oldest_pending_probe_job_age_ms: number | null;
    queued_email_deliveries: number;
    delivering_email_deliveries: number;
    retry_scheduled_email_deliveries: number;
    queued_webhook_deliveries: number;
    delivering_webhook_deliveries: number;
    retry_scheduled_webhook_deliveries: number;
    oldest_pending_delivery_age_ms: number | null;
  };
  objectives: {
    watch_run_success: RatioSlo;
    delivery_success: {
      email: RatioSlo;
      webhook: RatioSlo;
    };
    transition_to_delivery_latency: {
      email: LatencySlo;
      webhook: LatencySlo;
    };
    deletion_deadline_health: DeletionDeadlineSlo;
  };
}

export interface WatchTransitionEntry {
  transition: Transition;
  deliveries: NotificationDelivery[];
}

export interface WatchTransitionPage {
  schema: typeof API_SCHEMA;
  watch_id: string;
  entries: WatchTransitionEntry[];
  next_cursor: string | null;
}

export interface ApiErrorResponse {
  schema: typeof API_SCHEMA;
  request_id: string;
  error: {
    code: string;
    retryable: boolean;
    retry_after_ms: number | null;
    violations: Array<{
      field: string;
      code: string;
    }>;
  };
}
