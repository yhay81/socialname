import {
  API_SCHEMA,
  type DeliveryState,
  type LatencySlo,
  type NotificationAcknowledgementResource,
  type OperationalReportResource,
  type RatioSlo,
  type SloStatus,
  type WatchListPage,
  type WatchTransitionEntry,
  type WatchTransitionPage,
  type WorkspaceResource,
} from "./types.ts";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length &&
    [...expected].sort().every((key, index) => keys[index] === key)
  );
}

function assertPage(
  value: unknown,
  collection: "watches" | "entries",
): asserts value is Record<string, unknown> {
  if (
    !isRecord(value) ||
    value.schema !== API_SCHEMA ||
    !Array.isArray(value[collection]) ||
    value[collection].length > 50 ||
    !(
      value.next_cursor === null ||
      typeof value.next_cursor === "string"
    )
  ) {
    throw new Error("The monitoring response does not match API v1.");
  }
}

export function parseWorkspace(value: unknown): WorkspaceResource {
  if (
    !isRecord(value) ||
    value.schema !== API_SCHEMA ||
    typeof value.workspace_id !== "string" ||
    typeof value.display_name !== "string" ||
    !isRecord(value.authenticated_api_key) ||
    !Array.isArray(value.authenticated_api_key.scopes)
  ) {
    throw new Error("The workspace response does not match API v1.");
  }
  return value as unknown as WorkspaceResource;
}

export function parseWatchPage(value: unknown): WatchListPage {
  assertPage(value, "watches");
  const watches = value.watches;
  if (
    !Array.isArray(watches) ||
    !watches.every(
      (watch) =>
        isRecord(watch) &&
        watch.schema === API_SCHEMA &&
        typeof watch.watch_id === "string" &&
        isRecord(watch.configuration),
    )
  ) {
    throw new Error("The watch response does not match API v1.");
  }
  return value as unknown as WatchListPage;
}

export function parseTransitionPage(value: unknown): WatchTransitionPage {
  assertPage(value, "entries");
  const entries = value.entries;
  if (
    typeof value.watch_id !== "string" ||
    !Array.isArray(entries) ||
    !entries.every(
      (entry) =>
        isRecord(entry) &&
        isRecord(entry.transition) &&
        entry.transition.schema === API_SCHEMA &&
        Array.isArray(entry.deliveries) &&
        entry.deliveries.every(
          (delivery) =>
            isRecord(delivery) &&
            delivery.schema === API_SCHEMA &&
            typeof delivery.delivery_id === "string" &&
            (delivery.acknowledged_at_unix_ms === null ||
              typeof delivery.acknowledged_at_unix_ms === "number"),
        ),
    )
  ) {
    throw new Error("The transition response does not match API v1.");
  }
  return value as unknown as WatchTransitionPage;
}

export function parseNotificationAcknowledgement(
  value: unknown,
): NotificationAcknowledgementResource {
  if (
    !isRecord(value) ||
    value.schema !== API_SCHEMA ||
    typeof value.delivery_id !== "string" ||
    typeof value.acknowledged_at_unix_ms !== "number"
  ) {
    throw new Error("The notification response does not match API v1.");
  }
  return value as unknown as NotificationAcknowledgementResource;
}

const SLO_STATUSES = new Set<SloStatus>([
  "no_data",
  "meeting",
  "breached",
]);

function isSafeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isRatioSlo(value: unknown): value is RatioSlo {
  if (
    !(
      isRecord(value) &&
      hasExactKeys(value, [
        "status",
        "good_events",
        "total_events",
        "target_basis_points",
      ]) &&
      SLO_STATUSES.has(value.status as SloStatus) &&
      isSafeCount(value.good_events) &&
      isSafeCount(value.total_events) &&
      value.good_events <= value.total_events &&
      value.target_basis_points === 9_900
    )
  ) {
    return false;
  }
  const expected =
    value.total_events === 0
      ? "no_data"
      : BigInt(value.good_events) * 10_000n >=
          BigInt(value.total_events) * BigInt(value.target_basis_points)
        ? "meeting"
        : "breached";
  return value.status === expected;
}

function isLatencySlo(value: unknown): value is LatencySlo {
  if (
    !(
      isRecord(value) &&
      hasExactKeys(value, ["status", "samples", "p95_ms", "target_ms"]) &&
      SLO_STATUSES.has(value.status as SloStatus) &&
      isSafeCount(value.samples) &&
      (value.p95_ms === null || isSafeCount(value.p95_ms)) &&
      value.target_ms === 300_000 &&
      (value.samples === 0) === (value.p95_ms === null)
    )
  ) {
    return false;
  }
  const expected =
    value.p95_ms === null
      ? "no_data"
      : value.p95_ms <= value.target_ms
        ? "meeting"
        : "breached";
  return value.status === expected;
}

export function parseOperationalReport(
  value: unknown,
): OperationalReportResource {
  const backlogFields = [
    "active_watches",
    "paused_watches",
    "deleting_watches",
    "planned_watch_runs",
    "running_watch_runs",
    "queued_probe_jobs",
    "leased_probe_jobs",
    "retry_wait_probe_jobs",
    "oldest_pending_probe_job_age_ms",
    "queued_email_deliveries",
    "delivering_email_deliveries",
    "retry_scheduled_email_deliveries",
    "queued_webhook_deliveries",
    "delivering_webhook_deliveries",
    "retry_scheduled_webhook_deliveries",
    "oldest_pending_delivery_age_ms",
  ] as const;
  const deletionFields = [
    "status",
    "open_requests",
    "failed_requests",
    "overdue",
    "target_max_overdue_milestones",
  ] as const;
  const overdueFields = [
    "hide",
    "support_withdrawal",
    "primary_delete",
    "derived_rebuild",
    "backup_expiry",
  ] as const;
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schema",
      "window",
      "generated_at_unix_ms",
      "window_started_at_unix_ms",
      "backlog",
      "objectives",
    ]) ||
    value.schema !== API_SCHEMA ||
    !["24h", "7d", "30d"].includes(String(value.window)) ||
    !isSafeCount(value.generated_at_unix_ms) ||
    !isSafeCount(value.window_started_at_unix_ms) ||
    value.window_started_at_unix_ms === 0 ||
    value.generated_at_unix_ms <= value.window_started_at_unix_ms ||
    !isRecord(value.backlog) ||
    !hasExactKeys(value.backlog, backlogFields) ||
    !Object.values(value.backlog).every(
      (entry) => entry === null || isSafeCount(entry),
    ) ||
    !isRecord(value.objectives) ||
    !hasExactKeys(value.objectives, [
      "watch_run_success",
      "delivery_success",
      "transition_to_delivery_latency",
      "deletion_deadline_health",
    ]) ||
    !isRatioSlo(value.objectives.watch_run_success) ||
    !isRecord(value.objectives.delivery_success) ||
    !hasExactKeys(value.objectives.delivery_success, ["email", "webhook"]) ||
    !isRatioSlo(value.objectives.delivery_success.email) ||
    !isRatioSlo(value.objectives.delivery_success.webhook) ||
    !isRecord(value.objectives.transition_to_delivery_latency) ||
    !hasExactKeys(value.objectives.transition_to_delivery_latency, [
      "email",
      "webhook",
    ]) ||
    !isLatencySlo(value.objectives.transition_to_delivery_latency.email) ||
    !isLatencySlo(value.objectives.transition_to_delivery_latency.webhook) ||
    !isRecord(value.objectives.deletion_deadline_health) ||
    !hasExactKeys(
      value.objectives.deletion_deadline_health,
      deletionFields,
    ) ||
    !SLO_STATUSES.has(
      value.objectives.deletion_deadline_health.status as SloStatus,
    ) ||
    !isRecord(value.objectives.deletion_deadline_health.overdue) ||
    !hasExactKeys(
      value.objectives.deletion_deadline_health.overdue,
      overdueFields,
    ) ||
    !isSafeCount(value.objectives.deletion_deadline_health.open_requests) ||
    !isSafeCount(value.objectives.deletion_deadline_health.failed_requests) ||
    value.objectives.deletion_deadline_health.failed_requests >
      value.objectives.deletion_deadline_health.open_requests ||
    value.objectives.deletion_deadline_health
      .target_max_overdue_milestones !== 0 ||
    !Object.values(value.objectives.deletion_deadline_health.overdue).every(
      isSafeCount,
    )
  ) {
    throw new Error("The operational report does not match API v1.");
  }
  const report = value as unknown as OperationalReportResource;
  const expectedWindowMs = {
    "24h": 24 * 60 * 60 * 1_000,
    "7d": 7 * 24 * 60 * 60 * 1_000,
    "30d": 30 * 24 * 60 * 60 * 1_000,
  }[report.window];
  const hasProbeBacklog =
    report.backlog.queued_probe_jobs +
      report.backlog.leased_probe_jobs +
      report.backlog.retry_wait_probe_jobs >
    0;
  const hasDeliveryBacklog =
    report.backlog.queued_email_deliveries +
      report.backlog.delivering_email_deliveries +
      report.backlog.retry_scheduled_email_deliveries +
      report.backlog.queued_webhook_deliveries +
      report.backlog.delivering_webhook_deliveries +
      report.backlog.retry_scheduled_webhook_deliveries >
    0;
  const deletion = report.objectives.deletion_deadline_health;
  const overdue = Object.values(deletion.overdue).reduce(
    (sum, count) => sum + count,
    0,
  );
  const expectedDeletionStatus =
    deletion.open_requests === 0
      ? "no_data"
      : deletion.failed_requests === 0 && overdue === 0
        ? "meeting"
        : "breached";
  if (
    report.generated_at_unix_ms - report.window_started_at_unix_ms !==
      expectedWindowMs ||
    hasProbeBacklog !==
      (report.backlog.oldest_pending_probe_job_age_ms !== null) ||
    hasDeliveryBacklog !==
      (report.backlog.oldest_pending_delivery_age_ms !== null) ||
    (deletion.open_requests === 0 &&
      (deletion.failed_requests !== 0 || overdue !== 0)) ||
    deletion.status !== expectedDeletionStatus
  ) {
    throw new Error("The operational report does not match API v1.");
  }
  return report;
}

export function ratioText(objective: RatioSlo): string {
  if (objective.status === "no_data") {
    return "No data";
  }
  return `${((objective.good_events / objective.total_events) * 100).toFixed(1)}%`;
}

export function latencyText(objective: LatencySlo): string {
  if (objective.p95_ms === null) {
    return "No data";
  }
  if (objective.p95_ms < 60_000) {
    return `${(objective.p95_ms / 1_000).toFixed(1)}s`;
  }
  return `${(objective.p95_ms / 60_000).toFixed(1)}m`;
}

export function sloLabel(status: SloStatus): string {
  return (
    {
      no_data: "No data",
      meeting: "Meeting",
      breached: "Breached",
    } satisfies Record<SloStatus, string>
  )[status];
}

export interface MonitoringTotals {
  accountChanges: number;
  measurementChanges: number;
  delivered: number;
  acknowledged: number;
  retrying: number;
  failed: number;
}

export function summarizeTimeline(
  entries: WatchTransitionEntry[],
): MonitoringTotals {
  const totals: MonitoringTotals = {
    accountChanges: 0,
    measurementChanges: 0,
    delivered: 0,
    acknowledged: 0,
    retrying: 0,
    failed: 0,
  };
  for (const entry of entries) {
    if (entry.transition.change.class === "account_state") {
      totals.accountChanges += 1;
    } else {
      totals.measurementChanges += 1;
    }
    for (const delivery of entry.deliveries) {
      if (delivery.state === "delivered") {
        totals.delivered += 1;
        if (delivery.acknowledged_at_unix_ms !== null) {
          totals.acknowledged += 1;
        }
      } else if (
        delivery.state === "queued" ||
        delivery.state === "delivering" ||
        delivery.state === "retry_scheduled"
      ) {
        totals.retrying += 1;
      } else if (delivery.state === "permanently_failed") {
        totals.failed += 1;
      }
    }
  }
  return totals;
}

export function deliveryLabel(state: DeliveryState): string {
  return (
    {
      queued: "Queued",
      delivering: "Sending",
      retry_scheduled: "Retry scheduled",
      delivered: "Delivered",
      permanently_failed: "Dead letter",
      cancelled: "Cancelled",
    } satisfies Record<DeliveryState, string>
  )[state];
}

export function readableToken(value: string): string {
  return value.replaceAll("_", " ");
}
