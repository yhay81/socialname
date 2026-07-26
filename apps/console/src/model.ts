import {
  API_SCHEMA,
  type DeliveryState,
  type NotificationAcknowledgementResource,
  type WatchListPage,
  type WatchTransitionEntry,
  type WatchTransitionPage,
  type WorkspaceResource,
} from "./types.ts";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
