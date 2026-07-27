import assert from "node:assert/strict";
import test from "node:test";
import {
  deliveryLabel,
  latencyText,
  parseOperationalReport,
  parseOrganization,
  parseOrganizationAuditPage,
  parseOrganizationMemberPage,
  parseRetentionPolicy,
  parseTransitionReviewPage,
  parseWatchPage,
  ratioText,
  sloLabel,
  summarizeTimeline,
} from "./model.ts";
import { API_SCHEMA, type WatchTransitionEntry } from "./types.ts";

test("timeline totals keep account, measurement, retry, and failure separate", () => {
  const entries = [
    {
      transition: {
        change: { class: "account_state" },
      },
      deliveries: [
        { state: "delivered", acknowledged_at_unix_ms: 2_000 },
      ],
    },
    {
      transition: {
        change: { class: "measurement_health" },
      },
      deliveries: [
        { state: "retry_scheduled" },
        { state: "permanently_failed" },
      ],
    },
  ] as unknown as WatchTransitionEntry[];
  assert.deepEqual(summarizeTimeline(entries), {
    accountChanges: 1,
    measurementChanges: 1,
    delivered: 1,
    acknowledged: 1,
    retrying: 1,
    failed: 1,
  });
  assert.equal(deliveryLabel("permanently_failed"), "Dead letter");
});

test("bounded API parser rejects an unversioned or oversized watch page", () => {
  assert.throws(() => parseWatchPage({ watches: [], next_cursor: null }));
  assert.throws(() =>
    parseWatchPage({
      schema: API_SCHEMA,
      watches: Array.from({ length: 51 }, () => ({})),
      next_cursor: null,
    }),
  );
});

const teamMember = {
  schema: API_SCHEMA,
  organization_id: "organization_01",
  membership_id: "membership_01",
  display_name: "Owner",
  role: "owner",
  state: "active",
  revision: 1,
  created_at_unix_ms: 1_000,
  updated_at_unix_ms: 1_000,
};

test("team parsers keep member subjects and audit details outside responses", () => {
  const organization = parseOrganization({
    schema: API_SCHEMA,
    organization_id: "organization_01",
    slug: "example",
    display_name: "Example",
    state: "active",
    authenticated_member: teamMember,
  });
  assert.equal(organization.authenticated_member.role, "owner");

  const members = parseOrganizationMemberPage({
    schema: API_SCHEMA,
    members: [teamMember],
    next_cursor: "membership_01",
  });
  assert.equal(members.members.length, 1);

  const leakedSubject = structuredClone(teamMember) as Record<string, unknown>;
  leakedSubject.subject_reference = "forbidden";
  assert.throws(() =>
    parseOrganizationMemberPage({
      schema: API_SCHEMA,
      members: [leakedSubject],
      next_cursor: null,
    }),
  );

  const retention = parseRetentionPolicy({
    schema: API_SCHEMA,
    organization_id: "organization_01",
    revision: 2,
    minimum_watch_retention_days: 30,
    maximum_watch_retention_days: 365,
    updated_at_unix_ms: 2_000,
  });
  assert.equal(retention.maximum_watch_retention_days, 365);

  assert.throws(() =>
    parseOrganizationAuditPage({
      schema: API_SCHEMA,
      events: [
        {
          schema: API_SCHEMA,
          audit_event_id: "audit_01",
          actor: { kind: "system" },
          action: "transition.review.opened",
          resource_kind: "transition_review",
          resource_id: "review_01",
          occurred_at_unix_ms: 2_000,
          details: { target: "forbidden" },
        },
      ],
      next_cursor: null,
    }),
  );

  assert.throws(() =>
    parseOrganizationAuditPage({
      schema: API_SCHEMA,
      events: [
        {
          schema: API_SCHEMA,
          audit_event_id: "audit_01",
          actor: { kind: "system", membership_id: "forbidden" },
          action: "transition.review.opened",
          resource_kind: "transition_review",
          resource_id: "review_01",
          occurred_at_unix_ms: 2_000,
        },
      ],
      next_cursor: null,
    }),
  );
});

test("team review parser enforces confirmed-account workflow relations", () => {
  const reviewPage = {
    schema: API_SCHEMA,
    reviews: [
      {
        schema: API_SCHEMA,
        review_id: "review_01",
        transition: {
          schema: API_SCHEMA,
          transition_id: "transition_01",
          target: { username: "private-target", site_id: "github" },
          change: {
            class: "account_state",
            from: "not_found",
            to: "found",
          },
          confirmation: { status: "confirmed", basis: "managed_e4" },
        },
        state: "acknowledged",
        revision: 2,
        assigned_membership_id: "membership_01",
        acknowledged_by_membership_id: "membership_01",
        acknowledged_at_unix_ms: 2_000,
        resolved_by_membership_id: null,
        resolved_at_unix_ms: null,
        resolution: null,
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 2_000,
      },
    ],
    next_cursor: "review_01",
  };
  assert.equal(parseTransitionReviewPage(reviewPage).reviews.length, 1);

  const wrongAssignee = structuredClone(reviewPage);
  wrongAssignee.reviews[0].acknowledged_by_membership_id = "membership_02";
  assert.throws(() => parseTransitionReviewPage(wrongAssignee));

  const measurementReview = structuredClone(reviewPage);
  measurementReview.reviews[0].transition.change.class =
    "measurement_health";
  assert.throws(() => parseTransitionReviewPage(measurementReview));
});

const operationalReport = {
  schema: API_SCHEMA,
  window: "24h",
  generated_at_unix_ms: 100_000_000,
  window_started_at_unix_ms: 13_600_000,
  backlog: {
    active_watches: 2,
    paused_watches: 1,
    deleting_watches: 0,
    planned_watch_runs: 1,
    running_watch_runs: 0,
    queued_probe_jobs: 1,
    leased_probe_jobs: 0,
    retry_wait_probe_jobs: 0,
    oldest_pending_probe_job_age_ms: 1_000,
    queued_email_deliveries: 0,
    delivering_email_deliveries: 0,
    retry_scheduled_email_deliveries: 0,
    queued_webhook_deliveries: 0,
    delivering_webhook_deliveries: 0,
    retry_scheduled_webhook_deliveries: 0,
    oldest_pending_delivery_age_ms: null,
  },
  objectives: {
    watch_run_success: {
      status: "meeting",
      good_events: 99,
      total_events: 100,
      target_basis_points: 9_900,
    },
    delivery_success: {
      email: {
        status: "meeting",
        good_events: 1,
        total_events: 1,
        target_basis_points: 9_900,
      },
      webhook: {
        status: "no_data",
        good_events: 0,
        total_events: 0,
        target_basis_points: 9_900,
      },
    },
    transition_to_delivery_latency: {
      email: {
        status: "meeting",
        samples: 1,
        p95_ms: 250_000,
        target_ms: 300_000,
      },
      webhook: {
        status: "no_data",
        samples: 0,
        p95_ms: null,
        target_ms: 300_000,
      },
    },
    deletion_deadline_health: {
      status: "no_data",
      open_requests: 0,
      failed_requests: 0,
      overdue: {
        hide: 0,
        support_withdrawal: 0,
        primary_delete: 0,
        derived_rebuild: 0,
        backup_expiry: 0,
      },
      target_max_overdue_milestones: 0,
    },
  },
};

test("operational parser and labels preserve no-data and SLO status", () => {
  const report = parseOperationalReport(structuredClone(operationalReport));
  assert.equal(ratioText(report.objectives.watch_run_success), "99.0%");
  assert.equal(ratioText(report.objectives.delivery_success.webhook), "No data");
  assert.equal(
    latencyText(report.objectives.transition_to_delivery_latency.email),
    "4.2m",
  );
  assert.equal(
    latencyText({
      status: "breached",
      samples: 1,
      p95_ms: 17_910_000_000,
      target_ms: 300_000,
    }),
    "207.3d",
  );
  assert.equal(sloLabel("breached"), "Breached");
});

test("operational parser rejects relabelled or structurally partial reports", () => {
  const relabelled = structuredClone(operationalReport);
  relabelled.objectives.delivery_success.webhook.status = "meeting";
  assert.throws(() => parseOperationalReport(relabelled));

  const missingBacklogField = structuredClone(operationalReport);
  delete (missingBacklogField.backlog as Partial<
    typeof missingBacklogField.backlog
  >).active_watches;
  assert.throws(() => parseOperationalReport(missingBacklogField));

  const impossibleDeletion = structuredClone(operationalReport);
  impossibleDeletion.objectives.deletion_deadline_health.overdue.hide = 1;
  assert.throws(() => parseOperationalReport(impossibleDeletion));

  const impossibleWindow = structuredClone(operationalReport);
  impossibleWindow.window_started_at_unix_ms = 0;
  impossibleWindow.generated_at_unix_ms = 86_400_000;
  assert.throws(() => parseOperationalReport(impossibleWindow));
});
