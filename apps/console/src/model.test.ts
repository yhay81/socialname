import assert from "node:assert/strict";
import test from "node:test";
import {
  deliveryLabel,
  parseWatchPage,
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
