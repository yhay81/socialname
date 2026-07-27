import assert from "node:assert/strict";
import test from "node:test";

import { SocialNameApiClient } from "./client.mjs";

const SEARCH_ID = "11111111-1111-4111-8111-111111111111";
const STARTED_ID = "22222222-2222-4222-8222-222222222222";
const FINISHED_ID = "33333333-3333-4333-8333-333333333333";

test("client keeps credentials in headers and builds bounded page cursors", async () => {
  const requests = [];
  const client = new SocialNameApiClient({
    baseUrl: "http://127.0.0.1:8787",
    apiKey: "private-api-key",
    fetchImpl: async (url, init) => {
      requests.push({ url: url.toString(), init });
      return Response.json({
        schema: "socialname.dev/api/v1",
        searches: [],
        next_cursor: null,
      });
    },
  });

  await client.listSearches({ limit: 10, after: SEARCH_ID });

  assert.equal(
    requests[0].url,
    `http://127.0.0.1:8787/v1/searches?limit=10&after=${SEARCH_ID}`,
  );
  assert.equal(requests[0].init.headers.authorization, "Bearer private-api-key");
  assert.doesNotMatch(requests[0].url, /private-api-key/);
});

test("SSE reconnect uses Last-Event-ID and deduplicates replay", async () => {
  const requests = [];
  const started = searchEvent(STARTED_ID, 1, { type: "started", total_targets: 1 });
  const finished = searchEvent(FINISHED_ID, 2, {
    type: "finished",
    state: "cancelled",
    progress: {
      total_targets: 1,
      completed_targets: 0,
      definitive_results: 0,
      uncertain_results: 0,
      operational_failures: 0,
    },
  });
  const responses = [
    splitSseResponse(started),
    sseResponse(started, finished),
  ];
  const client = new SocialNameApiClient({
    baseUrl: "https://api.example.test",
    apiKey: "private-api-key",
    fetchImpl: async (url, init) => {
      requests.push({ url: url.toString(), init });
      return responses.shift();
    },
  });
  const observed = [];

  const terminal = await client.streamSearchToTerminal(
    SEARCH_ID,
    async (event) => observed.push(event.sequence),
  );

  assert.equal(terminal.event_id, FINISHED_ID);
  assert.deepEqual(observed, [1, 2]);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].init.headers["last-event-id"], STARTED_ID);
});

test("untrusted API failures do not enter error messages", async () => {
  const client = new SocialNameApiClient({
    baseUrl: "https://api.example.test",
    apiKey: "private-api-key",
    fetchImpl: async () =>
      Response.json(
        {
          schema: "socialname.dev/api/v1",
          error: { code: "forbidden:private-target" },
        },
        { status: 403 },
      ),
  });

  await assert.rejects(
    client.listSearches(),
    (error) =>
      error.message === "api_error:403:invalid_response" &&
      !error.message.includes("private-target"),
  );
});

test("untrusted SSE error codes do not enter error messages", async () => {
  const client = new SocialNameApiClient({
    baseUrl: "https://api.example.test",
    apiKey: "private-api-key",
    fetchImpl: async () =>
      new Response(
        `event: stream_error\ndata: ${JSON.stringify({
          schema: "socialname.dev/api/v1",
          error: { code: "unavailable:private-target" },
        })}\n\n`,
        {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        },
      ),
  });

  await assert.rejects(
    client.streamSearchToTerminal(SEARCH_ID, async () => {}),
    (error) =>
      error.message === "stream_error:invalid_response" &&
      !error.message.includes("private-target"),
  );
});

test("non-loopback cleartext, URL credentials, and invalid keys fail closed", () => {
  assert.throws(
    () =>
      new SocialNameApiClient({
        baseUrl: "http://api.example.test",
        apiKey: "key",
      }),
    /invalid_api_url/,
  );
  assert.throws(
    () =>
      new SocialNameApiClient({
        baseUrl: "https://user:password@example.test",
        apiKey: "key",
      }),
    /invalid_api_url/,
  );
  assert.throws(
    () =>
      new SocialNameApiClient({
        baseUrl: "https://api.example.test",
        apiKey: "key with spaces",
      }),
    /invalid_api_key/,
  );
});

function searchEvent(eventId, sequence, data) {
  return {
    schema: "socialname.dev/api/v1",
    event_id: eventId,
    search_id: SEARCH_ID,
    sequence,
    emitted_at_unix_ms: sequence * 1_000,
    data,
  };
}

function sseResponse(...events) {
  const body = events
    .map(
      (event) =>
        `id: ${event.event_id}\nevent: search_event\nretry: 1000\ndata: ${JSON.stringify(event)}\n\n`,
    )
    .join("");
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

function splitSseResponse(...events) {
  const body = events
    .map(
      (event) =>
        `id: ${event.event_id}\r\nevent: search_event\r\nretry: 1000\r\ndata: ${JSON.stringify(event)}\r\n\r\n`,
    )
    .join("");
  const split = body.indexOf("\r\n") + 1;
  const encoder = new TextEncoder();
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(body.slice(0, split)));
        controller.enqueue(encoder.encode(body.slice(split)));
        controller.close();
      },
    }),
    {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    },
  );
}
