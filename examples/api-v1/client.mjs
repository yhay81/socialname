import { randomUUID } from "node:crypto";

const API_SCHEMA = "socialname.dev/api/v1";
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_SSE_FRAME_BYTES = 256 * 1024;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const API_ERROR_CODES = new Set([
  "invalid_request",
  "unauthenticated",
  "forbidden",
  "not_found",
  "conflict",
  "idempotency_conflict",
  "rate_limited",
  "quota_exceeded",
  "unavailable",
  "internal",
]);

export class SocialNameApiClient {
  constructor({ baseUrl, apiKey, fetchImpl = globalThis.fetch }) {
    this.baseUrl = validateBaseUrl(baseUrl);
    this.apiKey = validateApiKey(apiKey);
    this.fetchImpl = fetchImpl;
  }

  async createSearch(request, idempotencyKey = randomUUID()) {
    return this.#json("/v1/searches", {
      method: "POST",
      headers: { "idempotency-key": idempotencyKey },
      body: request,
    });
  }

  async listSearches({ limit = 20, after } = {}) {
    return this.#json(pagePath("/v1/searches", limit, after));
  }

  async exportSearch(searchId, { limit = 50, after } = {}) {
    requireUuid("search_id", searchId);
    return this.#json(
      pagePath(`/v1/searches/${encodeURIComponent(searchId)}/export`, limit, after),
    );
  }

  async streamSearchToTerminal(searchId, onEvent, { maximumReconnects = 10 } = {}) {
    requireUuid("search_id", searchId);
    let lastEventId;
    let lastSequence = 0;
    const seen = new Map();

    for (let reconnect = 0; reconnect <= maximumReconnects; reconnect += 1) {
      const headers = { accept: "text/event-stream" };
      if (lastEventId !== undefined) {
        headers["last-event-id"] = lastEventId;
      }
      const response = await this.#request(
        `/v1/searches/${encodeURIComponent(searchId)}/events`,
        { headers, timeoutMs: 35_000 },
      );
      if (!response.ok) {
        throw await apiFailure(response);
      }
      if (!response.headers.get("content-type")?.startsWith("text/event-stream")) {
        throw new Error("invalid_sse_content_type");
      }
      for await (const frame of decodeSse(response.body)) {
        if (frame.event === "stream_error") {
          const error = parseJson(frame.data);
          throw new Error(`stream_error:${closedApiErrorCode(error)}`);
        }
        if (frame.event !== "search_event" || frame.id === undefined) {
          throw new Error("invalid_sse_frame");
        }
        const event = parseJson(frame.data);
        requireSchema(event);
        if (
          event.search_id !== searchId ||
          !Number.isSafeInteger(event.sequence) ||
          event.sequence <= 0 ||
          !UUID.test(frame.id) ||
          event.event_id !== frame.id
        ) {
          throw new Error("invalid_search_event");
        }
        const previous = seen.get(frame.id);
        if (previous !== undefined) {
          if (previous.sequence !== event.sequence || previous.data !== frame.data) {
            throw new Error("conflicting_search_event_replay");
          }
          continue;
        }
        if (event.sequence <= lastSequence) {
          throw new Error("invalid_search_event_order");
        }
        seen.set(frame.id, { sequence: event.sequence, data: frame.data });
        lastEventId = frame.id;
        lastSequence = event.sequence;
        await onEvent(event);
        if (event.data?.type === "finished") {
          return event;
        }
      }
    }
    throw new Error("sse_reconnect_limit");
  }

  async #json(path, { method = "GET", headers = {}, body } = {}) {
    const response = await this.#request(path, {
      method,
      headers: {
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      throw await apiFailure(response);
    }
    const value = parseJson(await readBoundedText(response, MAX_JSON_BYTES));
    requireSchema(value);
    return value;
  }

  async #request(path, { timeoutMs = 30_000, ...init } = {}) {
    const url = new URL(path, this.baseUrl);
    return this.fetchImpl(url, {
      ...init,
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        ...init.headers,
      },
    });
  }
}

export async function readStdinJson(maximumBytes = 64 * 1024) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new Error("stdin_too_large");
    }
    chunks.push(chunk);
  }
  return parseJson(Buffer.concat(chunks).toString("utf8"));
}

function validateBaseUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("invalid_api_url");
  }
  const loopback =
    url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname.replace(/\/+$/, "") !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("invalid_api_url");
  }
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/`;
  return url;
}

function validateApiKey(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    [...value].some((character) => {
      const code = character.codePointAt(0);
      return code < 0x21 || code > 0x7e;
    })
  ) {
    throw new Error("invalid_api_key");
  }
  return value;
}

function pagePath(path, limit, after) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 50) {
    throw new Error("invalid_page_limit");
  }
  const query = new URLSearchParams({ limit: String(limit) });
  if (after !== undefined) {
    requireUuid("after", after);
    query.set("after", after);
  }
  return `${path}?${query}`;
}

function requireSchema(value) {
  if (value === null || typeof value !== "object" || value.schema !== API_SCHEMA) {
    throw new Error("invalid_api_schema");
  }
}

function requireUuid(field, value) {
  if (typeof value !== "string" || !UUID.test(value)) {
    throw new Error(`invalid_${field}`);
  }
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error("invalid_json");
  }
}

async function apiFailure(response) {
  let code = "invalid_response";
  try {
    const value = parseJson(await readBoundedText(response, MAX_JSON_BYTES));
    code = closedApiErrorCode(value);
  } catch {
    // Do not include an untrusted response body in errors.
  }
  return new Error(`api_error:${response.status}:${code}`);
}

function closedApiErrorCode(value) {
  const code = value?.schema === API_SCHEMA ? value?.error?.code : undefined;
  return API_ERROR_CODES.has(code) ? code : "invalid_response";
}

async function readBoundedText(response, maximumBytes) {
  if (response.body === null) {
    throw new Error("missing_response_body");
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new Error("response_too_large");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function* decodeSse(body) {
  if (body === null) {
    throw new Error("missing_sse_body");
  }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    buffer = buffer.replaceAll("\r\n", "\n");
    let boundary;
    while ((boundary = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const frame = parseSseBlock(block);
      if (frame !== undefined) {
        yield frame;
      }
    }
    if (Buffer.byteLength(buffer) > MAX_SSE_FRAME_BYTES) {
      throw new Error("sse_frame_too_large");
    }
  }
  buffer += decoder.decode();
  buffer = buffer.replaceAll("\r\n", "\n");
  if (buffer.trim() !== "") {
    throw new Error("truncated_sse_frame");
  }
}

function parseSseBlock(block) {
  const frame = { data: [] };
  for (const line of block.split("\n")) {
    if (line === "" || line.startsWith(":")) {
      continue;
    }
    const separator = line.indexOf(":");
    const field = separator < 0 ? line : line.slice(0, separator);
    let value = separator < 0 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }
    if (field === "data") {
      frame.data.push(value);
    } else if (field === "event") {
      frame.event = value;
    } else if (field === "id") {
      frame.id = value;
    }
  }
  if (frame.data.length === 0 && frame.event === undefined && frame.id === undefined) {
    return undefined;
  }
  return { ...frame, data: frame.data.join("\n") };
}
