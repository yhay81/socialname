import {
  parseTransitionPage,
  parseWatchPage,
  parseWorkspace,
} from "./model";
import {
  API_SCHEMA,
  type ApiErrorResponse,
  type WatchCreateRequest,
  type WatchListPage,
  type WatchResource,
  type WatchTransitionPage,
  type WorkspaceResource,
} from "./types";

export class ApiFailure extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, code: string, requestId?: string) {
    super(code === "invalid_credential" ? "The API key was not accepted." : "The monitoring request could not be completed.");
    this.name = "ApiFailure";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

async function request(
  path: string,
  token: string,
  init: RequestInit = {},
): Promise<unknown> {
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  headers.set("authorization", `Bearer ${token}`);
  if (init.body) {
    headers.set("content-type", "application/json");
  }
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    credentials: "omit",
    headers,
  });
  const value: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = value as Partial<ApiErrorResponse> | undefined;
    throw new ApiFailure(
      response.status,
      error?.error?.code ?? "unavailable",
      error?.request_id,
    );
  }
  return value;
}

export async function loadWorkspace(token: string): Promise<WorkspaceResource> {
  return parseWorkspace(await request("/v1/workspace", token));
}

export async function loadWatches(
  token: string,
  after?: string,
): Promise<WatchListPage> {
  const query = new URLSearchParams({ limit: "20" });
  if (after) {
    query.set("after", after);
  }
  return parseWatchPage(await request(`/v1/watches?${query}`, token));
}

export async function loadTransitions(
  token: string,
  watchId: string,
  after?: string,
): Promise<WatchTransitionPage> {
  const query = new URLSearchParams({ limit: "20" });
  if (after) {
    query.set("after", after);
  }
  return parseTransitionPage(
    await request(
      `/v1/watches/${encodeURIComponent(watchId)}/transitions?${query}`,
      token,
    ),
  );
}

export async function createWatch(
  token: string,
  payload: WatchCreateRequest,
): Promise<WatchResource> {
  const value = await request("/v1/watches", token, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  const page = parseWatchPage({
    schema: API_SCHEMA,
    watches: [value],
    next_cursor: null,
  });
  const watch = page.watches[0];
  if (!watch) {
    throw new ApiFailure(503, "unavailable");
  }
  return watch;
}

export async function setWatchState(
  token: string,
  watch: WatchResource,
  state: "active" | "paused",
): Promise<WatchResource> {
  const value = await request(
    `/v1/watches/${encodeURIComponent(watch.watch_id)}`,
    token,
    {
      method: "PATCH",
      body: JSON.stringify({
        schema: API_SCHEMA,
        expected_revision: watch.revision,
        state,
        maximum_age_ms: null,
        schedule: null,
        probe_budget: null,
        notification_endpoint_ids: null,
        retention_days: null,
      }),
    },
  );
  const page = parseWatchPage({
    schema: API_SCHEMA,
    watches: [value],
    next_cursor: null,
  });
  const updated = page.watches[0];
  if (!updated) {
    throw new ApiFailure(503, "unavailable");
  }
  return updated;
}
