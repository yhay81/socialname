import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  SearchCompletion,
  SearchEvent,
  SearchRequest,
  SiteSummary,
} from "./types";

export function getAppInfo(): Promise<AppInfo> {
  return invoke<AppInfo>("get_app_info");
}

export function listSites(): Promise<SiteSummary[]> {
  return invoke<SiteSummary[]>("list_sites");
}

export function startSearch(
  searchId: string,
  request: SearchRequest,
  onEvent: (event: SearchEvent) => void,
): Promise<SearchCompletion> {
  const eventChannel = new Channel<SearchEvent>();
  eventChannel.onmessage = onEvent;

  return invoke<SearchCompletion>("start_search", {
    searchId,
    request,
    onEvent: eventChannel,
  });
}

export function cancelSearch(searchId: string): Promise<boolean> {
  return invoke<boolean>("cancel_search", { searchId });
}

export function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === "string") {
    return error;
  }

  return "The desktop service returned an unexpected error.";
}
