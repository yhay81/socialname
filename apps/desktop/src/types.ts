export type Verdict =
  | "found"
  | "not_found"
  | "invalid_username"
  | "inconclusive";

export type InconclusiveReason =
  | "blocked"
  | "rate_limited"
  | "timeout"
  | "dns"
  | "connect"
  | "tls"
  | "redirect_rejected"
  | "response_too_large"
  | "decode"
  | "site_changed"
  | "no_rule_matched"
  | "conflicting_evidence";

export type EvidenceClass =
  | "e0_no_account_evidence"
  | "e1_weak_signal"
  | "e2_differential_template"
  | "e3_explicit_endpoint"
  | "e4_structured_identity";

export type TransportOutcome =
  | "completed"
  | "blocked"
  | "rate_limited"
  | "timeout"
  | "dns"
  | "connect"
  | "tls"
  | "redirect_rejected"
  | "response_too_large"
  | "decode";

export type AccountNamespace =
  | "person"
  | "organization"
  | "person_or_organization"
  | "developer_account"
  | "federated_account"
  | "channel";

export interface SiteSummary {
  id: string;
  name: string;
  homepage: string;
  namespace: AccountNamespace;
  enabled: boolean;
  tags: string[];
  notes: string;
}

export interface SearchRequest {
  username: string;
  siteIds: string[];
  allowDiscovery: boolean;
  policy: SearchPolicy;
}

export type SearchSource = "local" | "cache" | "hybrid";
export type ResultSource = "local" | "cache";
export type SyncPolicy = "never";
export type SearchStatus =
  | "complete"
  | "cache_miss"
  | "cache_unavailable"
  | "invalid_username"
  | "rule_not_promoted"
  | "rule_health_unavailable"
  | "rule_not_healthy"
  | "rule_health_stale";
export type RefreshState = "completed" | "not_requested" | "pending";
export type RuleHealth =
  | "healthy"
  | "degraded"
  | "quarantined"
  | "recovering";

export interface SearchPolicy {
  source: SearchSource;
  sync: SyncPolicy;
  regionClass: string;
  maximumAgeMs: number;
}

export interface ProbeSummary {
  probeId: string;
  transport: TransportOutcome;
  status: number | null;
  finalUrl: string | null;
  contentType: string | null;
  bodyBytes: number;
  bodyTruncated: boolean;
  elapsedMs: number;
}

export interface MatcherTrace {
  path: string;
  matched: boolean;
  detail: string;
}

export interface SearchResult {
  siteId: string;
  siteName: string;
  username: string;
  source: ResultSource;
  requestedSource: SearchSource;
  sync: SyncPolicy;
  status: SearchStatus;
  refreshState: RefreshState;
  profileUrl: string | null;
  ruleHash: string;
  rulePromoted: boolean;
  ruleHealth: RuleHealth | null;
  ruleHealthExpiresAtUnixMs: number | null;
  observations: SearchObservation[];
  liveResult: LiveSearchResult | null;
}

export interface SearchObservation {
  observationId: string;
  source: ResultSource;
  verdict: Verdict;
  inconclusiveReason: InconclusiveReason | null;
  evidenceClass: EvidenceClass;
  evidenceDigest: string;
  observedAtUnixMs: number;
  expiresAtUnixMs: number;
  regionClass: string;
  ruleHash: string;
  ruleHealthGreen: boolean;
  cachedAtUnixMs: number | null;
  lastAccessedAtUnixMs: number | null;
  accessCount: number | null;
}

export interface LiveSearchResult {
  verdict: Verdict;
  inconclusiveReason: InconclusiveReason | null;
  evidenceClass: EvidenceClass;
  evidenceDigest: string;
  matcherTrace: MatcherTrace[];
  probes: ProbeSummary[];
}

export interface SearchCompletion {
  total: number;
  completed: number;
  found: number;
  notFound: number;
  inconclusive: number;
  invalidUsername: number;
  cacheHits: number;
  cacheMisses: number;
  unavailable: number;
  cancelled: boolean;
}

export type SearchEvent =
  | {
      event: "started";
      data: {
        total: number;
      };
    }
  | {
      event: "result";
      data: {
        result: SearchResult;
      };
    }
  | {
      event: "finished";
      data: {
        summary: SearchCompletion;
      };
    };

export interface AppInfo {
  version: string;
  rulePackHash: string;
  availableSources: SearchSource[];
  defaultPolicy: SearchPolicy;
  synchronization: SyncPolicy;
  cacheReady: boolean;
  cacheError: string | null;
}
