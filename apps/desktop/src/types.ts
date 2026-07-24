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
  source: string;
  profileUrl: string | null;
  ruleHash: string;
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
  executionMode: "local";
  synchronization: "never";
}
