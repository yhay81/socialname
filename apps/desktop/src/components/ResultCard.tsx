import { useState } from "react";
import type {
  EvidenceClass,
  SearchObservation,
  SearchResult,
  SearchStatus,
  Verdict,
} from "../types";
import { Icon, type IconName } from "./Icon";

const verdictDetails: Record<
  Verdict,
  { label: string; icon: IconName; tone: string }
> = {
  found: { label: "Found", icon: "check", tone: "positive" },
  not_found: { label: "Not found", icon: "minus", tone: "neutral" },
  invalid_username: {
    label: "Invalid username",
    icon: "close",
    tone: "negative",
  },
  inconclusive: {
    label: "Inconclusive",
    icon: "warning",
    tone: "warning",
  },
};

const statusLabels: Record<SearchStatus, string> = {
  complete: "Complete",
  cache_miss: "No eligible cached observation",
  invalid_username: "Invalid username",
  rule_not_promoted: "Rule not promoted",
  rule_health_unavailable: "Rule health unavailable",
  rule_not_healthy: "Rule not healthy",
  rule_health_stale: "Rule health evidence expired",
};

const evidenceLabels: Record<EvidenceClass, string> = {
  e0_no_account_evidence: "E0 · No account evidence",
  e1_weak_signal: "E1 · Weak signal",
  e2_differential_template: "E2 · Differential template",
  e3_explicit_endpoint: "E3 · Explicit endpoint",
  e4_structured_identity: "E4 · Structured identity",
};

interface ResultCardProps {
  researchRule: boolean;
  result: SearchResult;
}

function formatTime(value: number) {
  return new Date(value).toLocaleString();
}

function observationLabel(observation: SearchObservation) {
  if (
    observation.verdict === "inconclusive" &&
    observation.inconclusiveReason
  ) {
    return observation.inconclusiveReason.replaceAll("_", " ");
  }
  return verdictDetails[observation.verdict].label;
}

export function ResultCard({ researchRule, result }: ResultCardProps) {
  const [expanded, setExpanded] = useState(false);
  const live = result.liveResult;
  const observationVerdicts = new Set(
    result.observations.map((observation) => observation.verdict),
  );
  const representative = live ?? result.observations[0];
  const conflictingCachedEvidence =
    !live && result.observations.length > 1 && observationVerdicts.size > 1;
  const verdict = conflictingCachedEvidence
    ? { label: "Conflicting cached observations", icon: "warning" as const, tone: "warning" }
    : representative
      ? {
          ...verdictDetails[representative.verdict],
          label:
            representative.verdict === "inconclusive" &&
            representative.inconclusiveReason
              ? representative.inconclusiveReason.replaceAll("_", " ")
              : verdictDetails[representative.verdict].label,
        }
      : {
          label: statusLabels[result.status],
          icon:
            result.status === "cache_miss"
              ? ("clock" as const)
              : ("warning" as const),
          tone: result.status === "cache_miss" ? "neutral" : "warning",
        };
  const primaryProbe = live?.probes.at(-1);

  return (
    <article className={`result-card result-card--${verdict.tone}`}>
      <div className="result-card__main">
        <span className={`result-status result-status--${verdict.tone}`}>
          <Icon name={verdict.icon} />
        </span>

        <div className="result-card__identity">
          <div className="result-card__title-row">
            <h3>{result.siteName}</h3>
            <span className={`tag tag--${result.source}`}>
              {result.source === "local" ? "Local probe" : "Cached"}
            </span>
            {researchRule && (
              <span className="tag tag--research">Research rule</span>
            )}
          </div>
          <p
            className="result-card__url"
            title={result.profileUrl ?? undefined}
          >
            {result.profileUrl ?? "No profile URL produced"}
          </p>
        </div>

        <div className="result-card__summary">
          <strong>{verdict.label}</strong>
          <span>
            {primaryProbe
              ? `${primaryProbe.status ?? primaryProbe.transport} · ${primaryProbe.elapsedMs} ms`
              : result.observations.length > 0
                ? `${result.observations.length} observation${result.observations.length === 1 ? "" : "s"} · offline`
                : statusLabels[result.status]}
          </span>
        </div>

        <button
          aria-expanded={expanded}
          aria-label={`${expanded ? "Hide" : "Show"} evidence for ${result.siteName}`}
          className="icon-button result-card__expand"
          onClick={() => setExpanded((value) => !value)}
          type="button"
        >
          <Icon className={expanded ? "rotate-90" : ""} name="chevron" />
        </button>
      </div>

      {expanded && (
        <div className="result-card__details">
          <dl className="evidence-grid">
            <div>
              <dt>Source</dt>
              <dd>{result.source === "local" ? "Local probe" : "Local cache"}</dd>
            </div>
            <div>
              <dt>Refresh</dt>
              <dd>{result.refreshState.replaceAll("_", " ")}</dd>
            </div>
            <div>
              <dt>Rule health</dt>
              <dd>{result.ruleHealth ?? "unavailable"}</dd>
            </div>
            <div>
              <dt>Rule hash</dt>
              <dd>
                <code title={result.ruleHash}>{result.ruleHash.slice(0, 12)}</code>
              </dd>
            </div>
            {live && (
              <>
                <div>
                  <dt>Live evidence</dt>
                  <dd>{evidenceLabels[live.evidenceClass]}</dd>
                </div>
                <div>
                  <dt>Transport</dt>
                  <dd>{primaryProbe?.transport ?? "—"}</dd>
                </div>
              </>
            )}
          </dl>

          {result.observations.length > 0 && (
            <div className="observation-list">
              <h4>Immutable observations</h4>
              {result.observations.map((observation) => (
                <dl key={observation.observationId}>
                  <div>
                    <dt>Verdict</dt>
                    <dd>{observationLabel(observation)}</dd>
                  </div>
                  <div>
                    <dt>Observed</dt>
                    <dd>{formatTime(observation.observedAtUnixMs)}</dd>
                  </div>
                  <div>
                    <dt>Expires</dt>
                    <dd>{formatTime(observation.expiresAtUnixMs)}</dd>
                  </div>
                  <div>
                    <dt>Region / rule</dt>
                    <dd>
                      {observation.regionClass} ·{" "}
                      <code title={observation.ruleHash}>
                        {observation.ruleHash.slice(0, 12)}
                      </code>
                    </dd>
                  </div>
                </dl>
              ))}
            </div>
          )}

          {live && live.matcherTrace.length > 0 && (
            <div className="matcher-trace">
              <h4>Matcher trace</h4>
              <ul>
                {live.matcherTrace.map((trace, index) => (
                  <li key={`${trace.path}-${index}`}>
                    <span
                      className={
                        trace.matched
                          ? "trace-indicator trace-indicator--matched"
                          : "trace-indicator"
                      }
                    />
                    <code>{trace.path}</code>
                    <span>{trace.detail}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </article>
  );
}
