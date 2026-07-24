import { useState } from "react";
import type { EvidenceClass, SearchResult, Verdict } from "../types";
import { Icon, type IconName } from "./Icon";

const verdictDetails: Record<Verdict, { label: string; icon: IconName; tone: string }> = {
  found: { label: "Found", icon: "check", tone: "positive" },
  not_found: { label: "Not found", icon: "minus", tone: "neutral" },
  invalid_username: { label: "Invalid username", icon: "close", tone: "negative" },
  inconclusive: { label: "Inconclusive", icon: "warning", tone: "warning" },
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

export function ResultCard({ researchRule, result }: ResultCardProps) {
  const [expanded, setExpanded] = useState(false);
  const verdict = {
    ...verdictDetails[result.verdict],
    label:
      result.verdict === "inconclusive" && result.inconclusiveReason
        ? result.inconclusiveReason.replaceAll("_", " ")
        : verdictDetails[result.verdict].label,
  };
  const primaryProbe = result.probes.at(-1);

  return (
    <article className={`result-card result-card--${verdict.tone}`}>
      <div className="result-card__main">
        <span className={`result-status result-status--${verdict.tone}`}>
          <Icon name={verdict.icon} />
        </span>

        <div className="result-card__identity">
          <div className="result-card__title-row">
            <h3>{result.siteName}</h3>
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
              : "No response"}
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
              <dt>Evidence</dt>
              <dd>{evidenceLabels[result.evidenceClass]}</dd>
            </div>
            <div>
              <dt>Decision</dt>
              <dd>{result.inconclusiveReason ?? result.verdict}</dd>
            </div>
            <div>
              <dt>Transport</dt>
              <dd>{primaryProbe?.transport ?? "—"}</dd>
            </div>
            <div>
              <dt>Content type</dt>
              <dd>{primaryProbe?.contentType ?? "—"}</dd>
            </div>
          </dl>

          {result.matcherTrace.length > 0 && (
            <div className="matcher-trace">
              <h4>Matcher trace</h4>
              <ul>
                {result.matcherTrace.map((trace, index) => (
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
