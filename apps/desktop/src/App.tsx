import { useEffect, useMemo, useRef, useState } from "react";
import {
  cancelSearch,
  describeError,
  getAppInfo,
  listSites,
  startSearch,
} from "./api";
import { Icon } from "./components/Icon";
import { ResultCard } from "./components/ResultCard";
import type {
  AppInfo,
  SearchEvent,
  SearchResult,
  SearchSource,
  SiteSummary,
  SyncPolicy,
  Verdict,
} from "./types";

const verdictOrder: Verdict[] = [
  "found",
  "not_found",
  "inconclusive",
  "invalid_username",
];

// How strong an answer a site's rule can produce at best. This is a property
// of the check itself, so it is knowable before searching: a rule that reads
// the site's own structured identity can say far more than one that only sees
// a status code.
type EvidenceTier = "structured" | "body" | "redirect" | "status";

const tierLabels: Record<EvidenceTier, string> = {
  structured: "Structured identity",
  body: "Page content",
  redirect: "Redirect target",
  status: "Status code only",
};

const tierHints: Record<EvidenceTier, string> = {
  structured: "The site's own response names the exact account.",
  body: "A marker in the page text distinguishes present from absent.",
  redirect: "Absence is inferred from where the site redirects.",
  status: "Only the response status separates present from absent.",
};

const tierOrder: EvidenceTier[] = ["structured", "body", "redirect", "status"];

function siteTier(site: SiteSummary): EvidenceTier {
  if (site.tags.includes("check-message")) {
    return "body";
  }
  if (site.tags.includes("check-response-url")) {
    return "redirect";
  }
  if (site.tags.includes("check-status-code")) {
    return "status";
  }
  // Hand-authored rules read a structured response rather than a generic page.
  return "structured";
}

function createSearchId() {
  return crypto.randomUUID();
}

function App() {
  const [appInfo, setAppInfo] = useState<AppInfo>();
  const [sites, setSites] = useState<SiteSummary[]>([]);
  const [selectedSites, setSelectedSites] = useState<Set<string>>(new Set());
  const [username, setUsername] = useState("");
  const [siteFilter, setSiteFilter] = useState("");
  const [tierFilter, setTierFilter] = useState<EvidenceTier | "all">("all");
  const [allowDiscovery, setAllowDiscovery] = useState(false);
  const [source, setSource] = useState<SearchSource>("local");
  const [sync, setSync] = useState<SyncPolicy>("never");
  const [apiUrl, setApiUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [consentGrantId, setConsentGrantId] = useState("");
  const [regionClass, setRegionClass] = useState("local");
  const [sharedAcknowledged, setSharedAcknowledged] = useState(false);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [activeSearchId, setActiveSearchId] = useState<string>();
  const [totalSites, setTotalSites] = useState(0);
  const [cancelled, setCancelled] = useState(false);
  const [error, setError] = useState<string>();
  const activeSearchRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    void Promise.all([getAppInfo(), listSites()])
      .then(([info, availableSites]) => {
        setAppInfo(info);
        setSites(availableSites);
        setSelectedSites(new Set(availableSites.map((site) => site.id)));
      })
      .catch((reason: unknown) => setError(describeError(reason)));
  }, []);

  const filteredSites = useMemo(() => {
    const query = siteFilter.trim().toLowerCase();
    return sites.filter((site) => {
      if (tierFilter !== "all" && siteTier(site) !== tierFilter) {
        return false;
      }
      if (!query) {
        return true;
      }
      return (
        site.name.toLowerCase().includes(query) ||
        site.id.toLowerCase().includes(query)
      );
    });
  }, [siteFilter, sites, tierFilter]);

  const tierCounts = useMemo(() => {
    const counts = Object.fromEntries(
      tierOrder.map((tier) => [tier, 0]),
    ) as Record<EvidenceTier, number>;
    for (const site of sites) {
      counts[siteTier(site)] += 1;
    }
    return counts;
  }, [sites]);

  const verdictCounts = useMemo(() => {
    const counts = Object.fromEntries(
      verdictOrder.map((verdict) => [verdict, 0]),
    ) as Record<Verdict, number>;
    for (const result of results) {
      if (result.liveResult) {
        counts[result.liveResult.verdict] += 1;
      } else {
        for (const observation of result.observations) {
          counts[observation.verdict] += 1;
        }
      }
    }
    return counts;
  }, [results]);

  const running = activeSearchId !== undefined;
  const discoverySitesSelected = sites.some(
    (site) => selectedSites.has(site.id) && !site.enabled,
  );
  const usesManagedService =
    source === "remote" || (source === "hybrid" && sync !== "never");
  const performsLocalProbe =
    source === "local" || (source === "hybrid" && sync === "never");
  const policyValid =
    ((source === "local" || source === "cache") && sync === "never") ||
    (source === "remote" && sync !== "never") ||
    source === "hybrid";
  const managedAccessReady =
    !usesManagedService ||
    (apiUrl.trim().length > 0 &&
      apiKey.length > 0 &&
      consentGrantId.trim().length > 0 &&
      regionClass.trim().length > 0 &&
      (sync !== "shared" || sharedAcknowledged));
  const canSearch =
    !running &&
    policyValid &&
    managedAccessReady &&
    username.trim().length > 0 &&
    selectedSites.size > 0 &&
    (source !== "cache" || appInfo?.cacheReady === true) &&
    (!performsLocalProbe || !discoverySitesSelected || allowDiscovery);

  function handleEvent(searchId: string, event: SearchEvent) {
    if (activeSearchRef.current !== searchId) {
      return;
    }

    if (event.event === "started") {
      setTotalSites(event.data.total);
    } else if (event.event === "result") {
      setResults((current) => {
        const index = current.findIndex(
          (result) => result.siteId === event.data.result.siteId,
        );
        if (index === -1) {
          return [...current, event.data.result];
        }
        return current.map((result, resultIndex) =>
          resultIndex === index ? event.data.result : result,
        );
      });
    } else {
      setCancelled(event.data.summary.cancelled);
    }
  }

  async function handleSearch() {
    if (!canSearch) {
      return;
    }

    const searchId = createSearchId();
    activeSearchRef.current = searchId;
    setActiveSearchId(searchId);
    setResults([]);
    setTotalSites(selectedSites.size);
    setCancelled(false);
    setError(undefined);

    try {
      const completion = await startSearch(
        searchId,
        {
          username: username.trim(),
          siteIds: [...selectedSites],
          allowDiscovery,
          policy: {
            source,
            sync,
            regionClass: regionClass.trim(),
            maximumAgeMs: 86_400_000,
          },
          managedAccess: usesManagedService
            ? {
                apiUrl: apiUrl.trim(),
                apiKey,
                consentGrantId: consentGrantId.trim(),
              }
            : null,
        },
        (event) => handleEvent(searchId, event),
      );
      setCancelled(completion.cancelled);
      setTotalSites(completion.total);
    } catch (reason: unknown) {
      setError(describeError(reason));
    } finally {
      if (activeSearchRef.current === searchId) {
        activeSearchRef.current = undefined;
        setActiveSearchId(undefined);
      }
    }
  }

  async function handleCancel() {
    const searchId = activeSearchRef.current;
    if (!searchId) {
      return;
    }

    try {
      await cancelSearch(searchId);
    } catch (reason: unknown) {
      setError(describeError(reason));
    }
  }

  function toggleSite(siteId: string) {
    if (running) {
      return;
    }
    setSelectedSites((current) => {
      const next = new Set(current);
      if (next.has(siteId)) {
        next.delete(siteId);
      } else {
        next.add(siteId);
      }
      return next;
    });
  }

  const completed = results.filter(
    (result) => result.refreshState !== "pending",
  ).length;
  const progress = totalSites === 0 ? 0 : (completed / totalSites) * 100;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true">
            <span />
          </span>
          <div>
            <strong>SocialName</strong>
            <span>Identity intelligence</span>
          </div>
        </div>

        <div className="topbar__status">
          <span className="status-pill">
            <span className="status-dot" />
            {source === "local"
              ? "Local probe"
              : source === "cache"
                ? "Offline cache"
                : source === "remote"
                  ? "Managed remote"
                  : sync === "never"
                    ? "Cached-first local"
                    : "Remote-assisted"}
          </span>
          <span className="status-pill status-pill--muted">
            <Icon name="shield" />
            Sync: {sync}
          </span>
        </div>
      </header>

      <main className="workspace">
        <aside className="site-panel">
          <div className="site-panel__heading">
            <div>
              <p className="eyebrow">Rule pack</p>
              <h2>Search scope</h2>
            </div>
            <span className="site-count">
              {selectedSites.size}/{sites.length}
            </span>
          </div>

          <label className="filter-field">
            <span className="sr-only">Filter sites</span>
            <Icon name="search" />
            <input
              onChange={(event) => setSiteFilter(event.target.value)}
              placeholder="Filter sites"
              type="search"
              value={siteFilter}
            />
          </label>

          <div className="tier-filter" role="group" aria-label="Evidence strength">
            <button
              aria-pressed={tierFilter === "all"}
              className={tierFilter === "all" ? "tier-chip tier-chip--on" : "tier-chip"}
              onClick={() => setTierFilter("all")}
              type="button"
            >
              All {sites.length}
            </button>
            {tierOrder.map((tier) => (
              <button
                aria-pressed={tierFilter === tier}
                className={tierFilter === tier ? "tier-chip tier-chip--on" : "tier-chip"}
                key={tier}
                onClick={() => setTierFilter(tier)}
                title={tierHints[tier]}
                type="button"
              >
                {tierLabels[tier]} {tierCounts[tier]}
              </button>
            ))}
          </div>

          <div className="selection-actions">
            {/* Selection follows what is on screen: with hundreds of sites,
                acting on the hidden ones would be a surprise. */}
            <button
              disabled={running}
              onClick={() =>
                setSelectedSites((current) => {
                  const next = new Set(current);
                  for (const site of filteredSites) {
                    next.add(site.id);
                  }
                  return next;
                })
              }
              type="button"
            >
              Select shown
            </button>
            <span />
            <button
              disabled={running}
              onClick={() =>
                setSelectedSites((current) => {
                  const next = new Set(current);
                  for (const site of filteredSites) {
                    next.delete(site.id);
                  }
                  return next;
                })
              }
              type="button"
            >
              Clear shown
            </button>
          </div>

          <div className="site-list">
            {filteredSites.map((site) => (
              <label className="site-option" key={site.id}>
                <input
                  checked={selectedSites.has(site.id)}
                  disabled={running}
                  onChange={() => toggleSite(site.id)}
                  type="checkbox"
                />
                <span className="checkbox">
                  <Icon name="check" />
                </span>
                <span className="site-option__name">
                  <strong>{site.name}</strong>
                  <small title={tierHints[siteTier(site)]}>
                    {tierLabels[siteTier(site)]}
                  </small>
                </span>
                <span
                  className={
                    site.enabled
                      ? "readiness-dot readiness-dot--ready"
                      : "readiness-dot"
                  }
                  title={
                    site.enabled ? "Production-ready" : "Research rule"
                  }
                />
              </label>
            ))}
          </div>

          <div className="pack-meta">
            <span>Embedded rule pack</span>
            <code>{appInfo?.rulePackHash.slice(0, 12) ?? "loading…"}</code>
          </div>
        </aside>

        <section className="content">
          <div className="search-hero">
            <p className="eyebrow">Username observation search</p>
            <h1>Trace an identity across the open web.</h1>
            <p className="search-hero__description">
              {source === "local"
                ? "Requests run from this device. Results remain local and are stored only in this installation's cache."
                : source === "cache"
                  ? "Cache lookup is strictly offline. It never falls through to a network probe and only returns fresh, rule-matched observations."
                  : source === "remote"
                    ? "The target is sent to your configured SocialName service. Managed results retain their exact cloud, assertion, or probe source."
                    : sync === "never"
                      ? "Eligible cached evidence appears first, then this device performs a separately labelled local refresh."
                      : "Eligible device cache appears first, then the target is sent to your configured SocialName service for a separately labelled managed result."}
            </p>

            <div
              aria-label="Search source"
              className="source-policy"
              role="group"
            >
              <button
                aria-pressed={source === "local"}
                disabled={running}
                onClick={() => setSource("local")}
                type="button"
              >
                <Icon name="globe" />
                <span>
                  <strong>Local probe</strong>
                  <small>Contact selected public sites</small>
                </span>
              </button>
              <button
                aria-pressed={source === "cache"}
                disabled={running || appInfo?.cacheReady !== true}
                onClick={() => setSource("cache")}
                title={appInfo?.cacheError ?? undefined}
                type="button"
              >
                <Icon name="clock" />
                <span>
                  <strong>Offline cache</strong>
                  <small>
                    {appInfo?.cacheReady === false
                      ? "Cache unavailable"
                      : "No network refresh"}
                  </small>
                </span>
              </button>
              <button
                aria-pressed={source === "remote"}
                disabled={running}
                onClick={() => setSource("remote")}
                type="button"
              >
                <Icon name="globe" />
                <span>
                  <strong>Managed remote</strong>
                  <small>Target leaves this device</small>
                </span>
              </button>
              <button
                aria-pressed={source === "hybrid"}
                disabled={running}
                onClick={() => setSource("hybrid")}
                type="button"
              >
                <Icon name="clock" />
                <span>
                  <strong>Hybrid</strong>
                  <small>Cache first, then selected assist</small>
                </span>
              </button>
            </div>

            <div
              aria-label="Synchronization policy"
              className="sync-policy"
              role="group"
            >
              {(["never", "private", "shared"] as const).map((value) => (
                <button
                  aria-pressed={sync === value}
                  disabled={running}
                  key={value}
                  onClick={() => {
                    setSync(value);
                    if (value !== "shared") {
                      setSharedAcknowledged(false);
                    }
                  }}
                  type="button"
                >
                  <strong>{value}</strong>
                  <small>
                    {value === "never"
                      ? "No SocialName sync"
                      : value === "private"
                        ? "Private history"
                        : "Eligible shared evidence"}
                  </small>
                </button>
              ))}
            </div>

            {!policyValid && (
              <p className="policy-note" role="status">
                {source === "remote"
                  ? "Remote sends the target to SocialName, so choose private or shared sync."
                  : "Local and cache sources do not upload; choose sync never or use hybrid."}
              </p>
            )}

            {usesManagedService && (
              <div className="managed-access">
                <div>
                  <label>
                    <span>API URL</span>
                    <input
                      autoCapitalize="none"
                      autoComplete="off"
                      disabled={running}
                      onChange={(event) => setApiUrl(event.target.value)}
                      placeholder="https://api.example.com/"
                      spellCheck={false}
                      value={apiUrl}
                    />
                  </label>
                  <label>
                    <span>Region class</span>
                    <input
                      autoCapitalize="none"
                      autoComplete="off"
                      disabled={running}
                      onChange={(event) => setRegionClass(event.target.value)}
                      placeholder="jp"
                      spellCheck={false}
                      value={regionClass}
                    />
                  </label>
                </div>
                <div>
                  <label>
                    <span>API key · session only</span>
                    <input
                      autoComplete="off"
                      disabled={running}
                      onChange={(event) => setApiKey(event.target.value)}
                      type="password"
                      value={apiKey}
                    />
                  </label>
                  <label>
                    <span>Consent grant ID</span>
                    <input
                      autoCapitalize="none"
                      autoComplete="off"
                      disabled={running}
                      onChange={(event) =>
                        setConsentGrantId(event.target.value)
                      }
                      spellCheck={false}
                      value={consentGrantId}
                    />
                  </label>
                </div>
                <p>
                  Credentials stay in this app session and are sent only to the
                  configured API origin. The native client refuses redirects.
                </p>
              </div>
            )}

            {usesManagedService && sync === "shared" && (
              <label className="research-consent">
                <input
                  checked={sharedAcknowledged}
                  disabled={running}
                  onChange={(event) =>
                    setSharedAcknowledged(event.target.checked)
                  }
                  type="checkbox"
                />
                <span className="toggle" />
                <span>
                  <strong>Use the shared-observation consent grant</strong>
                  <small>
                    Shared sync may contribute eligible evidence under the
                    selected purpose-specific grant. Matching usernames still
                    do not prove common ownership.
                  </small>
                </span>
              </label>
            )}

            <form
              className="search-form"
              onSubmit={(event) => {
                event.preventDefault();
                void handleSearch();
              }}
            >
              <label className="username-field">
                <span>@</span>
                <input
                  aria-label="Username"
                  autoCapitalize="none"
                  autoComplete="off"
                  autoCorrect="off"
                  disabled={running}
                  maxLength={256}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="username"
                  spellCheck={false}
                  value={username}
                />
              </label>
              {running ? (
                <button
                  className="button button--cancel"
                  onClick={() => void handleCancel()}
                  type="button"
                >
                  <Icon name="close" />
                  Cancel
                </button>
              ) : (
                <button
                  className="button button--primary"
                  disabled={!canSearch}
                >
                  <Icon name="search" />
                  Search {selectedSites.size} sites
                </button>
              )}
            </form>

            {performsLocalProbe && discoverySitesSelected && (
              <label className="research-consent">
                <input
                  checked={allowDiscovery}
                  disabled={running}
                  onChange={(event) => setAllowDiscovery(event.target.checked)}
                  type="checkbox"
                />
                <span className="toggle" />
                <span>
                  <strong>Enable research rules</strong>
                  <small>
                    These rules are under evaluation and can produce uncertain
                    or incorrect results. Network requests go directly to
                    selected sites.
                  </small>
                </span>
              </label>
            )}
          </div>

          {error && (
            <div className="error-banner" role="alert">
              <Icon name="warning" />
              <span>{error}</span>
              <button
                aria-label="Dismiss error"
                onClick={() => setError(undefined)}
                type="button"
              >
                <Icon name="close" />
              </button>
            </div>
          )}

          <section className="results-section" aria-live="polite">
            <div className="results-heading">
              <div>
                <p className="eyebrow">
                  {source === "local"
                    ? "Local evidence"
                    : source === "cache"
                      ? "Cached evidence"
                      : source === "remote"
                        ? "Managed evidence"
                        : sync === "never"
                          ? "Cached-first local evidence"
                          : "Remote-assisted evidence"}
                </p>
                <h2>
                  {running
                    ? `Searching ${completed} of ${totalSites}`
                    : results.length > 0
                      ? `${results.length} results`
                      : "Results"}
                </h2>
              </div>

              {results.length > 0 && (
                <div className="result-totals" aria-label="Result summary">
                  <span className="result-total result-total--positive">
                    {verdictCounts.found} found
                  </span>
                  <span>{verdictCounts.not_found} absent</span>
                  <span>
                    {verdictCounts.inconclusive +
                      verdictCounts.invalid_username}{" "}
                    unresolved
                  </span>
                </div>
              )}
            </div>

            {(running || results.length > 0) && (
              <div
                aria-label={`${Math.round(progress)}% complete`}
                aria-valuemax={100}
                aria-valuemin={0}
                aria-valuenow={Math.round(progress)}
                className="progress-track"
                role="progressbar"
              >
                <span style={{ width: `${progress}%` }} />
              </div>
            )}

            {results.length === 0 && !running ? (
              <div className="empty-state">
                <span className="empty-state__icon">
                  <Icon name="globe" />
                </span>
                <h3>No search has run yet</h3>
                <p>
                  Choose a source and sites, enter a username, and inspect every
                  result with its source and freshness.
                </p>
              </div>
            ) : (
              <div className="results-list">
                {results.map((result) => (
                  <ResultCard
                    key={result.siteId}
                    researchRule={
                      !sites.find((site) => site.id === result.siteId)?.enabled
                    }
                    result={result}
                  />
                ))}
                {running &&
                  Array.from({
                    length: Math.min(3, Math.max(0, totalSites - completed)),
                  }).map((_, index) => (
                    <div
                      className="result-skeleton"
                      key={`skeleton-${index}`}
                    >
                      <span />
                      <div>
                        <span />
                        <span />
                      </div>
                    </div>
                  ))}
              </div>
            )}

            {cancelled && !running && (
              <p className="cancelled-note">
                Search cancelled. Completed evidence is retained in this view.
              </p>
            )}
          </section>
        </section>
      </main>
    </div>
  );
}

export default App;
