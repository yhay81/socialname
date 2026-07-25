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
  Verdict,
} from "./types";

const verdictOrder: Verdict[] = [
  "found",
  "not_found",
  "inconclusive",
  "invalid_username",
];

function createSearchId() {
  return crypto.randomUUID();
}

function App() {
  const [appInfo, setAppInfo] = useState<AppInfo>();
  const [sites, setSites] = useState<SiteSummary[]>([]);
  const [selectedSites, setSelectedSites] = useState<Set<string>>(new Set());
  const [username, setUsername] = useState("");
  const [siteFilter, setSiteFilter] = useState("");
  const [allowDiscovery, setAllowDiscovery] = useState(false);
  const [source, setSource] = useState<SearchSource>("local");
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
    if (!query) {
      return sites;
    }
    return sites.filter(
      (site) =>
        site.name.toLowerCase().includes(query) ||
        site.id.toLowerCase().includes(query),
    );
  }, [siteFilter, sites]);

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
  const canSearch =
    !running &&
    username.trim().length > 0 &&
    selectedSites.size > 0 &&
    (source !== "cache" || appInfo?.cacheReady === true) &&
    (source !== "local" || !discoverySitesSelected || allowDiscovery);

  function handleEvent(searchId: string, event: SearchEvent) {
    if (activeSearchRef.current !== searchId) {
      return;
    }

    if (event.event === "started") {
      setTotalSites(event.data.total);
    } else if (event.event === "result") {
      setResults((current) => [...current, event.data.result]);
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
            sync: "never",
            regionClass: "local",
            maximumAgeMs: 86_400_000,
          },
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

  const completed = results.length;
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
            {source === "local" ? "Local probe" : "Offline cache"}
          </span>
          <span className="status-pill status-pill--muted">
            <Icon name="shield" />
            Not synchronized
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

          <div className="selection-actions">
            <button
              disabled={running}
              onClick={() =>
                setSelectedSites(new Set(sites.map((site) => site.id)))
              }
              type="button"
            >
              Select all
            </button>
            <span />
            <button
              disabled={running}
              onClick={() => setSelectedSites(new Set())}
              type="button"
            >
              Clear
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
                  <small>
                    {site.enabled ? "Verified" : "Research rule"}
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
            <p className="eyebrow">Local username search</p>
            <h1>Trace an identity across the open web.</h1>
            <p className="search-hero__description">
              {source === "local"
                ? "Requests run from this device. Results remain local and are stored only in this installation's cache."
                : "Cache lookup is strictly offline. It never falls through to a network probe and only returns fresh, rule-matched observations."}
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
            </div>

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

            {source === "local" && discoverySitesSelected && (
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
                  {source === "local" ? "Local evidence" : "Cached evidence"}
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
