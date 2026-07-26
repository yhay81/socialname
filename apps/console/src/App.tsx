import { useMemo, useRef, useState } from "react";
import {
  ApiFailure,
  createWatch,
  loadTransitions,
  loadWatches,
  loadWorkspace,
  setWatchState,
} from "./api";
import {
  deliveryLabel,
  readableToken,
  summarizeTimeline,
} from "./model";
import {
  API_SCHEMA,
  type WatchCreateRequest,
  type WatchResource,
  type WatchTransitionEntry,
  type WorkspaceResource,
} from "./types";

interface CreateFields {
  username: string;
  siteId: string;
  region: string;
  consentId: string;
  endpointId: string;
  intervalHours: string;
}

const emptyCreateFields: CreateFields = {
  username: "",
  siteId: "github",
  region: "jp",
  consentId: "",
  endpointId: "",
  intervalHours: "1",
};

function formatTime(value: number | null): string {
  if (value === null) {
    return "Not scheduled";
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function shortId(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function App() {
  const tokenRef = useRef("");
  const timelineRequestRef = useRef(0);
  const [tokenInput, setTokenInput] = useState("");
  const [workspace, setWorkspace] = useState<WorkspaceResource>();
  const [watches, setWatches] = useState<WatchResource[]>([]);
  const [watchCursor, setWatchCursor] = useState<string | null>(null);
  const [selectedWatchId, setSelectedWatchId] = useState<string>();
  const [timeline, setTimeline] = useState<WatchTransitionEntry[]>([]);
  const [timelineCursor, setTimelineCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [timelineBusy, setTimelineBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [showCreate, setShowCreate] = useState(false);
  const [createFields, setCreateFields] =
    useState<CreateFields>(emptyCreateFields);

  const selectedWatch = watches.find(
    (watch) => watch.watch_id === selectedWatchId,
  );
  const totals = useMemo(() => summarizeTimeline(timeline), [timeline]);
  const watchCounts = useMemo(
    () => ({
      active: watches.filter((watch) => watch.state === "active").length,
      paused: watches.filter((watch) => watch.state === "paused").length,
      deleting: watches.filter((watch) => watch.state === "deleting").length,
    }),
    [watches],
  );

  function describeFailure(reason: unknown): string {
    if (reason instanceof ApiFailure) {
      const suffix = reason.requestId
        ? ` Request ${shortId(reason.requestId)}.`
        : "";
      if (reason.status === 401) {
        return `The API key was not accepted.${suffix}`;
      }
      if (reason.status === 403) {
        return `This key does not grant the required workspace and watch scopes.${suffix}`;
      }
      if (reason.status === 409) {
        return `The watch changed before this action completed. Refresh and try again.${suffix}`;
      }
      return `The API returned ${readableToken(reason.code)}.${suffix}`;
    }
    if (reason instanceof Error && reason.message.includes("API v1")) {
      return reason.message;
    }
    return "The monitoring service is unavailable.";
  }

  async function selectWatch(watchId: string, token = tokenRef.current) {
    const request = ++timelineRequestRef.current;
    setSelectedWatchId(watchId);
    setTimeline([]);
    setTimelineCursor(null);
    setTimelineBusy(true);
    setError(undefined);
    try {
      const page = await loadTransitions(token, watchId);
      if (request !== timelineRequestRef.current) {
        return;
      }
      setTimeline(page.entries);
      setTimelineCursor(page.next_cursor);
    } catch (reason: unknown) {
      if (request !== timelineRequestRef.current) {
        return;
      }
      setTimeline([]);
      setTimelineCursor(null);
      setError(describeFailure(reason));
    } finally {
      if (request === timelineRequestRef.current) {
        setTimelineBusy(false);
      }
    }
  }

  async function connect() {
    const candidate = tokenInput.trim();
    if (!candidate || busy) {
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const [loadedWorkspace, watchPage] = await Promise.all([
        loadWorkspace(candidate),
        loadWatches(candidate),
      ]);
      tokenRef.current = candidate;
      setTokenInput("");
      setWorkspace(loadedWorkspace);
      setWatches(watchPage.watches);
      setWatchCursor(watchPage.next_cursor);
      const first = watchPage.watches[0];
      if (first) {
        await selectWatch(first.watch_id, candidate);
      } else {
        setSelectedWatchId(undefined);
        setTimeline([]);
      }
    } catch (reason: unknown) {
      tokenRef.current = "";
      setWorkspace(undefined);
      setError(describeFailure(reason));
    } finally {
      setBusy(false);
    }
  }

  function disconnect() {
    timelineRequestRef.current += 1;
    tokenRef.current = "";
    setTokenInput("");
    setWorkspace(undefined);
    setWatches([]);
    setWatchCursor(null);
    setSelectedWatchId(undefined);
    setTimeline([]);
    setTimelineCursor(null);
    setError(undefined);
    setShowCreate(false);
  }

  async function loadMoreWatches() {
    if (!watchCursor || busy) {
      return;
    }
    setBusy(true);
    try {
      const page = await loadWatches(tokenRef.current, watchCursor);
      setWatches((current) => [...current, ...page.watches]);
      setWatchCursor(page.next_cursor);
    } catch (reason: unknown) {
      setError(describeFailure(reason));
    } finally {
      setBusy(false);
    }
  }

  async function loadMoreTimeline() {
    if (!selectedWatchId || !timelineCursor || timelineBusy) {
      return;
    }
    const request = timelineRequestRef.current;
    setTimelineBusy(true);
    try {
      const page = await loadTransitions(
        tokenRef.current,
        selectedWatchId,
        timelineCursor,
      );
      if (request !== timelineRequestRef.current) {
        return;
      }
      setTimeline((current) => [...current, ...page.entries]);
      setTimelineCursor(page.next_cursor);
    } catch (reason: unknown) {
      if (request === timelineRequestRef.current) {
        setError(describeFailure(reason));
      }
    } finally {
      if (request === timelineRequestRef.current) {
        setTimelineBusy(false);
      }
    }
  }

  async function toggleWatchState() {
    if (!selectedWatch || selectedWatch.state === "deleting" || busy) {
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const updated = await setWatchState(
        tokenRef.current,
        selectedWatch,
        selectedWatch.state === "active" ? "paused" : "active",
      );
      setWatches((current) =>
        current.map((watch) =>
          watch.watch_id === updated.watch_id ? updated : watch,
        ),
      );
    } catch (reason: unknown) {
      setError(describeFailure(reason));
    } finally {
      setBusy(false);
    }
  }

  async function submitWatch() {
    const intervalHours = Number(createFields.intervalHours);
    if (
      busy ||
      !createFields.username.trim() ||
      !createFields.siteId.trim() ||
      !createFields.region.trim() ||
      !createFields.consentId.trim() ||
      !createFields.endpointId.trim() ||
      !Number.isFinite(intervalHours) ||
      intervalHours < 1
    ) {
      setError("Complete every watch field with an interval of at least one hour.");
      return;
    }
    const payload: WatchCreateRequest = {
      schema: API_SCHEMA,
      targets: {
        usernames: [createFields.username.trim()],
        site_ids: [createFields.siteId.trim()],
      },
      region_classes: [createFields.region.trim()],
      maximum_age_ms: 3_600_000,
      schedule: {
        interval_seconds: Math.round(intervalHours * 3_600),
        jitter_percent: 10,
      },
      probe_budget: {
        maximum_probes_per_run: 1,
        maximum_bytes_per_run: 1_048_576,
      },
      notification_endpoint_ids: [createFields.endpointId.trim()],
      private_history_consent_grant_id: createFields.consentId.trim(),
      retention_days: 30,
    };
    setBusy(true);
    setError(undefined);
    try {
      const created = await createWatch(tokenRef.current, payload);
      setWatches((current) => [created, ...current]);
      setCreateFields(emptyCreateFields);
      setShowCreate(false);
      await selectWatch(created.watch_id);
    } catch (reason: unknown) {
      setError(describeFailure(reason));
    } finally {
      setBusy(false);
    }
  }

  if (!workspace) {
    return (
      <main className="connection-shell">
        <section className="connection-panel" aria-labelledby="connect-title">
          <div className="brand-lockup">
            <span className="brand-signal" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
            <span>SocialName</span>
          </div>
          <p className="eyebrow">Monitoring console</p>
          <h1 id="connect-title">See what changed—and why it matters.</h1>
          <p className="connection-copy">
            Connect an issued API key to review watches, evidence-backed
            transitions, and delivery health. The key stays in this page only
            and disappears on reload.
          </p>
          <form
            className="connection-form"
            onSubmit={(event) => {
              event.preventDefault();
              void connect();
            }}
          >
            <label>
              <span>Scoped API key</span>
              <input
                autoCapitalize="none"
                autoComplete="off"
                autoCorrect="off"
                disabled={busy}
                onChange={(event) => setTokenInput(event.target.value)}
                placeholder="snk_…"
                spellCheck={false}
                type="password"
                value={tokenInput}
              />
            </label>
            <button disabled={busy || !tokenInput.trim()} type="submit">
              {busy ? "Connecting…" : "Open monitoring"}
              <span aria-hidden="true">↗</span>
            </button>
          </form>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="trust-note">
            <span aria-hidden="true">◆</span>
            <p>
              <strong>API boundary intact.</strong>
              No direct database access, browser persistence, analytics, or
              cross-origin requests.
            </p>
          </div>
        </section>
        <aside className="connection-visual" aria-label="Monitoring model">
          <p>Trustworthy coverage</p>
          <div className="coverage-orbit">
            <span className="orbit orbit--one" />
            <span className="orbit orbit--two" />
            <span className="orbit orbit--three" />
            <div>
              <strong>Observe</strong>
              <small>Confirm</small>
              <b>Deliver</b>
            </div>
          </div>
          <ol>
            <li>
              <span>01</span> Evidence stays time- and vantage-specific
            </li>
            <li>
              <span>02</span> Measurement failure stays separate
            </li>
            <li>
              <span>03</span> Every delivery keeps its lineage
            </li>
          </ol>
        </aside>
      </main>
    );
  }

  return (
    <div className="console-shell">
      <header className="console-header">
        <div className="brand-lockup brand-lockup--compact">
          <span className="brand-signal" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span>SocialName</span>
          <em>Monitor</em>
        </div>
        <div className="workspace-identity">
          <span>
            <i />
            API connected
          </span>
          <strong>{workspace.display_name}</strong>
          <small>{workspace.slug}</small>
        </div>
        <button className="text-button" onClick={disconnect} type="button">
          Disconnect
        </button>
      </header>

      <main className="console-main">
        <section className="overview">
          <div className="overview-copy">
            <p className="eyebrow">Trustworthy coverage</p>
            <h1>Monitoring, without the false certainty.</h1>
            <p>
              Account changes, measurement degradation, and delivery outcomes
              remain separate—and traceable to their evidence.
            </p>
          </div>
          <div className="metric-grid">
            <article>
              <span>Loaded active watches</span>
              <strong>{watchCounts.active}</strong>
              <small>
                {watchCounts.paused} paused · {watchCounts.deleting} deleting
                {" "}in loaded pages
              </small>
            </article>
            <article>
              <span>Loaded account changes</span>
              <strong>{totals.accountChanges}</strong>
              <small>{totals.measurementChanges} measurement events</small>
            </article>
            <article>
              <span>Loaded deliveries</span>
              <strong>{totals.delivered}</strong>
              <small>{totals.retrying} queued or retrying</small>
            </article>
            <article className={totals.failed > 0 ? "metric--alert" : ""}>
              <span>Loaded dead letters</span>
              <strong>{totals.failed}</strong>
              <small>
                {totals.failed > 0 ? "Needs operator review" : "No failed delivery"}
              </small>
            </article>
          </div>
        </section>

        {error && (
          <div className="alert-banner" role="alert">
            <span aria-hidden="true">!</span>
            <p>{error}</p>
            <button
              aria-label="Dismiss message"
              onClick={() => setError(undefined)}
              type="button"
            >
              ×
            </button>
          </div>
        )}

        <section className="monitoring-grid">
          <aside className="watch-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Coverage set</p>
                <h2>Watches</h2>
              </div>
              <button
                aria-label={showCreate ? "Close create watch form" : "Create watch"}
                className="round-button"
                onClick={() => setShowCreate((current) => !current)}
                type="button"
              >
                {showCreate ? "×" : "+"}
              </button>
            </div>

            {showCreate && (
              <form
                autoComplete="off"
                className="create-watch"
                onSubmit={(event) => {
                  event.preventDefault();
                  void submitWatch();
                }}
              >
                <div>
                  <label>
                    Username
                    <input
                      maxLength={256}
                      onChange={(event) =>
                        setCreateFields((current) => ({
                          ...current,
                          username: event.target.value,
                        }))
                      }
                      placeholder="alice"
                      value={createFields.username}
                    />
                  </label>
                  <label>
                    Site ID
                    <input
                      maxLength={64}
                      onChange={(event) =>
                        setCreateFields((current) => ({
                          ...current,
                          siteId: event.target.value,
                        }))
                      }
                      value={createFields.siteId}
                    />
                  </label>
                </div>
                <div>
                  <label>
                    Region
                    <input
                      maxLength={64}
                      onChange={(event) =>
                        setCreateFields((current) => ({
                          ...current,
                          region: event.target.value,
                        }))
                      }
                      value={createFields.region}
                    />
                  </label>
                  <label>
                    Interval hours
                    <input
                      max="744"
                      min="1"
                      onChange={(event) =>
                        setCreateFields((current) => ({
                          ...current,
                          intervalHours: event.target.value,
                        }))
                      }
                      type="number"
                      value={createFields.intervalHours}
                    />
                  </label>
                </div>
                <label>
                  Private-history consent grant ID
                  <input
                    maxLength={128}
                    onChange={(event) =>
                      setCreateFields((current) => ({
                        ...current,
                        consentId: event.target.value,
                      }))
                    }
                    placeholder="Provisioned opaque ID"
                    value={createFields.consentId}
                  />
                </label>
                <label>
                  Verified notification endpoint ID
                  <input
                    maxLength={128}
                    onChange={(event) =>
                      setCreateFields((current) => ({
                        ...current,
                        endpointId: event.target.value,
                      }))
                    }
                    placeholder="Provisioned opaque ID"
                    value={createFields.endpointId}
                  />
                </label>
                <button disabled={busy} type="submit">
                  {busy ? "Creating…" : "Create watch"}
                </button>
                <p>
                  Uses a 1 MiB run budget, 10% jitter, one target, and 30-day
                  retention. Endpoint and consent must already be active.
                </p>
              </form>
            )}

            <ul className="watch-list">
              {watches.map((watch) => {
                const target = watch.configuration.targets.usernames[0];
                const site = watch.configuration.targets.site_ids[0];
                const selected = watch.watch_id === selectedWatchId;
                return (
                  <li key={watch.watch_id}>
                    <button
                      aria-current={selected ? "true" : undefined}
                      className="watch-card"
                      onClick={() => void selectWatch(watch.watch_id)}
                      type="button"
                    >
                      <span
                        className={`watch-state watch-state--${watch.state}`}
                      >
                        {watch.state}
                      </span>
                      <strong>@{target ?? "bounded target"}</strong>
                      <small>
                        {site ?? "site"} ·{" "}
                        {watch.configuration.region_classes.join(", ")}
                      </small>
                      <span className="watch-next">
                        {watch.state === "active" ? "Next" : "Updated"}{" "}
                        {formatTime(
                          watch.next_run_at_unix_ms ?? watch.updated_at_unix_ms,
                        )}
                      </span>
                    </button>
                  </li>
                );
              })}
              {watches.length === 0 && (
                <li className="panel-empty">
                  <strong>No watches yet</strong>
                  <p>Create one with an active consent grant and endpoint.</p>
                </li>
              )}
            </ul>
            {watchCursor && (
              <button
                className="load-button"
                disabled={busy}
                onClick={() => void loadMoreWatches()}
                type="button"
              >
                Load more watches
              </button>
            )}
          </aside>

          <section className="timeline-panel">
            <div className="section-heading timeline-heading">
              <div>
                <p className="eyebrow">Evidence-backed history</p>
                <h2>
                  {selectedWatch
                    ? `@${selectedWatch.configuration.targets.usernames[0] ?? "target"}`
                    : "Select a watch"}
                </h2>
                {selectedWatch && (
                  <p>
                    {selectedWatch.configuration.targets.site_ids.join(", ")} ·
                    revision {selectedWatch.revision}
                  </p>
                )}
              </div>
              {selectedWatch && selectedWatch.state !== "deleting" && (
                <button
                  className="state-button"
                  disabled={busy}
                  onClick={() => void toggleWatchState()}
                  type="button"
                >
                  {selectedWatch.state === "active" ? "Pause watch" : "Resume watch"}
                </button>
              )}
            </div>

            {timelineBusy && timeline.length === 0 ? (
              <div className="timeline-loading" aria-live="polite">
                <span />
                <span />
                <span />
                Loading transition history…
              </div>
            ) : timeline.length === 0 ? (
              <div className="timeline-empty">
                <span aria-hidden="true">◎</span>
                <h3>No meaningful transition yet</h3>
                <p>
                  The first trustworthy assertion establishes a baseline. A
                  later confirmed change will appear here with its delivery.
                </p>
              </div>
            ) : (
              <ol className="timeline">
                {timeline.map((entry) => {
                  const change = entry.transition.change;
                  const confirmation = entry.transition.confirmation;
                  return (
                    <li
                      className={`timeline-item timeline-item--${change.class}`}
                      key={entry.transition.transition_id}
                    >
                      <span className="timeline-marker" aria-hidden="true">
                        {change.class === "account_state" ? "A" : "M"}
                      </span>
                      <article>
                        <div className="timeline-meta">
                          <span>
                            {change.class === "account_state"
                              ? "Account state"
                              : "Measurement health"}
                          </span>
                          <time dateTime={new Date(entry.transition.detected_at_unix_ms).toISOString()}>
                            {formatTime(entry.transition.detected_at_unix_ms)}
                          </time>
                        </div>
                        <h3>
                          <span>{readableToken(change.from)}</span>
                          <b aria-hidden="true">→</b>
                          <strong>{readableToken(change.to)}</strong>
                        </h3>
                        <p className="timeline-target">
                          @{entry.transition.target.username} on{" "}
                          {entry.transition.target.site_id}
                          {change.class === "measurement_health" &&
                            ` · ${change.region_class}`}
                        </p>
                        <div className="confirmation-row">
                          <span
                            className={`confirmation confirmation--${confirmation.status}`}
                          >
                            {confirmation.status}
                          </span>
                          <small>
                            {readableToken(
                              "basis" in confirmation
                                ? confirmation.basis
                                : confirmation.reason,
                            )}
                          </small>
                          <small>
                            {entry.transition.supporting_observation_ids.length}{" "}
                            supporting observation
                            {entry.transition.supporting_observation_ids.length ===
                            1
                              ? ""
                              : "s"}
                          </small>
                        </div>
                        <div className="delivery-list">
                          {entry.deliveries.map((delivery) => (
                            <div
                              className={`delivery delivery--${delivery.state}`}
                              key={delivery.delivery_id}
                            >
                              <span aria-hidden="true">
                                {delivery.state === "delivered"
                                  ? "✓"
                                  : delivery.state === "permanently_failed"
                                    ? "!"
                                    : "↻"}
                              </span>
                              <div>
                                <strong>{deliveryLabel(delivery.state)}</strong>
                                <small>
                                  {delivery.channel} · attempt{" "}
                                  {delivery.attempt_count}
                                  {delivery.last_error_code
                                    ? ` · ${readableToken(delivery.last_error_code)}`
                                    : ""}
                                </small>
                              </div>
                              <code title={delivery.delivery_id}>
                                {shortId(delivery.delivery_id)}
                              </code>
                            </div>
                          ))}
                          {entry.deliveries.length === 0 && (
                            <p className="no-delivery">
                              No delivery was created for this transition.
                            </p>
                          )}
                        </div>
                      </article>
                    </li>
                  );
                })}
              </ol>
            )}
            {timelineCursor && (
              <button
                className="load-button load-button--timeline"
                disabled={timelineBusy}
                onClick={() => void loadMoreTimeline()}
                type="button"
              >
                {timelineBusy ? "Loading…" : "Load older transitions"}
              </button>
            )}
          </section>
        </section>
      </main>
      <footer>
        <span>Observation ≠ timeless truth</span>
        <span>Account ownership is never inferred</span>
        <span>API v1 · no-store</span>
      </footer>
    </div>
  );
}

export default App;
