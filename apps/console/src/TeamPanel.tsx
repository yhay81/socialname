import { useEffect, useMemo, useState } from "react";
import {
  ApiFailure,
  createOrganizationMember,
  loadOrganization,
  loadOrganizationAudit,
  loadOrganizationMembers,
  loadOrganizationRetention,
  loadTransitionReviews,
  updateOrganizationMember,
  updateOrganizationRetention,
  updateTransitionReview,
} from "./api";
import { readableToken } from "./model";
import {
  API_SCHEMA,
  type ApiKeyScope,
  type OrganizationAuditEventPage,
  type OrganizationMemberAction,
  type OrganizationMemberResource,
  type OrganizationResource,
  type OrganizationRetentionPolicyResource,
  type OrganizationRole,
  type TransitionReviewAction,
  type TransitionReviewResolution,
  type TransitionReviewResource,
} from "./types";

interface TeamPanelProps {
  scopes: ApiKeyScope[];
  token: string;
}

const resolutions: TransitionReviewResolution[] = [
  "action_taken",
  "no_action_required",
  "measurement_follow_up",
  "externally_escalated",
];

function shortId(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function formatTime(value: number): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function failureMessage(reason: unknown): string {
  if (reason instanceof ApiFailure) {
    if (reason.status === 403) {
      return "Your role or API-key scopes do not permit that team action.";
    }
    if (reason.status === 409) {
      return "Team state changed or a safety invariant blocked the action. Refresh and try again.";
    }
    return `Team API returned ${readableToken(reason.code)}.`;
  }
  if (reason instanceof Error && reason.message.includes("API v1")) {
    return reason.message;
  }
  return "Team data is temporarily unavailable.";
}

function roleOptions(actor: OrganizationRole): OrganizationRole[] {
  return actor === "owner"
    ? ["owner", "administrator", "member", "viewer"]
    : ["member", "viewer"];
}

export function TeamPanel({ scopes, token }: TeamPanelProps) {
  const [organization, setOrganization] = useState<OrganizationResource>();
  const [members, setMembers] = useState<OrganizationMemberResource[]>([]);
  const [reviews, setReviews] = useState<TransitionReviewResource[]>([]);
  const [retention, setRetention] =
    useState<OrganizationRetentionPolicyResource>();
  const [audit, setAudit] = useState<OrganizationAuditEventPage>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [showInvite, setShowInvite] = useState(false);
  const [subjectReference, setSubjectReference] = useState("");
  const [memberName, setMemberName] = useState("");
  const [memberRole, setMemberRole] = useState<OrganizationRole>("member");
  const [minimumRetention, setMinimumRetention] = useState("30");
  const [maximumRetention, setMaximumRetention] = useState("730");
  const [assignees, setAssignees] = useState<Record<string, string>>({});
  const [reviewResolutions, setReviewResolutions] = useState<
    Record<string, TransitionReviewResolution>
  >({});

  const current = organization?.authenticated_member;
  const canManage = current
    ? current.role === "owner" || current.role === "administrator"
    : false;
  const hasAuditScope = scopes.includes("operations:read");
  const canReadAudit = canManage && hasAuditScope;
  const canWriteReviews = scopes.includes("watch:write");
  const activeReviewers = useMemo(
    () =>
      members.filter(
        (member) => member.state === "active" && member.role !== "viewer",
      ),
    [members],
  );

  useEffect(() => {
    let currentRequest = true;
    async function load() {
      setLoading(true);
      setError(undefined);
      try {
        const [loadedOrganization, memberPage, reviewPage, loadedRetention] =
          await Promise.all([
            loadOrganization(token),
            loadOrganizationMembers(token),
            loadTransitionReviews(token),
            loadOrganizationRetention(token),
          ]);
        if (!currentRequest) {
          return;
        }
        setOrganization(loadedOrganization);
        setMembers(memberPage.members);
        setReviews(reviewPage.reviews);
        setRetention(loadedRetention);
        setMinimumRetention(
          String(loadedRetention.minimum_watch_retention_days),
        );
        setMaximumRetention(
          String(loadedRetention.maximum_watch_retention_days),
        );
        if (
          hasAuditScope &&
          (loadedOrganization.authenticated_member.role === "owner" ||
            loadedOrganization.authenticated_member.role === "administrator")
        ) {
          const loadedAudit = await loadOrganizationAudit(token);
          if (!currentRequest) {
            return;
          }
          setAudit(loadedAudit);
        } else {
          setAudit(undefined);
        }
      } catch (reason) {
        if (currentRequest) {
          setError(failureMessage(reason));
        }
      } finally {
        if (currentRequest) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      currentRequest = false;
    };
  }, [hasAuditScope, token]);

  async function refreshAudit() {
    if (!canReadAudit) {
      return;
    }
    try {
      setAudit(await loadOrganizationAudit(token));
    } catch {
      // A successful primary mutation is not relabelled by an audit refresh.
    }
  }

  async function createMember() {
    if (!canManage || !subjectReference.trim() || !memberName.trim()) {
      setError("Member name and private subject reference are required.");
      return;
    }
    setBusy("member-create");
    setError(undefined);
    try {
      const created = await createOrganizationMember(token, {
        schema: API_SCHEMA,
        subject_reference: subjectReference.trim(),
        display_name: memberName.trim(),
        role: memberRole,
      });
      setMembers((currentMembers) => {
        const withoutReplay = currentMembers.filter(
          (member) => member.membership_id !== created.membership_id,
        );
        return [...withoutReplay, created];
      });
      setSubjectReference("");
      setMemberName("");
      setMemberRole("member");
      setShowInvite(false);
      void refreshAudit();
    } catch (reason) {
      setError(failureMessage(reason));
    } finally {
      setBusy(undefined);
    }
  }

  function canManageMember(member: OrganizationMemberResource): boolean {
    if (!current || member.membership_id === current.membership_id) {
      return false;
    }
    return (
      current.role === "owner" ||
      (current.role === "administrator" &&
        (member.role === "member" || member.role === "viewer"))
    );
  }

  async function changeMember(
    member: OrganizationMemberResource,
    action: OrganizationMemberAction,
  ) {
    setBusy(`member-${member.membership_id}`);
    setError(undefined);
    try {
      const updated = await updateOrganizationMember(token, member, action);
      setMembers((currentMembers) =>
        currentMembers.map((candidate) =>
          candidate.membership_id === updated.membership_id
            ? updated
            : candidate,
        ),
      );
      void refreshAudit();
    } catch (reason) {
      setError(failureMessage(reason));
    } finally {
      setBusy(undefined);
    }
  }

  async function changeReview(
    review: TransitionReviewResource,
    action: TransitionReviewAction,
  ) {
    setBusy(`review-${review.review_id}`);
    setError(undefined);
    try {
      const updated = await updateTransitionReview(token, review, action);
      setReviews((currentReviews) =>
        currentReviews.map((candidate) =>
          candidate.review_id === updated.review_id ? updated : candidate,
        ),
      );
      void refreshAudit();
    } catch (reason) {
      setError(failureMessage(reason));
    } finally {
      setBusy(undefined);
    }
  }

  async function saveRetention() {
    if (!retention || !canManage) {
      return;
    }
    const minimum = Number(minimumRetention);
    const maximum = Number(maximumRetention);
    if (
      !Number.isSafeInteger(minimum) ||
      !Number.isSafeInteger(maximum) ||
      minimum < 30 ||
      maximum > 730 ||
      minimum > maximum
    ) {
      setError("Retention must be an ordered whole-day range within 30–730.");
      return;
    }
    setBusy("retention");
    setError(undefined);
    try {
      const updated = await updateOrganizationRetention(
        token,
        retention,
        minimum,
        maximum,
      );
      setRetention(updated);
      setMinimumRetention(String(updated.minimum_watch_retention_days));
      setMaximumRetention(String(updated.maximum_watch_retention_days));
      void refreshAudit();
    } catch (reason) {
      setError(failureMessage(reason));
    } finally {
      setBusy(undefined);
    }
  }

  if (loading) {
    return (
      <section className="team-console team-console--loading" aria-live="polite">
        Loading organization workflow…
      </section>
    );
  }

  if (!organization || !current || !retention) {
    return (
      <section className="team-console">
        <p className="team-error" role="alert">
          {error ?? "Organization workflow is unavailable."}
        </p>
      </section>
    );
  }

  const openReviews = reviews.filter((review) => review.state !== "resolved");

  return (
    <section className="team-console" aria-labelledby="team-title">
      <div className="team-heading">
        <div>
          <p className="eyebrow">Organization workflow</p>
          <h2 id="team-title">Review together. Keep every action attributable.</h2>
          <p>
            {organization.display_name} · signed in as {current.display_name} (
            {readableToken(current.role)})
          </p>
        </div>
        <div className="team-summary">
          <span>
            <strong>{members.filter((member) => member.state === "active").length}</strong>
            active members
          </span>
          <span>
            <strong>{openReviews.length}</strong>
            unresolved reviews
          </span>
          <span>
            <strong>
              {retention.minimum_watch_retention_days}–
              {retention.maximum_watch_retention_days}d
            </strong>
            watch retention
          </span>
        </div>
      </div>

      {error && (
        <p className="team-error" role="alert">
          {error}
          <button onClick={() => setError(undefined)} type="button">
            Dismiss
          </button>
        </p>
      )}

      <div className="team-grid">
        <article className="team-card team-members">
          <div className="team-card-heading">
            <div>
              <span>Directory</span>
              <h3>Members and roles</h3>
            </div>
            {canManage && (
              <button onClick={() => setShowInvite((shown) => !shown)} type="button">
                {showInvite ? "Close" : "Add member"}
              </button>
            )}
          </div>

          {showInvite && (
            <form
              className="team-member-form"
              onSubmit={(event) => {
                event.preventDefault();
                void createMember();
              }}
            >
              <label>
                Display name
                <input
                  maxLength={100}
                  onChange={(event) => setMemberName(event.target.value)}
                  value={memberName}
                />
              </label>
              <label>
                Private subject reference
                <input
                  autoComplete="off"
                  maxLength={200}
                  onChange={(event) => setSubjectReference(event.target.value)}
                  type="password"
                  value={subjectReference}
                />
              </label>
              <label>
                Role
                <select
                  onChange={(event) =>
                    setMemberRole(event.target.value as OrganizationRole)
                  }
                  value={memberRole}
                >
                  {roleOptions(current.role).map((role) => (
                    <option key={role} value={role}>
                      {readableToken(role)}
                    </option>
                  ))}
                </select>
              </label>
              <button disabled={busy === "member-create"} type="submit">
                {busy === "member-create" ? "Adding…" : "Add member"}
              </button>
              <small>
                The subject reference is write-only and is never returned or
                placed in audit output.
              </small>
            </form>
          )}

          <ul className="team-member-list">
            {members.map((member) => {
              const memberBusy = busy === `member-${member.membership_id}`;
              return (
                <li key={member.membership_id}>
                  <div>
                    <strong>{member.display_name}</strong>
                    <span>
                      {readableToken(member.role)} · {readableToken(member.state)}
                    </span>
                  </div>
                  {canManageMember(member) && member.state !== "removed" ? (
                    <div className="team-member-actions">
                      {member.state === "active" && (
                        <select
                          aria-label={`Role for ${member.display_name}`}
                          disabled={memberBusy}
                          onChange={(event) => {
                            const role = event.target.value as OrganizationRole;
                            if (role !== member.role) {
                              void changeMember(member, {
                                kind: "change_role",
                                role,
                              });
                            }
                          }}
                          value={member.role}
                        >
                          {roleOptions(current.role).map((role) => (
                            <option key={role} value={role}>
                              {readableToken(role)}
                            </option>
                          ))}
                        </select>
                      )}
                      <button
                        disabled={memberBusy}
                        onClick={() =>
                          void changeMember(member, {
                            kind:
                              member.state === "suspended"
                                ? "reactivate"
                                : "suspend",
                          })
                        }
                        type="button"
                      >
                        {member.state === "suspended" ? "Reactivate" : "Suspend"}
                      </button>
                      <button
                        className="team-danger"
                        disabled={memberBusy}
                        onClick={() =>
                          void changeMember(member, { kind: "remove" })
                        }
                        type="button"
                      >
                        Remove
                      </button>
                    </div>
                  ) : (
                    <code>{shortId(member.membership_id)}</code>
                  )}
                </li>
              );
            })}
          </ul>
        </article>

        <article className="team-card team-reviews">
          <div className="team-card-heading">
            <div>
              <span>Confirmed account changes</span>
              <h3>Review queue</h3>
            </div>
            <b>{openReviews.length} open</b>
          </div>
          <ol>
            {reviews.map((review) => {
              const assignedToCurrent =
                review.assigned_membership_id === current.membership_id;
              const reviewBusy = busy === `review-${review.review_id}`;
              const selectedAssignee =
                assignees[review.review_id] ??
                review.assigned_membership_id ??
                activeReviewers[0]?.membership_id ??
                "";
              const selectedResolution =
                reviewResolutions[review.review_id] ?? "no_action_required";
              return (
                <li key={review.review_id}>
                  <div className="review-title">
                    <div>
                      <strong>
                        @{review.transition.target.username} on{" "}
                        {review.transition.target.site_id}
                      </strong>
                      <span>
                        {readableToken(review.state)} · revision {review.revision}
                      </span>
                    </div>
                    <time>{formatTime(review.transition.detected_at_unix_ms)}</time>
                  </div>
                  <p>
                    {review.transition.change.class === "account_state"
                      ? `${readableToken(review.transition.change.from)} → ${readableToken(review.transition.change.to)}`
                      : "Measurement-only events never enter this queue."}
                  </p>
                  <div className="review-actions">
                    {canManage && canWriteReviews && review.state === "open" && (
                      <>
                        <select
                          aria-label="Review assignee"
                          disabled={reviewBusy || activeReviewers.length === 0}
                          onChange={(event) =>
                            setAssignees((currentAssignees) => ({
                              ...currentAssignees,
                              [review.review_id]: event.target.value,
                            }))
                          }
                          value={selectedAssignee}
                        >
                          {activeReviewers.map((member) => (
                            <option
                              key={member.membership_id}
                              value={member.membership_id}
                            >
                              {member.display_name}
                            </option>
                          ))}
                        </select>
                        <button
                          disabled={
                            !selectedAssignee ||
                            reviewBusy ||
                            selectedAssignee === review.assigned_membership_id
                          }
                          onClick={() =>
                            void changeReview(review, {
                              kind: "assign",
                              membership_id: selectedAssignee,
                            })
                          }
                          type="button"
                        >
                          {review.assigned_membership_id ? "Reassign" : "Assign"}
                        </button>
                      </>
                    )}
                    {canWriteReviews &&
                      assignedToCurrent &&
                      review.state === "open" && (
                      <button
                        disabled={reviewBusy}
                        onClick={() =>
                          void changeReview(review, { kind: "acknowledge" })
                        }
                        type="button"
                      >
                        Acknowledge responsibility
                      </button>
                    )}
                    {canWriteReviews &&
                      assignedToCurrent &&
                      review.state === "acknowledged" && (
                      <>
                        <select
                          aria-label="Review resolution"
                          disabled={reviewBusy}
                          onChange={(event) =>
                            setReviewResolutions((currentResolutions) => ({
                              ...currentResolutions,
                              [review.review_id]: event.target
                                .value as TransitionReviewResolution,
                            }))
                          }
                          value={selectedResolution}
                        >
                          {resolutions.map((resolution) => (
                            <option key={resolution} value={resolution}>
                              {readableToken(resolution)}
                            </option>
                          ))}
                        </select>
                        <button
                          disabled={reviewBusy}
                          onClick={() =>
                            void changeReview(review, {
                              kind: "resolve",
                              resolution: selectedResolution,
                            })
                          }
                          type="button"
                        >
                          Resolve review
                        </button>
                      </>
                    )}
                    {review.state === "resolved" && review.resolution && (
                      <span className="review-resolution">
                        {readableToken(review.resolution)}
                      </span>
                    )}
                  </div>
                </li>
              );
            })}
            {reviews.length === 0 && (
              <li className="team-empty">
                No confirmed account transition needs human review.
              </li>
            )}
          </ol>
        </article>
      </div>

      <div className="governance-grid">
        <article className="team-card retention-card">
          <div className="team-card-heading">
            <div>
              <span>Organization policy</span>
              <h3>Watch retention range</h3>
            </div>
            <b>rev {retention.revision}</b>
          </div>
          <div className="retention-fields">
            <label>
              Minimum days
              <input
                disabled={!canManage}
                max="730"
                min="30"
                onChange={(event) => setMinimumRetention(event.target.value)}
                type="number"
                value={minimumRetention}
              />
            </label>
            <span aria-hidden="true">→</span>
            <label>
              Maximum days
              <input
                disabled={!canManage}
                max="730"
                min="30"
                onChange={(event) => setMaximumRetention(event.target.value)}
                type="number"
                value={maximumRetention}
              />
            </label>
            {canManage && (
              <button
                disabled={
                  busy === "retention" ||
                  (Number(minimumRetention) ===
                    retention.minimum_watch_retention_days &&
                    Number(maximumRetention) ===
                      retention.maximum_watch_retention_days)
                }
                onClick={() => void saveRetention()}
                type="button"
              >
                {busy === "retention" ? "Saving…" : "Save range"}
              </button>
            )}
          </div>
          <p>
            Existing watches must be moved into the range first. The policy
            never silently rewrites retention.
          </p>
        </article>

        <article className="team-card audit-card">
          <div className="team-card-heading">
            <div>
              <span>Private actor trail</span>
              <h3>Recent audit events</h3>
            </div>
            <b>{audit?.events.length ?? 0}</b>
          </div>
          {audit ? (
            <ol>
              {audit.events.slice(0, 10).map((event) => (
                <li key={event.audit_event_id}>
                  <div>
                    <strong>{readableToken(event.action)}</strong>
                    <span>
                      {readableToken(event.resource_kind)} ·{" "}
                      {readableToken(event.actor.kind)}
                    </span>
                  </div>
                  <time>{formatTime(event.occurred_at_unix_ms)}</time>
                </li>
              ))}
            </ol>
          ) : (
            <p>
              Audit projection is restricted to owner and administrator roles.
            </p>
          )}
        </article>
      </div>
    </section>
  );
}
