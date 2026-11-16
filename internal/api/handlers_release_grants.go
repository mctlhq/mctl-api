package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/releaseartifact"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Release grants, slice S1 (mctl-api#1022, mctlhq/mctl-gitops#2528).
//
//	POST /api/v1/release/grants  {"repository":"mctlhq/mctl-api","version":"4.163.0"}
//	GET  /api/v1/release/grants?repository=mctlhq/mctl-api&version=4.163.0
//
// POST opens the pending release.grant request for one release. The server
// reads the tag and the image itself (releaseartifact.Resolver) and binds the
// request to the tag commit and the image digest; it refuses a release whose
// image was not built from its tag. The request grants nothing: nothing in
// this slice can decide it. The decision belongs to a fresh, MFA-backed
// sign-in page (S2), so every request created now stays pending.
//
// GET lists the requests for one release with the artifact each one binds,
// for the release gate in mctlhq/mctl-gitops (S3) and for admins. A row whose
// columns do not reproduce its args digest is reported as an error, never
// skipped.
//
// Dark by default: the routes exist only when ReleaseGrants is configured
// (RELEASE_GRANTS_ENABLED=true in cmd/api).

const (
	releaseGrantsPath = "/api/v1/release/grants"

	codeReleaseGrantInvalid      = "release_grant_invalid_input"
	codeReleaseGrantForbidden    = "release_grant_forbidden"
	codeReleaseNotFound          = "release_artifact_not_found"
	codeReleaseMismatch          = "release_artifact_mismatch"
	codeReleaseUnavailable       = "release_artifact_unavailable"
	codeReleaseGrantStore        = "release_grant_store_unavailable"
	codeReleaseGrantInconsistent = "release_grant_record_inconsistent"

	releaseGrantMaxBody    = 4096
	defaultReleaseGrantTTL = 72 * time.Hour
)

// ReleaseArtifactResolver reads a release. *releaseartifact.Resolver
// implements it.
type ReleaseArtifactResolver interface {
	Resolve(ctx context.Context, repository, version string) (workitems.ReleaseArtifact, error)
}

// ReleaseGrantOptions configures the release grant routes.
type ReleaseGrantOptions struct {
	Resolver ReleaseArtifactResolver
	// Repositories are the lower-case owner/name repositories a release
	// grant may be requested for.
	Repositories []string
	// ReaderRepository is the repository whose GitHub Actions jobs on main
	// may read grants (the release gate), e.g. mctlhq/mctl-gitops. Empty
	// lets no CI principal read.
	ReaderRepository string
	// TTL is how long a request stays decidable; zero means 72 hours.
	TTL time.Duration
}

func (o *ReleaseGrantOptions) enabled() bool {
	return o != nil && o.Resolver != nil && len(o.Repositories) > 0
}

func (o *ReleaseGrantOptions) ttl() time.Duration {
	if o.TTL > 0 {
		return o.TTL
	}
	return defaultReleaseGrantTTL
}

// releaseGrantReader is a CI principal of the reader repository running a
// workflow from that repository's main branch.
func (o *ReleaseGrantOptions) releaseGrantReader(u *auth.User) bool {
	if o == nil || o.ReaderRepository == "" || !u.IsCI() || u.CIRepository() != o.ReaderRepository {
		return false
	}
	ref := u.CIJobWorkflowRef()
	return strings.HasPrefix(ref, o.ReaderRepository+"/.github/workflows/") && strings.HasSuffix(ref, "@refs/heads/main")
}

// ciReleaseGrantReadAllowed is the one release route a CI principal may
// reach; the handler decides whether this CI principal is the reader.
func ciReleaseGrantReadAllowed(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == releaseGrantsPath
}

type releaseGrantView struct {
	Approval *workitems.ActionApprovalRequest `json:"approval"`
	Artifact workitems.ReleaseArtifact        `json:"artifact"`
}

func (h *Handlers) releaseGrantAudit(r *http.Request, user *auth.User, op, status, msg string, params map[string]string) {
	h.logAudit(r, audit.Entry{
		UserID: user.ID, Operation: op, Parameters: params, Status: status,
		RiskLevel: string(operations.RiskHigh), Message: msg,
	})
}

// RequestReleaseGrant answers POST /api/v1/release/grants.
func (h *Handlers) RequestReleaseGrant(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	o := h.opts.ReleaseGrants
	params := map[string]string{}
	refuse := func(status int, code, msg string) {
		h.releaseGrantAudit(r, user, "release.grant.request", "denied", code+": "+msg, params)
		writeErrorCode(w, status, code, msg, nil)
	}
	// Requesting grants nothing, but only an admin may put a release in
	// front of the owner.
	if !user.IsAdmin() || user.IsCI() {
		refuse(http.StatusForbidden, codeReleaseGrantForbidden, "only an admin may request a release grant")
		return
	}
	var body struct {
		Repository string `json:"repository"`
		Version    string `json:"version"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, releaseGrantMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		refuse(http.StatusBadRequest, codeReleaseGrantInvalid, "the body must be {\"repository\": ..., \"version\": ...}")
		return
	}
	params["repository"], params["version"] = truncate256(body.Repository), truncate256(body.Version)
	if !slices.Contains(o.Repositories, body.Repository) {
		refuse(http.StatusForbidden, codeReleaseGrantForbidden, "release grants are not enabled for this repository")
		return
	}
	art, err := o.Resolver.Resolve(r.Context(), body.Repository, body.Version)
	switch {
	case err == nil:
	case errors.Is(err, workitems.ErrInvalid):
		refuse(http.StatusBadRequest, codeReleaseGrantInvalid, err.Error())
		return
	case errors.Is(err, releaseartifact.ErrNotFound):
		refuse(http.StatusNotFound, codeReleaseNotFound, err.Error())
		return
	case errors.Is(err, releaseartifact.ErrMismatch):
		refuse(http.StatusConflict, codeReleaseMismatch, err.Error())
		return
	default:
		slog.Warn("release grant: artifact unavailable", "repository", body.Repository, "version", body.Version, "error", err)
		refuse(http.StatusServiceUnavailable, codeReleaseUnavailable, "the release could not be read and checked right now")
		return
	}
	params["tag_commit"], params["image_digest"] = art.TagCommit, art.ImageDigest
	actor, subject := actorAndSubject(user)
	in := workitems.ActionApprovalInput{
		ActionIntent:           workitems.ReleaseIntent(art),
		RequestedBy:            principalOf(user),
		RequestedByPrincipalID: user.PrincipalID(),
		ViaPrincipalID:         user.ViaPrincipalID(),
		ActorKind:              actor.Kind,
		ActorName:              actor.Name,
		AgentRunID:             user.AgentRunID(),
		IdempotencyKey:         workitems.ReleaseIdempotencyKey(art),
		ExpiresAt:              h.deployPlanNow().Add(o.ttl()),
		RiskLevel:              string(operations.RiskHigh),
		IntentSource:           "release:" + workitems.ReleaseTarget(art.Repository, art.Version),
	}
	if subject != nil {
		in.SubjectPrincipalID, in.SubjectKind = subject.PrincipalID, subject.Kind
	}
	pol := h.approvalPolicies()[workitems.ReleaseGrantPolicyRuleID]
	in.SideEffect, in.PolicyDecision = pol.SideEffect, pol.Decision
	in.PolicyReasons = append([]string(nil), pol.Reasons...)
	approval, created, err := h.opts.WorkItems.CreateReleaseApproval(r.Context(), art, in)
	if err != nil {
		if code := actionApprovalRefusalCode(err); code != "" {
			h.releaseGrantAudit(r, user, "release.grant.request", "denied", code, params)
		} else {
			slog.Error("release grant: create", "repository", art.Repository, "version", art.Version, "error", err)
			h.releaseGrantAudit(r, user, "release.grant.request", "error", "create_failed", params)
		}
		writeActionApprovalError(w, err)
		return
	}
	params["approval_id"] = approval.ID
	if created {
		h.auditActionApproval(r, user, "action_approval.create", approval, operations.RiskHigh, nil)
		h.releaseGrantAudit(r, user, "release.grant.request", "succeeded", "succeeded", params)
	} else {
		h.releaseGrantAudit(r, user, "release.grant.request", "succeeded", "replayed", params)
	}
	writeJSON(w, createdStatus(created), map[string]any{
		"schema_version":     workitems.ActionApprovalSchemaVersion,
		"grant":              releaseGrantView{Approval: approval, Artifact: art},
		"decided_by":         "the owner, signed in fresh with a second factor on the release approval page; a bearer token cannot decide it",
		"decide_unavailable": "the release approval page does not exist yet (mctl-api#1022 S2), so this grant cannot be decided",
	})
}

// ListReleaseGrants answers GET /api/v1/release/grants.
func (h *Handlers) ListReleaseGrants(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	o := h.opts.ReleaseGrants
	q := r.URL.Query()
	repo, version := q.Get("repository"), q.Get("version")
	params := map[string]string{"repository": truncate256(repo), "version": truncate256(version)}
	reader := o.releaseGrantReader(user)
	if !reader && (!user.IsAdmin() || user.IsCI()) {
		h.releaseGrantAudit(r, user, "release.grant.list", "denied", "not a reader", params)
		writeErrorCode(w, http.StatusForbidden, codeReleaseGrantForbidden, "release grants are readable by admins and the release gate only", nil)
		return
	}
	if !slices.Contains(o.Repositories, repo) {
		h.releaseGrantAudit(r, user, "release.grant.list", "denied", codeReleaseGrantInvalid+": repository not enabled", params)
		writeErrorCode(w, http.StatusBadRequest, codeReleaseGrantInvalid, "release grants are not enabled for this repository", nil)
		return
	}
	rows, err := h.opts.WorkItems.ReleaseApprovals(r.Context(), repo, version, 0)
	switch {
	case errors.Is(err, workitems.ErrInvalid):
		h.releaseGrantAudit(r, user, "release.grant.list", "denied", codeReleaseGrantInvalid, params)
		writeErrorCode(w, http.StatusBadRequest, codeReleaseGrantInvalid, err.Error(), nil)
		return
	case err != nil:
		slog.Error("release grant: list", "repository", repo, "version", version, "error", err)
		h.releaseGrantAudit(r, user, "release.grant.list", "error", codeReleaseGrantStore, params)
		writeErrorCode(w, http.StatusServiceUnavailable, codeReleaseGrantStore, "release grants could not be read", nil)
		return
	}
	out := make([]releaseGrantView, 0, len(rows))
	for i := range rows {
		art, err := workitems.ReleaseArtifactOf(&rows[i])
		if err != nil {
			slog.Error("release grant: inconsistent record", "id", rows[i].ID, "error", err)
			params["approval_id"] = rows[i].ID
			h.releaseGrantAudit(r, user, "release.grant.list", "error", codeReleaseGrantInconsistent, params)
			writeErrorCode(w, http.StatusInternalServerError, codeReleaseGrantInconsistent,
				"a release grant record does not reproduce its digest", map[string]any{"approval_id": rows[i].ID})
			return
		}
		out = append(out, releaseGrantView{Approval: &rows[i], Artifact: art})
	}
	h.releaseGrantAudit(r, user, "release.grant.list", "succeeded", "succeeded", params)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": workitems.ActionApprovalSchemaVersion,
		"repository":     repo,
		"version":        version,
		"grants":         out,
	})
}
