package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/deployanalyze"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// SourceRepoBindingReader answers which services are built from a
// repository. It fails closed: an unreadable gitops checkout is an error,
// never an empty list.
type SourceRepoBindingReader interface {
	ServicesBySourceRepo(repo string) ([]gitops.SourceRepoBinding, error)
}

var (
	deployTenantRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`)
	deployRepoRe   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9._-]{1,100}$`)
	deployRevRe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	deployPathRe   = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)
)

func validDeployRepo(repo string) bool {
	if !deployRepoRe.MatchString(repo) {
		return false
	}
	_, name, _ := strings.Cut(repo, "/")
	return !isDotOnly(name)
}

func validDeployPath(p string) bool {
	if !deployPathRe.MatchString(p) || strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// singleParam returns the only value of key, or false when it is missing
// (unless optional) or repeated.
func singleParam(q url.Values, key string) (string, bool, bool) {
	vals, present := q[key]
	if !present {
		return "", false, true
	}
	if len(vals) != 1 {
		return "", true, false
	}
	return vals[0], true, true
}

func truncate256(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// deployAudit collects the one audit row a deploy read writes.
type deployAudit struct {
	h      *Handlers
	r      *http.Request
	user   *auth.User
	op     string
	params map[string]string
	status string
	msg    string
	// skip drops the row: the request was refused by a helper that already
	// wrote its own audit entry.
	skip bool
}

func (a *deployAudit) set(status, msg string) {
	a.status, a.msg = status, msg
	a.params["outcome"] = msg
}

func (a *deployAudit) write() {
	if a.skip {
		return
	}
	a.h.logAudit(a.r, audit.Entry{
		UserID: a.user.ID, Operation: a.op, Parameters: a.params,
		Status: a.status, RiskLevel: string(operations.RiskLow), Message: a.msg,
	})
}

func (h *Handlers) newDeployAudit(r *http.Request, user *auth.User, op string) *deployAudit {
	q := r.URL.Query()
	params := map[string]string{}
	for _, k := range []string{"tenant", "repository", "revision", "dockerfile", "context"} {
		if v := q.Get(k); v != "" {
			params[k] = truncate256(v)
		}
	}
	return &deployAudit{h: h, r: r, user: user, op: op, params: params, status: "error", msg: "error:unknown"}
}

// refuse answers with a coded error and records it.
func (a *deployAudit) refuse(w http.ResponseWriter, httpStatus int, code, message string) {
	kind := "error"
	if httpStatus == http.StatusForbidden || httpStatus == http.StatusBadRequest {
		kind = "denied"
	}
	a.set(kind, kind+":"+code)
	writeErrorCode(w, httpStatus, code, message, nil)
}

// deployRefusal is a coded refusal a deploy helper hands back to its handler.
type deployRefusal struct {
	status  int
	code    string
	message string
}

// deployRepoBound checks that repo is bound to tenant: by the gitops
// github.com/source-repo annotation of one of the tenant's services, else by
// the portal binding. It returns the tenant's services built from repo. An
// unreadable binding is 503 deploy_binding_unavailable and an unbound
// repository 403 deploy_repository_not_bound.
func (h *Handlers) deployRepoBound(ctx context.Context, tenant, repo string) ([]string, *deployRefusal) {
	unavailable := &deployRefusal{http.StatusServiceUnavailable, "deploy_binding_unavailable", "the repository binding cannot be read right now"}
	if h.opts.SourceRepoBindings == nil {
		return nil, unavailable
	}
	all, err := h.opts.SourceRepoBindings.ServicesBySourceRepo(repo)
	if err != nil {
		slog.Error("deploy: reading repository bindings", "error", err)
		return nil, unavailable
	}
	services := []string{}
	for _, b := range all {
		if b.Tenant == tenant {
			services = append(services, b.Service)
		}
	}
	if len(services) == 0 {
		bound, err := h.repoBoundToTeam(ctx, tenant, repo)
		if err != nil {
			slog.Error("deploy: portal binding check", "error", err)
			return nil, unavailable
		}
		if !bound {
			return nil, &deployRefusal{http.StatusForbidden, "deploy_repository_not_bound", "the repository is not bound to this tenant"}
		}
	}
	return services, nil
}

// DeployAnalyze answers GET /api/v1/deploy/analyze: a static, read-only
// Tier 0 analysis of a repository at a pinned commit.
func (h *Handlers) DeployAnalyze(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployAudit(r, user, "deploy.analyze")
	defer a.write()

	q := r.URL.Query()
	tenant, _, okT := singleParam(q, "tenant")
	repo, _, okR := singleParam(q, "repository")
	rev, _, okV := singleParam(q, "revision")
	dockerfile, hasD, okD := singleParam(q, "dockerfile")
	buildCtx, hasC, okC := singleParam(q, "context")
	if !hasD {
		dockerfile = "Dockerfile"
	}
	if !hasC {
		buildCtx = "."
	}
	if !okT || !okR || !okV || !okD || !okC ||
		!deployTenantRe.MatchString(tenant) || !validDeployRepo(repo) || !deployRevRe.MatchString(rev) ||
		!validDeployPath(dockerfile) || !validDeployPath(buildCtx) {
		a.refuse(w, http.StatusBadRequest, "deploy_analyze_invalid_input",
			"tenant, repository (owner/name), revision (40-hex commit SHA) are required; dockerfile and context must be relative repository paths")
		return
	}

	if !user.HasTenantAccess(tenant) {
		a.refuse(w, http.StatusForbidden, "deploy_tenant_access_denied", "you are not a member of this tenant")
		return
	}

	services, refusal := h.deployRepoBound(r.Context(), tenant, repo)
	if refusal != nil {
		a.refuse(w, refusal.status, refusal.code, refusal.message)
		return
	}

	if h.opts.DeployContentReader == nil {
		a.refuse(w, http.StatusBadGateway, "deploy_github_unavailable", "the repository cannot be read right now")
		return
	}
	res, err := deployanalyze.Analyze(r.Context(), h.opts.DeployContentReader, deployanalyze.Request{
		Tenant: tenant, Repository: repo, Revision: rev, Dockerfile: dockerfile, Context: buildCtx, BoundServices: services,
	})
	switch {
	case errors.Is(err, deployanalyze.ErrRevisionUnreadable):
		a.refuse(w, http.StatusUnprocessableEntity, "deploy_revision_unreadable", "the revision cannot be read from the repository")
		return
	case errors.Is(err, deployanalyze.ErrGitHubMalformed):
		slog.Error("deploy analyze: malformed github answer", "error", err)
		a.refuse(w, http.StatusBadGateway, "deploy_github_malformed", "GitHub returned an unusable answer")
		return
	case errors.Is(err, deployanalyze.ErrGitHubUnavailable):
		slog.Error("deploy analyze: github unavailable", "error", err)
		a.refuse(w, http.StatusBadGateway, "deploy_github_unavailable", "the repository cannot be read right now")
		return
	case errors.Is(err, deployanalyze.ErrDraftInvalid):
		slog.Error("deploy analyze: invalid draft", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_draft_invalid", "the draft intent failed validation")
		return
	case err != nil:
		slog.Error("deploy analyze", "error", err)
		a.refuse(w, http.StatusInternalServerError, "deploy_analyze_failed", "the analysis failed")
		return
	}
	if res.Supported {
		a.set("succeeded", "succeeded")
	} else {
		a.set("succeeded", "unsupported:"+string(res.Reason))
	}
	writeJSON(w, http.StatusOK, res)
}

// DeployBindings answers GET /api/v1/deploy/bindings: the services built
// from a repository, limited to tenants the caller can see.
func (h *Handlers) DeployBindings(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	a := h.newDeployAudit(r, user, "deploy.bindings")
	defer a.write()

	repo, _, ok := singleParam(r.URL.Query(), "repository")
	if !ok || !validDeployRepo(repo) {
		a.refuse(w, http.StatusBadRequest, "deploy_analyze_invalid_input", "repository (owner/name) is required")
		return
	}
	if h.opts.SourceRepoBindings == nil {
		a.refuse(w, http.StatusServiceUnavailable, "deploy_binding_unavailable", "the repository binding cannot be read right now")
		return
	}
	all, err := h.opts.SourceRepoBindings.ServicesBySourceRepo(repo)
	if err != nil {
		slog.Error("deploy bindings: reading repository bindings", "error", err)
		a.refuse(w, http.StatusServiceUnavailable, "deploy_binding_unavailable", "the repository binding cannot be read right now")
		return
	}
	items := []gitops.SourceRepoBinding{}
	for _, b := range all {
		if user.IsAdmin() || user.HasTenantAccess(b.Tenant) {
			items = append(items, b)
		}
	}
	a.set("succeeded", "succeeded")
	writeJSON(w, http.StatusOK, map[string]any{"repository": repo, "items": items, "count": len(items)})
}
