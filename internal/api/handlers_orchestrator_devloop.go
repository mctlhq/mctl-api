// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The orchestrator DevLoop principal (mctl-api#963, auth.OrchestratorDevLoopUserID)
// reaches three routes: it starts a DevLoop on the Temporal path, reads one
// back, and asks who it is. Everything else answers 403 before a handler
// runs, each refusal with a code a client can branch on and an audit row.
const (
	orchestratorDevLoopStartRoute = "/api/v1/agents/dev-loop/start"
	// orchestratorDevLoopReposEnv lists the repositories, as "mctlhq/<repo>"
	// and comma-separated, the orchestrator may start or read a DevLoop for.
	// Unset or empty refuses every repository. Matching is exact and
	// case-sensitive: the workflow id keeps the issue URL's case, so a
	// case-folded match would let MCTL-API and mctl-api start two loops for
	// one issue.
	orchestratorDevLoopReposEnv = "MCTL_ORCHESTRATOR_DEVLOOP_REPOS"

	codeOrchestratorRouteNotAllowed   = "orchestrator_devloop_route_not_allowed"
	codeOrchestratorApproveForbidden  = "orchestrator_devloop_approve_forbidden"
	codeOrchestratorTemporalRequired  = "orchestrator_devloop_temporal_required"
	codeOrchestratorRepoNotAllowed    = "orchestrator_devloop_repo_not_allowed"
	codeOrchestratorInvalidRequest    = "orchestrator_devloop_invalid_request"
	orchestratorDevLoopAuditOperation = "orchestrator-devloop.request"
)

var (
	// orchestratorDevLoopReadRe is a dev-loop read; the repository segment is
	// checked against the allow-list separately. A workflow id cannot be
	// split back into repo and issue unambiguously (a repo name may hold
	// "-<digits>"), so the read is admitted by prefix per allowed repo.
	orchestratorDevLoopReadRe     = regexp.MustCompile(`^/api/v1/agents/dev-loop/(dev-loop-mctlhq-[A-Za-z0-9_.-]+-[0-9]+)$`)
	orchestratorDevLoopApproveRe  = regexp.MustCompile(`^/api/v1/agents/dev-loop/[^/]+/approve$`)
	orchestratorArgoInvestigateRe = regexp.MustCompile(`^/api/v1/operations/mctl-agents-investigate(/|$)`)
)

// orchestratorDevLoopRepos is the configured allow-list, exactly as written.
func orchestratorDevLoopRepos() map[string]bool {
	repos := map[string]bool{}
	for _, r := range strings.Split(os.Getenv(orchestratorDevLoopReposEnv), ",") {
		if r = strings.TrimSpace(r); strings.HasPrefix(r, "mctlhq/") && len(r) > len("mctlhq/") {
			repos[r] = true
		}
	}
	return repos
}

// orchestratorDevLoopRepoAllowed reports whether repo (the bare name under
// mctlhq) is on the allow-list.
func orchestratorDevLoopRepoAllowed(repo string) bool {
	return repo != "" && orchestratorDevLoopRepos()["mctlhq/"+repo]
}

// orchestratorDevLoopWorkflowAllowed reports whether a dev-loop workflow id
// belongs to an allowed repository: dev-loop-mctlhq-<repo>-<issue>.
func orchestratorDevLoopWorkflowAllowed(workflowID string) bool {
	for r := range orchestratorDevLoopRepos() {
		prefix := "dev-loop-mctlhq-" + strings.TrimPrefix(r, "mctlhq/") + "-"
		if rest, ok := strings.CutPrefix(workflowID, prefix); ok && rest != "" && strings.Trim(rest, "0123456789") == "" {
			return true
		}
	}
	return false
}

// orchestratorDevLoopRefusal is the code for a request the gate refuses, or
// "" for one it admits. The issue_url of a start is judged by the handler,
// which has decoded it.
func orchestratorDevLoopRefusal(r *http.Request) string {
	if r.URL.RawPath != "" {
		// chi routes on RawPath: an encoded path is never admitted.
		return codeOrchestratorRouteNotAllowed
	}
	path := r.URL.Path
	switch {
	case r.Method == http.MethodPost && path == orchestratorDevLoopStartRoute:
		return ""
	case r.Method == http.MethodGet && path == "/api/v1/whoami":
		return ""
	case r.Method == http.MethodGet && orchestratorDevLoopReadRe.MatchString(path):
		if orchestratorDevLoopWorkflowAllowed(orchestratorDevLoopReadRe.FindStringSubmatch(path)[1]) {
			return ""
		}
		return codeOrchestratorRepoNotAllowed
	case orchestratorDevLoopApproveRe.MatchString(path):
		return codeOrchestratorApproveForbidden
	case orchestratorArgoInvestigateRe.MatchString(path):
		return codeOrchestratorTemporalRequired
	}
	return codeOrchestratorRouteNotAllowed
}

func isOrchestratorDevLoopStart(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == orchestratorDevLoopStartRoute
}

var orchestratorDevLoopRefusalText = map[string]string{
	codeOrchestratorRouteNotAllowed:  "the orchestrator may only call POST " + orchestratorDevLoopStartRoute + ", GET /api/v1/agents/dev-loop/{workflow_id} and GET /api/v1/whoami",
	codeOrchestratorApproveForbidden: "the orchestrator may not approve a DevLoop: approval is a human admin's decision",
	codeOrchestratorTemporalRequired: "the orchestrator may start a DevLoop only on the Temporal path (POST " + orchestratorDevLoopStartRoute + ")",
	codeOrchestratorRepoNotAllowed:   "the repository is not on the orchestrator's DevLoop allow-list",
	codeOrchestratorInvalidRequest:   "the DevLoop start request is malformed",
}

// orchestratorDevLoopGate confines the orchestrator DevLoop principal. It
// runs before any handler, so it also covers /mcp: the agent receipt gate
// never sees this principal, because no MCP tool call of it is ever served.
// Every request it judges is audited, admitted or refused, except an
// admitted start: the start handler records that one's real outcome, so the
// log never shows "allowed" for a start the handler then refuses.
func (h *Handlers) orchestratorDevLoopGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if !user.IsOrchestratorDevLoop() {
			next.ServeHTTP(w, r)
			return
		}
		code := orchestratorDevLoopRefusal(r)
		if code != "" || !isOrchestratorDevLoopStart(r) {
			h.auditOrchestratorDevLoop(r, user, code, "")
		}
		if code != "" {
			writeErrorCode(w, http.StatusForbidden, code, orchestratorDevLoopRefusalText[code], nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auditOrchestratorDevLoop records one judged request: code "" is admitted.
func (h *Handlers) auditOrchestratorDevLoop(r *http.Request, user *auth.User, code, issueURL string) {
	params := map[string]string{"method": r.Method, "path": r.URL.Path, "actor": user.ID}
	if issueURL != "" {
		params["issue_url"] = issueURL
	}
	status, msg := "allowed", ""
	if code != "" {
		params["code"] = code
		status, msg = "denied", orchestratorDevLoopRefusalText[code]
	}
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  orchestratorDevLoopAuditOperation,
		Parameters: params,
		Status:     status,
		RiskLevel:  string(operations.RiskMedium),
		Message:    msg,
	})
}

// auditOrchestratorDevLoopInvalid records a malformed start of the
// orchestrator principal, and nothing for any other caller.
func (h *Handlers) auditOrchestratorDevLoopInvalid(r *http.Request, user *auth.User, issueURL string) {
	if user.IsOrchestratorDevLoop() {
		h.auditOrchestratorDevLoop(r, user, codeOrchestratorInvalidRequest, issueURL)
	}
}
