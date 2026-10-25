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
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// The build workflow's repository-binding check. mctl-gitops'
// build-image.yaml refuses to check out a private repository for a
// component that is not registered yet unless a Vault PAT is bound for it,
// because whoever can dispatch that workflow names the repository. The
// platform's own onboard dispatches it the same way, so a private repository
// connected to the team through the GitHub App could never be onboarded.
// This route gives the workflow the answer mctl-api itself acts on before it
// submits a build (checkBuildRepos): is the repository connected to the
// team in the portal.
//
// Only that workflow may ask. A GitHub Actions token is accepted from any
// repository of a trusted owner, so the route pins the token's
// job_workflow_ref, which GitHub sets to the workflow file and ref the job
// ran, and which a tenant cannot mint for mctl-gitops' main branch. It also
// pins the token's repository to mctl-gitops: when another repository calls
// build-image.yaml as a reusable workflow, job_workflow_ref still names
// build-image.yaml, but repository names the caller.

const (
	codeCIBuildBindingDenied = "ci_build_binding_denied"

	ciBuildBindingRoute = "/api/v1/ci/build-repo-binding"

	// buildImageWorkflowRef is the only job_workflow_ref this route serves.
	// build-image.yaml is also called as a reusable workflow, and GitHub
	// sets job_workflow_ref to the called file in that case too, hence
	// buildImageRepository.
	buildImageWorkflowRef = "mctlhq/mctl-gitops/.github/workflows/build-image.yaml@refs/heads/main"

	// buildImageRepository is the only token repository this route serves.
	buildImageRepository = "mctlhq/mctl-gitops"
)

// CIBuildRepoBinding answers whether repo is connected to team in the
// portal. GET /api/v1/ci/build-repo-binding?team=<team>&repo=<owner/name>.
// 200 {"team","repo","bound"} is a verdict; any lookup failure is 503, never
// "not bound".
func (h *Handlers) CIBuildRepoBinding(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsCI() || user.CIJobWorkflowRef() != buildImageWorkflowRef ||
		!strings.EqualFold(user.CIRepository(), buildImageRepository) {
		// repository is what tells a reusable call of build-image.yaml from
		// another repository apart: its job_workflow_ref is the right one.
		slog.Warn("ci build binding refused", "user", user.ID,
			"job_workflow_ref", user.CIJobWorkflowRef(), "repository", user.CIRepository())
		writeErrorCode(w, http.StatusForbidden, codeCIBuildBindingDenied,
			"only "+buildImageWorkflowRef+" may call this route", nil)
		return
	}
	q := r.URL.Query()
	team, repo := q.Get("team"), q.Get("repo")
	if len(q["team"]) != 1 || len(q["repo"]) != 1 || !ciNameRe.MatchString(team) {
		writeError(w, http.StatusBadRequest, "exactly one team (a tenant name) and one repo are required")
		return
	}
	owner, name, _ := strings.Cut(repo, "/")
	if !repoFullNameRE.MatchString(repo) || isDotOnly(owner) || isDotOnly(name) {
		writeError(w, http.StatusBadRequest, "repo must be a GitHub repository name (owner/name)")
		return
	}
	bound, err := h.repoBoundToTeam(r.Context(), team, repo)
	if err != nil {
		slog.Error("ci build binding lookup failed", "team", team, "repo", repo, "error", err)
		writeError(w, http.StatusServiceUnavailable, "cannot check the repository binding right now")
		return
	}
	slog.Info("ci build binding", "team", team, "repo", repo, "bound", bound)
	writeJSON(w, http.StatusOK, map[string]any{"team": team, "repo": repo, "bound": bound})
}
