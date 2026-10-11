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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The CI principal (mctl-api#530): one GitHub Actions job, authenticated by
// its OIDC token, deploying a tag of its own repository to the component
// registered to that repository. Which tag is the job's choice: the token's
// ref is not tied to git_tag, since any tag of the repository is within the
// repository's own authority. See docs/federation.md, "GitHub Actions: CI
// deploys".

const (
	codeCIRouteForbidden = "ci_route_not_allowed"
	codeCIDeployDenied   = "ci_deploy_denied"

	ciDeployOperation = "deploy-service"
	ciDeployRoute     = "/api/v1/operations/" + ciDeployOperation + "/execute"
)

// ciDeployParams are the only parameters a CI deploy may send. Everything
// else deploy-service accepts (env vars, secrets, host, scaling, database,
// template, image_tag) changes the service's configuration rather than
// shipping a new build, and stays with the tenant's humans.
var ciDeployParams = []string{"action", "team_name", "component_name", "dockerfile_repo", "git_tag", "dockerfile_path"}

var (
	ciNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	// ciGitTagRe is what a tag must look like to be built: the characters a
	// container image tag allows, so it maps onto one without rewriting.
	ciGitTagRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	// ciDockerfilePathRe is a relative path inside the repository; ".."
	// segments are refused separately.
	ciDockerfilePathRe = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]{0,199}$`)
)

// ComponentSourceRepoReader answers which repository is registered for a
// component. *gitops.Reader implements it.
type ComponentSourceRepoReader interface {
	ComponentSourceRepo(team, component string) (string, error)
}

// ciPrincipalGate confines a CI principal to the one deploy route. Every
// other route -- /mcp, every read, every other operation -- answers 403
// before a handler runs, in the shape of registryPublisherGate. An encoded
// path is refused for the same reason as there: chi routes on RawPath.
func ciPrincipalGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsCI() &&
			(r.Method != http.MethodPost || r.URL.RawPath != "" || r.URL.Path != ciDeployRoute) {
			writeErrorCode(w, http.StatusForbidden, codeCIRouteForbidden,
				"a GitHub Actions principal may only call POST "+ciDeployRoute, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorizeCIDeploy decides a CI principal's deploy request on the raw,
// undefaulted input. It stands in for tenant membership and role, which a
// CI principal does not have: the request must be a plain deploy of a
// component whose registered source repository is the token's repository.
// It writes the refusal and answers false on any doubt.
func (h *Handlers) authorizeCIDeploy(w http.ResponseWriter, r *http.Request, user *auth.User, opName string, op operations.Operation, input map[string]string) bool {
	repo := user.CIRepository()
	deny := func(status int, msg string) bool {
		// What was asked for, so a refused CI deploy can be read back. Only
		// the identifying fields: the rest is either refused or not secret
		// to begin with, and secret_env_vars is never echoed.
		params := map[string]string{}
		for _, k := range []string{"action", "team_name", "component_name", "dockerfile_repo", "git_tag"} {
			if v, ok := input[k]; ok {
				params[k] = v
			}
		}
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  opName,
			Parameters: params,
			Status:     "denied",
			RiskLevel:  string(op.RiskLevel),
			Message:    "ci deploy refused: " + msg,
		})
		writeErrorCode(w, status, codeCIDeployDenied, "CI deploy refused: "+msg, nil)
		return false
	}

	if opName != ciDeployOperation {
		return deny(http.StatusForbidden, "only "+ciDeployOperation+" is allowed")
	}
	if repo == "" {
		return deny(http.StatusForbidden, "the token names no repository")
	}
	var extra []string
	for k := range input {
		if !slices.Contains(ciDeployParams, k) {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return deny(http.StatusForbidden, "parameters not allowed for CI: "+strings.Join(extra, ", "))
	}
	if input["action"] != "deploy" {
		return deny(http.StatusForbidden, "action must be deploy")
	}
	team, component := input["team_name"], input["component_name"]
	if !ciNameRe.MatchString(team) || !ciNameRe.MatchString(component) {
		return deny(http.StatusBadRequest, "team_name and component_name must be lowercase names matching "+ciNameRe.String())
	}
	// git_tag decides what is built, so it is required; it and
	// dockerfile_path are the only free-form values this principal sends.
	if !ciGitTagRe.MatchString(input["git_tag"]) {
		return deny(http.StatusBadRequest, "git_tag is required and must match "+ciGitTagRe.String())
	}
	if p, ok := input["dockerfile_path"]; ok && !ciRelativePath(p) {
		return deny(http.StatusBadRequest, "dockerfile_path must be a relative path inside the repository, without .. segments")
	}
	if !strings.EqualFold(input["dockerfile_repo"], repo) {
		return deny(http.StatusForbidden, fmt.Sprintf("dockerfile_repo must be the token's repository %s", repo))
	}

	if h.opts.ComponentSourceRepos == nil {
		slog.Error("ci deploy: no component source repository reader configured")
		return deny(http.StatusServiceUnavailable, "the component registry is unavailable")
	}
	registered, err := h.opts.ComponentSourceRepos.ComponentSourceRepo(team, component)
	switch {
	case errors.Is(err, gitops.ErrSourceRepoNotRegistered):
		return deny(http.StatusForbidden, fmt.Sprintf("%s/%s has no registered source repository", team, component))
	case err != nil:
		// Could not read is not "not registered" and not "matches".
		slog.Error("ci deploy: reading the component source repository failed", "team", team, "component", component, "error", err)
		return deny(http.StatusServiceUnavailable, "the component registry could not be read")
	case !strings.EqualFold(registered, repo):
		return deny(http.StatusForbidden, fmt.Sprintf("%s/%s is not registered to %s", team, component, repo))
	}
	return true
}

func ciRelativePath(p string) bool {
	if !ciDockerfilePathRe.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
