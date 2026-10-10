// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
)

// CI deploys through a GitHub Actions OIDC principal (mctl-api#530).

type fakeSourceRepos struct {
	repos map[string]string // "team/component" -> owner/repo
	err   error
	calls int
}

func (f *fakeSourceRepos) ComponentSourceRepo(team, component string) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	repo, ok := f.repos[team+"/"+component]
	if !ok {
		return "", gitops.ErrSourceRepoNotRegistered
	}
	return repo, nil
}

type ciFixture struct {
	router http.Handler
	exec   *fakeExecutor
	audit  *audit.Logger
	repos  *fakeSourceRepos
}

func newCIFixture(t *testing.T, repos *fakeSourceRepos) *ciFixture {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "false")
	f := &ciFixture{exec: &fakeExecutor{}, audit: audit.NewLogger(), repos: repos}
	opts := mctlapi.Options{
		Registry: operations.NewRegistry(),
		// No members at all: a CI deploy must not depend on tenant roles.
		GitReader: &fakeGitReader{tenants: []gitops.Tenant{{Name: "labs"}}},
		AuditLog:  f.audit,
		Executor:  f.exec,
	}
	if repos != nil {
		opts.ComponentSourceRepos = repos
	}
	f.router = mctlapi.NewRouter(opts)
	return f
}

func defaultRepos() *fakeSourceRepos {
	return &fakeSourceRepos{repos: map[string]string{
		"labs/mctl-telegram": "mctlhq/mctl-telegram",
		"labs/seerrsense":    "mctlhq/seerrsense",
	}}
}

func ciUser() *auth.User { return auth.NewCIUser("mctlhq/mctl-telegram", "1001") }

func ciBody() map[string]string {
	return map[string]string{
		"action":          "deploy",
		"team_name":       "labs",
		"component_name":  "mctl-telegram",
		"dockerfile_repo": "mctlhq/mctl-telegram",
		"git_tag":         "0.80.0",
	}
}

func (f *ciFixture) refused(t *testing.T, body map[string]string, wantCode int, wantMsg string) {
	t.Helper()
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, ciUser())
	if w.Code != wantCode {
		t.Fatalf("status %d, want %d; body: %s", w.Code, wantCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), wantMsg) {
		t.Fatalf("body %s does not mention %q", w.Body.String(), wantMsg)
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("a workflow was submitted: %v", f.exec.submitted)
	}
	entries := f.audit.List(1)
	if len(entries) != 1 || entries[0].Status != "denied" || entries[0].UserID != "ci:mctlhq/mctl-telegram" {
		t.Fatalf("want one denied audit entry for the CI principal, got %+v", entries)
	}
}

func TestCIDeploy_DeploysItsOwnComponent(t *testing.T) {
	f := newCIFixture(t, defaultRepos())
	body := ciBody()
	// Owner and repository names are case-insensitive on GitHub.
	body["dockerfile_repo"] = "MCTLHQ/mctl-telegram"
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, ciUser())
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202; body: %s", w.Code, w.Body.String())
	}
	if len(f.exec.submitted) != 1 || f.exec.submitted[0] != "deploy-service" {
		t.Fatalf("submitted %v", f.exec.submitted)
	}
	got := f.exec.submittedParams[0]
	if got["action"] != "deploy" || got["git_tag"] != "0.80.0" || got["component_name"] != "mctl-telegram" {
		t.Fatalf("submitted params %v", got)
	}
	entries := f.audit.List(1)
	if len(entries) != 1 || entries[0].Status != "submitted" || entries[0].UserID != "ci:mctlhq/mctl-telegram" {
		t.Fatalf("audit %+v", entries)
	}
}

func TestCIDeploy_RefusesAnotherRepositorysComponent(t *testing.T) {
	f := newCIFixture(t, defaultRepos())
	body := ciBody()
	body["component_name"] = "seerrsense"
	body["dockerfile_repo"] = "mctlhq/mctl-telegram"
	f.refused(t, body, http.StatusForbidden, "is not registered to mctlhq/mctl-telegram")
}

func TestCIDeploy_RefusesDockerfileRepoOtherThanTheToken(t *testing.T) {
	f := newCIFixture(t, defaultRepos())
	body := ciBody()
	body["dockerfile_repo"] = "mctlhq/seerrsense"
	f.refused(t, body, http.StatusForbidden, "dockerfile_repo must be the token's repository")
	if f.repos.calls != 0 {
		t.Fatal("gitops was read for a request the token already refutes")
	}
}

func TestCIDeploy_RefusesUnregisteredComponent(t *testing.T) {
	f := newCIFixture(t, defaultRepos())
	body := ciBody()
	body["component_name"] = "brand-new"
	f.refused(t, body, http.StatusForbidden, "has no registered source repository")
}

func TestCIDeploy_OnlyTheDeployAction(t *testing.T) {
	for _, action := range []string{"onboard", "update-config", "", "DEPLOY"} {
		t.Run(action, func(t *testing.T) {
			f := newCIFixture(t, defaultRepos())
			body := ciBody()
			body["action"] = action
			f.refused(t, body, http.StatusForbidden, "action must be deploy")
		})
	}
}

func TestCIDeploy_RefusesEveryParameterOutsideTheAllowlist(t *testing.T) {
	for _, p := range []string{
		"env_vars", "secret_env_vars", "clear_env", "clear_secrets", "host", "port",
		"provision_database", "image_tag", "service_template", "autoscaling_enabled",
		"component_type", "skip_health_check", "health_check_path", "config_patch",
	} {
		t.Run(p, func(t *testing.T) {
			f := newCIFixture(t, defaultRepos())
			body := ciBody()
			body[p] = "x"
			f.refused(t, body, http.StatusForbidden, "parameters not allowed for CI: "+p)
		})
	}
}

func TestCIDeploy_RefusesOtherOperations(t *testing.T) {
	// Behind the route gate this is unreachable; called directly on the
	// handler path it is refused on its own.
	f := newCIFixture(t, defaultRepos())
	for _, op := range []string{"retire-service", "rollback-service", "provision-database"} {
		w := postAs(t, f.router, "/api/v1/operations/"+op+"/execute", retireBody, ciUser())
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403; body %s", op, w.Code, w.Body.String())
		}
	}
	if len(f.exec.submitted) != 0 {
		t.Fatalf("submitted %v", f.exec.submitted)
	}
}

func TestCIDeploy_UnreadableGitopsIsNotAnswerable(t *testing.T) {
	f := newCIFixture(t, &fakeSourceRepos{err: errors.New("checkout unavailable")})
	f.refused(t, ciBody(), http.StatusServiceUnavailable, "could not be read")
}

func TestCIDeploy_NoSourceRepoReaderRefuses(t *testing.T) {
	f := newCIFixture(t, nil)
	f.refused(t, ciBody(), http.StatusServiceUnavailable, "unavailable")
}

func TestCIDeploy_EmptyRepositoryRefused(t *testing.T) {
	f := newCIFixture(t, &fakeSourceRepos{repos: map[string]string{"labs/x": ""}})
	u := auth.NewCIUser("", "1001")
	body := ciBody()
	body["component_name"], body["dockerfile_repo"] = "x", ""
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, u)
	if w.Code != http.StatusForbidden || len(f.exec.submitted) != 0 {
		t.Fatalf("status %d, submitted %v", w.Code, f.exec.submitted)
	}
}

// A tenant member's deploy is untouched by any of this: no CI rule applies,
// and an extra parameter still passes as before.
func TestCIDeploy_HumansAreUnaffected(t *testing.T) {
	f := newRoleFixture(t)
	body := ciBody()
	body["team_name"] = "erpact"
	body["env_vars"] = "A=1"
	w := postAs(t, f.router, "/api/v1/operations/deploy-service/execute", body, member("dan-dev"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d; body %s", w.Code, w.Body.String())
	}
}
