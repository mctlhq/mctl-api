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
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

const surfacePrincipalPath = "/api/v1/surface-principals/github"

// githubLoginResolver answers for GitHub login-only identities and records
// what it was asked.
type githubLoginResolver struct {
	pid   string
	err   error
	asked []auth.Identity
}

func (g *githubLoginResolver) ResolvePrincipal(_ context.Context, id auth.Identity) (string, error) {
	g.asked = append(g.asked, id)
	return g.pid, g.err
}

// resolveGitHub asks as who for the principal of actor, sent as the actor
// header ("" sends none), with no body.
func (e *sidEnv) resolveGitHub(who, actor string) (int, map[string]any) {
	e.t.Helper()
	if actor == "" {
		return e.do(who, "POST", surfacePrincipalPath, nil)
	}
	return e.do(who, "POST", surfacePrincipalPath, nil, SurfaceActorHeader, actor)
}

func TestResolveGitHubPrincipal_PortalGetsTheLoginsPrincipal(t *testing.T) {
	const pid = "prn_01M39HRB7JRXZ2PHW5VVB695YZ"
	pr := &githubLoginResolver{pid: pid}
	e := newSIDEnvWith(t, pr)
	code, body := e.resolveGitHub("portal", "github:Octo-Cat")
	if code != http.StatusOK || body["principalId"] != pid {
		t.Fatalf("resolve = %d %v", code, body)
	}
	// Asked as a login-only GitHub identity, which the resolver maps through
	// GitHub's numeric id and provisions like a first sign-in.
	if len(pr.asked) != 1 || !pr.asked[0].GitHubLoginOnly() || pr.asked[0].Display != "Octo-Cat" || pr.asked[0].Kind != auth.KindHuman {
		t.Fatalf("resolver asked %+v", pr.asked)
	}
	found := false
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "principal.resolve_github" && entry.Parameters["principal_id"] == pid &&
			entry.Parameters["github_login"] == "Octo-Cat" && entry.UserID == "surface:portal" {
			found = true
		}
	}
	if !found {
		t.Error("no audit entry for the resolution")
	}
}

func TestResolveGitHubPrincipal_OnlyThePortalSurface(t *testing.T) {
	pr := &githubLoginResolver{pid: "prn_01M39HRB7JRXZ2PHW5VVB695YZ"}
	e := newSIDEnvWith(t, pr)
	for _, who := range []string{"telegram", "alice", "root", "service"} {
		actor := "4242" // a valid telegram actor, so the handler answers
		if who != "telegram" {
			// Nobody but a surface may send the actor header at all.
			actor = ""
		}
		code, body := e.resolveGitHub(who, actor)
		if code != http.StatusForbidden || body["code"] != sidCodePortalOnly {
			t.Errorf("%s = %d %v", who, code, body)
		}
	}
	if len(pr.asked) != 0 {
		t.Fatalf("resolver reached by a non-portal caller: %+v", pr.asked)
	}
}

func TestResolveGitHubPrincipal_RefusesBadInput(t *testing.T) {
	pr := &githubLoginResolver{pid: "prn_01M39HRB7JRXZ2PHW5VVB695YZ"}
	e := newSIDEnvWith(t, pr)
	for _, actor := range []string{
		"", "octocat", "telegram:4242", "github:", "github:-octo", "github:octo-", "github:oc--to",
		"github:octo_cat", "github:octo.cat", "github:a123456789012345678901234567890123456789",
	} {
		if code, body := e.resolveGitHub("portal", actor); code != http.StatusBadRequest {
			t.Errorf("actor %q = %d %v", actor, code, body)
		}
	}
	// The body names nobody: an identity field is refused, so is any other.
	for _, body := range []map[string]any{{"login": "octocat"}, {"principal": "prn_x"}, {"extra": 1}} {
		if code, res := e.do("portal", "POST", surfacePrincipalPath, body, SurfaceActorHeader, "github:octocat"); code != http.StatusBadRequest {
			t.Errorf("body %v = %d %v", body, code, res)
		}
	}
	if len(pr.asked) != 0 {
		t.Fatalf("resolver reached on bad input: %+v", pr.asked)
	}
	// An empty object is no body, and the longest legal login is accepted.
	if code, res := e.do("portal", "POST", surfacePrincipalPath, map[string]any{}, SurfaceActorHeader, "github:octocat"); code != http.StatusOK {
		t.Errorf("{} body = %d %v", code, res)
	}
	if code, res := e.resolveGitHub("portal", "github:a12345678901234567890123456789012345678"); code != http.StatusOK {
		t.Errorf("39-character login = %d %v", code, res)
	}
}

// A failed or empty resolution is never reported as a principal, and never
// as "no principal".
func TestResolveGitHubPrincipal_Failures(t *testing.T) {
	for _, tc := range []struct {
		name string
		pr   auth.PrincipalResolver
		code int
		want string
	}{
		{"disabled", &githubLoginResolver{err: auth.ErrPrincipalDisabled}, http.StatusForbidden, sidCodePrincipalDisabled},
		{"refused", &githubLoginResolver{err: auth.ErrIdentityRefused}, http.StatusForbidden, sidCodeIdentityRefused},
		{"unreadable", &githubLoginResolver{err: errors.New("github user lookup: HTTP 502")}, http.StatusServiceUnavailable, sidCodeUnavailable},
		{"empty answer", &githubLoginResolver{}, http.StatusServiceUnavailable, sidCodeUnavailable},
		{"malformed answer", &githubLoginResolver{pid: "prn_short"}, http.StatusServiceUnavailable, sidCodeUnavailable},
		{"no store", nil, http.StatusServiceUnavailable, sidCodeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSIDEnvWith(t, tc.pr)
			code, body := e.resolveGitHub("portal", "github:octocat")
			if code != tc.code || body["code"] != tc.want || body["principalId"] != nil {
				t.Errorf("= %d %v, want %d %s", code, body, tc.code, tc.want)
			}
		})
	}
}
