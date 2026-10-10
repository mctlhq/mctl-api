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

package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// GitHub Actions OIDC provider (mctl-api#530).

func ghaConfig() GitHubActionsOIDCConfig {
	cfg, err := ParseGitHubActionsOIDC(`{"repository_owners":["mctlhq"]}`)
	if err != nil {
		panic(err)
	}
	return *cfg
}

func ghaClaims() map[string]any {
	return map[string]any{
		"sub":                 "repo:mctlhq/mctl-telegram:ref:refs/heads/main",
		"repository":          "mctlhq/mctl-telegram",
		"repository_id":       "1001",
		"repository_owner":    "mctlhq",
		"repository_owner_id": "2002",
		"event_name":          "push",
		"ref":                 "refs/heads/main",
		"ref_type":            "branch",
	}
}

func ghaVerify(t *testing.T, cfg GitHubActionsOIDCConfig, aud []string, claims map[string]any) (*Verified, error) {
	t.Helper()
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: GitHubActionsIssuer, Audience: aud, Claims: claims}}
	return newGitHubActionsProviderForTest(cfg, fv).Verify(context.Background(), "tok")
}

func TestGitHubActions_AcceptsAMainBranchPush(t *testing.T) {
	v, err := ghaVerify(t, ghaConfig(), []string{DefaultGitHubActionsAudience}, ghaClaims())
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{Provider: ProviderGitHubActions, Issuer: GitHubActionsIssuer, Subject: "1001", Display: "ci:mctlhq/mctl-telegram", Kind: KindService}
	if v.Identity != want || v.Claims.CIRepository != "mctlhq/mctl-telegram" || len(v.Claims.Groups) != 0 {
		t.Fatalf("got %+v", v)
	}

	u := userFromVerified(v)
	if !u.IsCI() || u.CIRepository() != "mctlhq/mctl-telegram" || u.ID != "ci:mctlhq/mctl-telegram" {
		t.Fatalf("user %+v", u)
	}
	if u.IsAdmin() || u.HasTenantAccess("labs") || u.IsService() || len(u.Groups) != 0 {
		t.Fatal("a CI principal must hold no group, tenant or service standing")
	}
	id, ok := u.Identity()
	if !ok || id != want {
		t.Fatalf("Identity() = %+v, %v", id, ok)
	}
}

func TestGitHubActions_AcceptsTagsAndOtherAllowedEvents(t *testing.T) {
	for name, mut := range map[string]func(map[string]any){
		"tag push":          func(c map[string]any) { c["ref"], c["ref_type"] = "refs/tags/1.2.3", "tag" },
		"release":           func(c map[string]any) { c["event_name"], c["ref"], c["ref_type"] = "release", "refs/tags/1.2.3", "tag" },
		"workflow_dispatch": func(c map[string]any) { c["event_name"] = "workflow_dispatch" },
		"owner case":        func(c map[string]any) { c["repository_owner"], c["repository"] = "MCTLHQ", "MCTLHQ/mctl-telegram" },
	} {
		t.Run(name, func(t *testing.T) {
			c := ghaClaims()
			mut(c)
			v, err := ghaVerify(t, ghaConfig(), []string{DefaultGitHubActionsAudience}, c)
			if err != nil {
				t.Fatal(err)
			}
			// One repository is one identity however the token spells it.
			if v.Identity.Display != "ci:mctlhq/mctl-telegram" || v.Claims.CIRepository != "mctlhq/mctl-telegram" {
				t.Fatalf("got %q / %q", v.Identity.Display, v.Claims.CIRepository)
			}
		})
	}
}

func TestGitHubActions_Refusals(t *testing.T) {
	cases := map[string]struct {
		aud    []string
		mut    func(map[string]any)
		cfg    func(*GitHubActionsOIDCConfig)
		reason string
	}{
		"wrong audience":         {aud: []string{"sts.amazonaws.com"}, reason: "audience"},
		"no audience":            {aud: nil, reason: "audience"},
		"pull_request":           {mut: func(c map[string]any) { c["event_name"] = "pull_request" }, reason: "event"},
		"pull_request_target":    {mut: func(c map[string]any) { c["event_name"] = "pull_request_target" }, reason: "event"},
		"schedule":               {mut: func(c map[string]any) { c["event_name"] = "schedule" }, reason: "event"},
		"workflow_run":           {mut: func(c map[string]any) { c["event_name"] = "workflow_run" }, reason: "event"},
		"feature branch":         {mut: func(c map[string]any) { c["ref"] = "refs/heads/feature" }, reason: "ref"},
		"pull ref":               {mut: func(c map[string]any) { c["ref"] = "refs/pull/7/merge" }, reason: "ref"},
		"tag ref typed branch":   {mut: func(c map[string]any) { c["ref"] = "refs/tags/1.0.0" }, reason: "ref"},
		"branch ref typed tag":   {mut: func(c map[string]any) { c["ref_type"] = "tag" }, reason: "ref"},
		"empty tag":              {mut: func(c map[string]any) { c["ref"], c["ref_type"] = "refs/tags/", "tag" }, reason: "ref"},
		"foreign owner":          {mut: func(c map[string]any) { c["repository_owner"], c["repository"] = "evil", "evil/mctl-telegram" }, reason: "owner"},
		"repo outside its owner": {mut: func(c map[string]any) { c["repository"] = "evil/mctl-telegram" }, reason: "claims"},
		"nested repo":            {mut: func(c map[string]any) { c["repository"] = "mctlhq/a/b" }, reason: "claims"},
		"missing repository_id":  {mut: func(c map[string]any) { delete(c, "repository_id") }, reason: "claims"},
		"non-numeric repo id":    {mut: func(c map[string]any) { c["repository_id"] = "abc" }, reason: "claims"},
		"missing event":          {mut: func(c map[string]any) { delete(c, "event_name") }, reason: "claims"},
		"missing ref_type":       {mut: func(c map[string]any) { delete(c, "ref_type") }, reason: "claims"},
		"non-string repository":  {mut: func(c map[string]any) { c["repository"] = 5 }, reason: "claims"},
		"owner id pinned":        {cfg: func(c *GitHubActionsOIDCConfig) { c.RepositoryOwnerIDs = []string{"999"} }, reason: "owner_id"},
		"branch not configured": {
			cfg: func(c *GitHubActionsOIDCConfig) { c.Branches = []string{"refs/heads/release"} }, reason: "ref",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := ghaConfig()
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			aud := tc.aud
			if aud == nil && name != "no audience" {
				aud = []string{DefaultGitHubActionsAudience}
			}
			c := ghaClaims()
			if tc.mut != nil {
				tc.mut(c)
			}
			v, err := ghaVerify(t, cfg, aud, c)
			var pe errGitHubActionsPolicy
			if err == nil || !errors.As(err, &pe) || pe.reason != tc.reason {
				t.Fatalf("got v=%+v err=%v, want refusal %q", v, err, tc.reason)
			}
		})
	}
}

func TestGitHubActions_WrongIssuerRefused(t *testing.T) {
	fv := fakeOIDCVerifier{tok: &oidcVerifiedToken{Issuer: "https://evil.example", Audience: []string{DefaultGitHubActionsAudience}, Claims: ghaClaims()}}
	if _, err := newGitHubActionsProviderForTest(ghaConfig(), fv).Verify(context.Background(), "tok"); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
	p := newGitHubActionsProviderForTest(ghaConfig(), fv)
	if p.Claims(tokenShape{jwt: true, iss: "https://evil.example"}) || p.Claims(tokenShape{}) {
		t.Fatal("the provider claims tokens of another issuer")
	}
	if !p.Claims(tokenShape{jwt: true, iss: GitHubActionsIssuer}) {
		t.Fatal("the provider does not claim its own issuer")
	}
}

func TestGitHubActions_BadSignatureRefused(t *testing.T) {
	fv := fakeOIDCVerifier{err: errors.New("bad signature")}
	if _, err := newGitHubActionsProviderForTest(ghaConfig(), fv).Verify(context.Background(), "tok"); err == nil {
		t.Fatal("accepted")
	}
}

func TestParseGitHubActionsOIDC(t *testing.T) {
	if cfg, err := ParseGitHubActionsOIDC("  "); cfg != nil || err != nil {
		t.Fatalf("unset must be off: %+v %v", cfg, err)
	}
	cfg, err := ParseGitHubActionsOIDC(`{"repository_owners":["mctlhq"]}`)
	if err != nil || cfg.Audience != DefaultGitHubActionsAudience || strings.Join(cfg.Branches, ",") != "refs/heads/main" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	for name, raw := range map[string]string{
		"null":          `null`,
		"malformed":     `{`,
		"no owners":     `{}`,
		"empty owners":  `{"repository_owners":[]}`,
		"bad owner":     `{"repository_owners":["a/b"]}`,
		"bad owner id":  `{"repository_owners":["mctlhq"],"repository_owner_ids":["x1"]}`,
		"wildcard":      `{"repository_owners":["mctlhq"],"branches":["refs/heads/*"]}`,
		"short ref":     `{"repository_owners":["mctlhq"],"branches":["main"]}`,
		"unknown field": `{"repository_owners":["mctlhq"],"allow_pull_requests":true}`,
		"trailing":      `{"repository_owners":["mctlhq"]} {}`,
		"dotdot":        `{"repository_owners":["mctlhq"],"branches":["refs/heads/../tags/x"]}`,
	} {
		if _, err := ParseGitHubActionsOIDC(raw); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

func TestGitHubActions_RegistryComposition(t *testing.T) {
	orig := newGitHubActionsProviderFn
	t.Cleanup(func() { newGitHubActionsProviderFn = orig })
	newGitHubActionsProviderFn = func(_ context.Context, cfg GitHubActionsOIDCConfig) (*githubActionsProvider, error) {
		return newGitHubActionsProviderForTest(cfg, fakeOIDCVerifier{}), nil
	}

	// Off unless configured.
	r, err := BuildFederationRegistry(context.Background(), FederationProvidersConfig{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.jwt {
		if p.Name() == ProviderGitHubActions {
			t.Fatal("registered without configuration")
		}
	}
	if _, err := r.Verify(context.Background(), fakeJWT(GitHubActionsIssuer)); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("an unconfigured GitHub Actions token must be unclaimed, got %v", err)
	}

	r, err = BuildFederationRegistry(context.Background(), FederationProvidersConfig{GitHubActionsRaw: `{"repository_owners":["mctlhq"]}`}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range r.jwt {
		found = found || p.Name() == ProviderGitHubActions
	}
	if !found {
		t.Fatal("configured but not registered")
	}

	if _, err := BuildFederationRegistry(context.Background(), FederationProvidersConfig{GitHubActionsRaw: `{}`}, nil, nil, nil); err == nil {
		t.Fatal("a malformed configuration must refuse boot")
	}
}

func TestGitHubActions_NameAndIssuerAreReserved(t *testing.T) {
	if _, err := ParseOIDCProviders(`[{"name":"github-actions","issuer":"https://x.example","audiences":["a"]}]`); err == nil {
		t.Fatal("an MCTL_OIDC_PROVIDERS entry may not take the github-actions name")
	}
	generic := newOIDCProviderForTest(OIDCProviderSpec{Name: "github-actions", Issuer: "https://x.example", Audiences: []string{"a"}}, fakeOIDCVerifier{})
	if _, err := NewRegistry(nil, []Provider{generic}, nil); err == nil {
		t.Fatal("a generic provider may not declare the github-actions namespace")
	}
	other := newOIDCProviderForTest(OIDCProviderSpec{Name: "ghx", Issuer: GitHubActionsIssuer, Audiences: []string{"a"}}, fakeOIDCVerifier{})
	gha := newGitHubActionsProviderForTest(ghaConfig(), fakeOIDCVerifier{})
	if _, err := NewRegistry(nil, []Provider{other, gha}, nil); err == nil {
		t.Fatal("two providers on the GitHub Actions issuer must refuse boot")
	}
	if _, err := NewRegistry(nil, []Provider{gha}, nil); err != nil {
		t.Fatalf("the dedicated provider must be accepted: %v", err)
	}
}
