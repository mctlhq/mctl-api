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

package auth

// provider_github_actions.go verifies GitHub Actions OIDC tokens for CI
// deploys (mctl-api#530). The token proves which repository, event and ref a
// job ran for; this provider refuses every token outside the configured
// owners, events and refs. What the resulting principal may call is decided
// in internal/api (ciPrincipalGate, authorizeCIDeploy), not here.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// GitHubActionsIssuer is the issuer of every GitHub Actions OIDC token on
// github.com. Fixed: GitHub Enterprise Server issuers are not supported.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// DefaultGitHubActionsAudience is the audience a workflow requests with
// core.getIDToken / ACTIONS_ID_TOKEN_REQUEST_URL&audience=... when the
// configuration names none.
const DefaultGitHubActionsAudience = "https://api.mctl.ai"

// githubActionsEvents are the workflow events a CI token may come from.
// Each runs only on a ref someone with write access put there. Every other
// event is refused: pull_request and pull_request_target run for forks and
// unmerged code, and schedule, workflow_run, issue_comment and the like can
// be steered by people without write access.
var githubActionsEvents = []string{"push", "workflow_dispatch", "release"}

// GitHubActionsOIDCConfig is MCTL_GITHUB_ACTIONS_OIDC. Unset means the
// provider is not registered at all.
type GitHubActionsOIDCConfig struct {
	// Audience the token's aud must contain. Defaults to
	// DefaultGitHubActionsAudience.
	Audience string `json:"audience,omitempty"`
	// RepositoryOwners are the GitHub owners (org or user logins) whose
	// repositories may deploy. Required and non-empty: a name can be
	// recreated after a delete, and only within an owner the platform
	// trusts is that the same party.
	RepositoryOwners []string `json:"repository_owners"`
	// RepositoryOwnerIDs optionally pins the owners' immutable numeric ids
	// as well; when set, repository_owner_id must be one of them.
	RepositoryOwnerIDs []string `json:"repository_owner_ids,omitempty"`
	// Branches are the full branch refs a token may come from, e.g.
	// "refs/heads/main". Defaults to ["refs/heads/main"]. Tags
	// (refs/tags/*) are always accepted.
	Branches []string `json:"branches,omitempty"`
}

var (
	githubLoginRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	numericIDRe   = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	branchRefRe   = regexp.MustCompile(`^refs/heads/[A-Za-z0-9._/-]+$`)
)

// ParseGitHubActionsOIDC decodes and validates MCTL_GITHUB_ACTIONS_OIDC.
// Unset or blank returns nil: the provider is off. Anything malformed refuses
// boot rather than registering a provider with a policy nobody wrote.
func ParseGitHubActionsOIDC(raw string) (*GitHubActionsOIDCConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg *GitHubActionsOIDCConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: trailing data after the JSON object")
	}
	if cfg == nil {
		return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: null is not a configuration (unset the variable to disable)")
	}
	if cfg.Audience == "" {
		cfg.Audience = DefaultGitHubActionsAudience
	}
	if len(cfg.RepositoryOwners) == 0 {
		return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: repository_owners is required and must not be empty")
	}
	for _, o := range cfg.RepositoryOwners {
		if !githubLoginRe.MatchString(o) {
			return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: repository_owners entry %q is not a GitHub login", o)
		}
	}
	for _, id := range cfg.RepositoryOwnerIDs {
		if !numericIDRe.MatchString(id) {
			return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: repository_owner_ids entry %q is not a numeric id", id)
		}
	}
	if len(cfg.Branches) == 0 {
		cfg.Branches = []string{"refs/heads/main"}
	}
	for _, b := range cfg.Branches {
		if !branchRefRe.MatchString(b) || strings.Contains(b, "..") {
			return nil, fmt.Errorf("MCTL_GITHUB_ACTIONS_OIDC: branches entry %q is not a full branch ref (refs/heads/<name>, no wildcards)", b)
		}
	}
	return cfg, nil
}

// githubActionsProvider verifies GitHub Actions OIDC tokens.
type githubActionsProvider struct {
	cfg      GitHubActionsOIDCConfig
	verifier oidcTokenVerifier
}

// newGitHubActionsProviderFn is the constructor BuildFederationRegistry
// calls; a seam so the registry composition is testable without the network.
var newGitHubActionsProviderFn = newGitHubActionsProvider

// newGitHubActionsProvider discovers GitHub's JWKS. The library's audience
// check is skipped only because Verify below makes its own, stricter one
// (exact membership, no audit mode).
func newGitHubActionsProvider(ctx context.Context, cfg GitHubActionsOIDCConfig) (*githubActionsProvider, error) {
	p, err := oidc.NewProvider(ctx, GitHubActionsIssuer)
	if err != nil {
		return nil, fmt.Errorf("github actions oidc init failed: %w", err)
	}
	return &githubActionsProvider{cfg: cfg, verifier: goOIDCVerifier{v: p.Verifier(&oidc.Config{SkipClientIDCheck: true})}}, nil
}

func newGitHubActionsProviderForTest(cfg GitHubActionsOIDCConfig, verifier oidcTokenVerifier) *githubActionsProvider {
	return &githubActionsProvider{cfg: cfg, verifier: verifier}
}

func (p *githubActionsProvider) Name() string       { return ProviderGitHubActions }
func (p *githubActionsProvider) issuerName() string { return GitHubActionsIssuer }

func (p *githubActionsProvider) Claims(t tokenShape) bool {
	return t.jwt && normalizeIssuer(t.iss) == normalizeIssuer(GitHubActionsIssuer)
}

// errGitHubActionsPolicy is wrapped by every policy refusal, so the reason
// reaches the log without leaking token contents to the caller.
type errGitHubActionsPolicy struct{ reason string }

func (e errGitHubActionsPolicy) Error() string {
	return "github actions token refused: " + e.reason
}

func (p *githubActionsProvider) refuse(reason string, attrs ...any) error {
	slog.Warn("github actions token refused", append([]any{"reason", reason}, attrs...)...)
	return errGitHubActionsPolicy{reason: reason}
}

func (p *githubActionsProvider) Verify(ctx context.Context, raw string) (*Verified, error) {
	tok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid github-actions JWT: %w", err)
	}
	if normalizeIssuer(tok.Issuer) != normalizeIssuer(GitHubActionsIssuer) {
		return nil, p.refuse("issuer", "issuer", tok.Issuer)
	}
	if p.cfg.Audience == "" || !slices.Contains(tok.Audience, p.cfg.Audience) {
		return nil, p.refuse("audience", "audience", tok.Audience)
	}

	// Every claim the policy reads must be present and a string: a missing
	// one is a refusal, never a default.
	claim := func(name string) (string, bool) {
		v, ok := stringClaim(tok.Claims, name)
		return v, ok && v != ""
	}
	repo, ok1 := claim("repository")
	repoID, ok2 := claim("repository_id")
	owner, ok3 := claim("repository_owner")
	ownerID, ok4 := claim("repository_owner_id")
	event, ok5 := claim("event_name")
	ref, ok6 := claim("ref")
	refType, ok7 := claim("ref_type")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return nil, p.refuse("claims", "repository", repo)
	}

	if !numericIDRe.MatchString(repoID) || !numericIDRe.MatchString(ownerID) {
		return nil, p.refuse("claims", "repository", repo)
	}
	name, found := strings.CutPrefix(strings.ToLower(repo), strings.ToLower(owner)+"/")
	if !found || name == "" || strings.Contains(name, "/") || !githubLoginRe.MatchString(owner) {
		return nil, p.refuse("claims", "repository", repo, "repository_owner", owner)
	}
	if !slices.ContainsFunc(p.cfg.RepositoryOwners, func(o string) bool { return strings.EqualFold(o, owner) }) {
		return nil, p.refuse("owner", "repository", repo)
	}
	if len(p.cfg.RepositoryOwnerIDs) > 0 && !slices.Contains(p.cfg.RepositoryOwnerIDs, ownerID) {
		return nil, p.refuse("owner_id", "repository", repo, "repository_owner_id", ownerID)
	}
	if !slices.Contains(githubActionsEvents, event) {
		return nil, p.refuse("event", "repository", repo, "event_name", event)
	}
	switch {
	case refType == "tag" && strings.HasPrefix(ref, "refs/tags/") && len(ref) > len("refs/tags/"):
	case refType == "branch" && slices.Contains(p.cfg.Branches, ref):
	default:
		return nil, p.refuse("ref", "repository", repo, "ref", ref, "ref_type", refType)
	}

	// GitHub names are case-insensitive: one repository is one display and
	// one rate-limit bucket however the token spells it.
	repo = strings.ToLower(repo)
	return &Verified{
		Identity: Identity{
			Provider: ProviderGitHubActions,
			Issuer:   GitHubActionsIssuer,
			Subject:  repoID,
			Display:  "ci:" + repo,
			Kind:     KindService,
		},
		Claims: Claims{CIRepository: repo},
	}, nil
}
