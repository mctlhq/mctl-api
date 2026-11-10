// Copyright 2026 MCTL Authors
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

package glovojoin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

// Header names of the join contract (contract.headers).
const (
	SubjectTokenHeader    = "X-Mctl-Subject-Token" //nolint:gosec // header name, not a credential
	SelectedTenantHeader  = "X-Mctl-Selected-Tenant"
	ScopeRefHeader        = "X-Mctl-Scope-Ref"
	IdempotencyKeyHeader  = "Idempotency-Key"
	IdempotentReplayedHdr = "Idempotent-Replayed"
)

// Scopes the Glovo audience carries. The local OAuth access token has no scope
// claim: the Glovo audience is the grant of exactly these two scopes, so a
// route's scope is checked against this fixed set (design section 3, known gap
// recorded in the PR: a future token that carries a scope claim narrows it).
const (
	ScopeRead          = "glovo:read"
	ScopeBasketPrepare = "glovo:basket:prepare"
)

// Refusal is a refusal of the join surface: the glovo code (the wire code is
// decided by the contract table), the audit-only reason of design 4.2 and
// whether it is the 401 written by glovo.WriteUnauthenticated.
type Refusal struct {
	Err             *glovo.Error
	Reason          string
	Unauthenticated bool
}

func (r *Refusal) Error() string { return r.Reason + ": " + r.Err.Error() }

// Unwrap lets errors.Is match the glovo code.
func (r *Refusal) Unwrap() error { return r.Err }

func refusal(c glovo.Code, reason string) *Refusal {
	return &Refusal{Err: glovo.Refuse(c), Reason: reason}
}

func unauthenticated(reason string) *Refusal {
	return &Refusal{Err: glovo.Refuse(glovo.CodeNotAuthorized), Reason: reason, Unauthenticated: true}
}

// TokenValidator is the local-OAuth verification path (OAuthServer.ValidateJWT):
// signature, iss, exp, the audience precedence (a token whose audience mixes
// the Glovo resource with the API or support audience is refused).
type TokenValidator interface {
	ValidateJWT(token string) (*auth.User, error)
}

// ScopeResolver is the #960 resolver (scope.Resolver).
type ScopeResolver interface {
	Resolve(ctx context.Context, u *auth.User) (scope.Scope, *glovo.Error)
}

// InstallReader is the #959 install read.
type InstallReader interface {
	GetInstall(ctx context.Context, tenantID string) (*glovo.Install, error)
}

// Subject is a verified subject: everything the handlers know about the
// caller. Every field is derived from the verified token, the resolver and the
// install row; none comes from a header, a body or a route.
type Subject struct {
	PrincipalID     string
	Tenant          string
	GrantID         string
	FamilyID        string
	InstallID       string
	InstallRevision int64
	Scopes          []string
	// TokenHash is the hex sha256 of the subject token: the only form of it
	// that reaches an audit record or a span.
	TokenHash string
	ExpiresAt time.Time
	User      *auth.User
}

// HasScope reports whether the subject holds want.
func (s Subject) HasScope(want string) bool {
	for _, c := range s.Scopes {
		if c == want {
			return true
		}
	}
	return false
}

// SubjectVerifier re-verifies the human subject of a join call (design 2).
type SubjectVerifier struct {
	Tokens   TokenValidator
	Resolver ScopeResolver
	Installs InstallReader
	Now      func() time.Time
}

// queryTokenNames are the query parameters that name a token. The subject
// token is accepted in the header only; a token in the query string is refused
// before it can be logged by a proxy as a successful credential.
var queryTokenNames = map[string]bool{"x-mctl-subject-token": true, "subject_token": true, "access_token": true, "token": true}

// Verify checks the request's subject token and derives the Subject. It deletes
// the subject header from r. Every failure is a *Refusal: a failed read is
// never an empty subject.
func (v *SubjectVerifier) Verify(r *http.Request) (Subject, *Refusal) {
	if v == nil || v.Tokens == nil || v.Resolver == nil || v.Installs == nil {
		return Subject{}, refusal(glovo.CodeNotReady, "not_ready:subject_verifier")
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	for name := range r.URL.Query() {
		if queryTokenNames[strings.ToLower(name)] {
			r.Header.Del(SubjectTokenHeader)
			return Subject{}, unauthenticated("subject_token_invalid:in_query")
		}
	}
	vals := r.Header.Values(SubjectTokenHeader)
	r.Header.Del(SubjectTokenHeader)
	if len(vals) != 1 {
		return Subject{}, unauthenticated("subject_token_invalid:header")
	}
	token := strings.TrimSpace(vals[0])
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return Subject{}, unauthenticated("subject_token_invalid:header")
	}
	user, err := v.Tokens.ValidateJWT(token)
	if err != nil || user == nil {
		return Subject{}, unauthenticated("subject_token_invalid:verify")
	}
	if !user.IsGlovoAudience() {
		return Subject{}, unauthenticated("subject_token_invalid:audience")
	}
	exp, ok := tokenExpiry(token)
	if !ok || !exp.After(now()) {
		return Subject{}, unauthenticated("subject_token_invalid:exp")
	}
	_, stn, hasGrant := user.TeamGrant()
	if h := strings.TrimSpace(r.Header.Get(SelectedTenantHeader)); h != "" && hasGrant && h != stn {
		return Subject{}, refusal(glovo.CodeNotAuthorized, "tenant_mismatch")
	}
	sc, ge := v.Resolver.Resolve(r.Context(), user)
	if ge != nil {
		return Subject{}, &Refusal{Err: ge, Reason: "resolver:" + string(ge.Code)}
	}
	if sc.PrincipalID == "" || sc.Tenant == "" || sc.GrantID == "" || sc.RefreshFamilyID == "" {
		// A resolver answer without a family cannot bind a scope ref: refuse
		// rather than mint a ref that no grant revocation can kill.
		return Subject{}, refusal(glovo.CodeUnavailable, "dependency_unavailable:resolver_scope")
	}
	inst, err := v.Installs.GetInstall(r.Context(), sc.Tenant)
	if err != nil {
		var ge *glovo.Error
		if errors.As(err, &ge) {
			return Subject{}, &Refusal{Err: ge, Reason: "install:" + string(ge.Code)}
		}
		return Subject{}, refusal(glovo.CodeUnavailable, "dependency_unavailable:install")
	}
	sum := sha256.Sum256([]byte(token))
	return Subject{
		PrincipalID: sc.PrincipalID, Tenant: sc.Tenant, GrantID: sc.GrantID, FamilyID: sc.RefreshFamilyID,
		InstallID: inst.InstallID, InstallRevision: inst.InstallRevision,
		Scopes:    []string{ScopeRead, ScopeBasketPrepare},
		TokenHash: hex.EncodeToString(sum[:]), ExpiresAt: exp, User: user,
	}, nil
}

// tokenExpiry reads exp from a token the validator has already verified. It
// never trusts an unverified token: Verify calls it after ValidateJWT.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var c struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(b, &c) != nil || c.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(c.Exp, 0), true
}
