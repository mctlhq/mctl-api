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

// Package glovobasketjoin is the basket join API: the routes under
// /api/v1/assistants/glovo-basket/v1 that the separate Glovo basket service
// (mctl-glovo) calls on behalf of one end user, so that the scope resolution,
// the approval ledger, the allowlist and the grants stay in mctl-api while
// the basket MCP itself moves out.
//
// The caller is one configured service principal (the router's gate admits
// nobody else). The end user is proven by their own Glovo-audience access
// token in X-Mctl-Subject-Token, verified here exactly like the order join
// (glovojoin.VerifySubjectToken), checked against the principal store and
// resolved by scope.Resolve on every request: nothing is cached here, so a
// revoked grant, a removed membership or a removed allowlist row takes effect
// on the next call. A read that fails is a 503, never an empty or allowed
// answer.
//
// The service never decides an approval: it can only ask for one. The owner
// decides on the approval page, which stays in mctl-api next to the ledger.
package glovobasketjoin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Paths, relative to the mount point.
const (
	PathResolve   = "/resolve"
	PathApprovals = "/approvals"
)

// DeciderRole is the least tenant role with which the end user can decide a
// basket approval on the approval page (api.glovoMinDeciderRole, pinned by a
// test there).
const DeciderRole = operations.RoleDeveloper

// Default limits.
const (
	DefaultPerSubjectPerMinute = 60
	DefaultWritesPerMinute     = 10
	DefaultAggregatePerMinute  = 600
	// MaxBodyBytes bounds one request body: a 30-line basket with names.
	MaxBodyBytes = 32 << 10
)

// Approvals is the ledger side (glovobasket.PGStore).
type Approvals interface {
	RequestApprovalFromSnapshot(ctx context.Context, o glovobasket.Owner, in glovobasket.SnapshotApprovalInput, ttl time.Duration) (*glovobasket.ApprovalRequest, error)
}

// Refused is one refusal, for metrics and audit. Reason never reaches the
// wire and never carries a token or a body.
type Refused struct {
	Route  string
	Code   glovo.Code
	Status int
	Reason string
}

// Service is the basket join API. A nil dependency answers 503 not_ready.
type Service struct {
	// Tokens verifies the subject token (OAuthServer.ValidateJWT).
	Tokens glovojoin.TokenValidator
	// Principals checks the subject's principal exactly like the auth
	// middleware does for a bearer (auth.AttachPrincipal): a disabled
	// principal is refused, a store that does not answer is 503.
	Principals auth.PrincipalResolver
	// Resolver is scope.Resolver.
	Resolver glovojoin.ScopeResolver
	// Approvals is the basket ledger.
	Approvals Approvals
	// ApprovalTTL of a requested approval; 0 is glovobasket.DefaultApprovalTTL.
	ApprovalTTL time.Duration
	// ApprovalPageBaseURL is the https origin of the owner approval page;
	// empty returns no approval_url.
	ApprovalPageBaseURL string
	// OnRefused is called once per refusal.
	OnRefused func(Refused)
	// Limits; zero keeps the default.
	PerSubject, Writes, Aggregate int
	// Now is the clock of the subject token expiry check; nil is time.Now.
	Now func() time.Time

	once                       sync.Once
	perSubject, writes, aggreg *httprate.RateLimiter
	pageOrigin                 string
	pageErr                    error
}

func (s *Service) init() {
	s.once.Do(func() {
		pick := func(v, def int) int {
			if v > 0 {
				return v
			}
			return def
		}
		s.perSubject = httprate.NewRateLimiter(pick(s.PerSubject, DefaultPerSubjectPerMinute), time.Minute)
		s.writes = httprate.NewRateLimiter(pick(s.Writes, DefaultWritesPerMinute), time.Minute)
		s.aggreg = httprate.NewRateLimiter(pick(s.Aggregate, DefaultAggregatePerMinute), time.Minute)
		if s.ApprovalPageBaseURL != "" {
			u, err := url.Parse(s.ApprovalPageBaseURL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
				s.pageErr = errors.New("glovo basket join: approval page base URL must be an https origin")
				return
			}
			s.pageOrigin = "https://" + u.Host
		}
	})
}

// Validate reports a configuration the routes would refuse every request
// with. cmd/api calls it at boot.
func (s *Service) Validate() error {
	s.init()
	switch {
	case s.pageErr != nil:
		return s.pageErr
	case s.Tokens == nil || glovo.IsNil(s.Principals) || s.Resolver == nil || glovo.IsNil(s.Approvals):
		return errors.New("glovo basket join: token validator, principal resolver, scope resolver and approvals are required")
	}
	return nil
}

// Handler returns the routes, relative to the mount point.
func (s *Service) Handler() http.Handler {
	s.init()
	r := chi.NewRouter()
	r.Post(PathResolve, s.pipeline("resolve", false, s.resolve))
	r.Post(PathApprovals, s.pipeline("approvals", true, s.approvals))
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { glovo.WriteError(w, glovo.ErrNotFound) })
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) { glovo.WriteError(w, glovo.ErrNotFound) })
	return r
}

type handler func(ctx context.Context, sub subject, body []byte) (int, any, *glovojoin.Refusal)

// subject is the verified and resolved end user of one request.
type subject struct {
	owner     glovobasket.Owner
	role      string
	expiresAt time.Time
}

func refusal(c glovo.Code, reason string) *glovojoin.Refusal {
	return &glovojoin.Refusal{Err: glovo.Refuse(c), Reason: reason}
}

func (s *Service) refuse(w http.ResponseWriter, route string, rf *glovojoin.Refusal) {
	if rf == nil || rf.Err == nil {
		rf = refusal(glovo.CodeUnavailable, "invariant")
	}
	status := glovo.Status(rf.Err.Code)
	if rf.Unauthenticated {
		status = http.StatusUnauthorized
	}
	if s.OnRefused != nil {
		s.OnRefused(Refused{Route: route, Code: rf.Err.Code, Status: status, Reason: rf.Reason})
	}
	if rf.Unauthenticated {
		glovo.WriteUnauthenticated(w, "")
		return
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	glovo.WriteError(w, rf.Err)
}

// pipeline is the order of both routes: the aggregate limit, the subject
// token, the principal check, scope.Resolve (uncached), the per-subject
// limits, the body, the handler.
func (s *Service) pipeline(route string, write bool, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Validate() != nil {
			r.Header.Del(glovojoin.SubjectTokenHeader)
			s.refuse(w, route, refusal(glovo.CodeNotReady, "not_ready:config"))
			return
		}
		if s.aggreg.OnLimit(w, r, "glovo-basket-join-total") {
			r.Header.Del(glovojoin.SubjectTokenHeader)
			s.refuse(w, route, refusal(glovo.CodeRateLimited, "rate_limited:aggregate"))
			return
		}
		sub, rf := s.verify(r)
		if rf != nil {
			s.refuse(w, route, rf)
			return
		}
		if s.perSubject.OnLimit(w, r, "s:"+sub.owner.PrincipalID) || (write && s.writes.OnLimit(w, r, "w:"+sub.owner.PrincipalID)) {
			s.refuse(w, route, refusal(glovo.CodeRateLimited, "rate_limited:subject"))
			return
		}
		if r.URL.RawQuery != "" {
			s.refuse(w, route, refusal(glovo.CodeInvalidRequest, "invalid_request:query"))
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
		if err != nil {
			s.refuse(w, route, refusal(glovo.CodeInvalidRequest, "invalid_request:body"))
			return
		}
		status, out, rf := h(r.Context(), sub, body)
		if rf != nil {
			s.refuse(w, route, rf)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// verify proves the end user: the token, the principal, the scope. Each
// failure is a refusal; a dependency that did not answer is 503.
func (s *Service) verify(r *http.Request) (subject, *glovojoin.Refusal) {
	tok, rf := glovojoin.VerifySubjectToken(r, s.Tokens, s.Now)
	if rf != nil {
		return subject{}, rf
	}
	u := tok.User
	if err := auth.AttachPrincipal(r.Context(), s.Principals, u); err != nil {
		if errors.Is(err, auth.ErrPrincipalDisabled) || errors.Is(err, auth.ErrIdentityRefused) {
			return subject{}, &glovojoin.Refusal{Err: glovo.Refuse(glovo.CodeNotAuthorized), Reason: "principal_refused", Unauthenticated: true}
		}
		// Could not observe the principal: never "no principal", never a
		// refusal that reads as a decision.
		return subject{}, refusal(glovo.CodeUnavailable, "dependency_unavailable:principal")
	}
	if u.PrincipalUnresolved() {
		return subject{}, refusal(glovo.CodeUnavailable, "dependency_unavailable:principal")
	}
	sc, ge := s.Resolver.Resolve(r.Context(), u)
	if ge != nil {
		return subject{}, &glovojoin.Refusal{Err: ge, Reason: "resolver:" + string(ge.Code)}
	}
	if sc.Personal {
		// The basket service acts for a team member; a personal scope has
		// no team, which is a refusal, not an outage.
		return subject{}, &glovojoin.Refusal{Err: scope.RequireTeam(sc), Reason: "resolver:personal_scope"}
	}
	if sc.PrincipalID == "" || sc.Tenant == "" || sc.PrincipalID != u.PrincipalID() {
		return subject{}, refusal(glovo.CodeUnavailable, "dependency_unavailable:resolver_scope")
	}
	return subject{owner: glovobasket.Owner{Tenant: sc.Tenant, PrincipalID: sc.PrincipalID}, role: sc.Role, expiresAt: tok.ExpiresAt}, nil
}

// ResolveResponse is POST /resolve: who the end user is for the basket
// service, as resolved now. It carries no grant or family id.
type ResolveResponse struct {
	PrincipalID string `json:"principal_id"`
	Tenant      string `json:"tenant"`
	Role        string `json:"role"`
	// CanDecide reports whether the end user's role lets them decide an
	// approval on the approval page. The service itself never decides.
	CanDecide bool `json:"can_decide"`
	// SubjectExpiresAt is the subject token's expiry: no answer derived from
	// it may be used past this instant.
	SubjectExpiresAt time.Time `json:"subject_expires_at"`
}

func (s *Service) resolve(_ context.Context, sub subject, body []byte) (int, any, *glovojoin.Refusal) {
	if b := bytes.TrimSpace(body); len(b) != 0 && !bytes.Equal(b, []byte("{}")) {
		return 0, nil, refusal(glovo.CodeInvalidRequest, "invalid_request:resolve_body")
	}
	return http.StatusOK, ResolveResponse{
		PrincipalID: sub.owner.PrincipalID, Tenant: sub.owner.Tenant, Role: sub.role,
		CanDecide:        operations.Role(sub.role).Satisfies(DeciderRole),
		SubjectExpiresAt: sub.expiresAt.UTC(),
	}, nil
}

// ApprovalRequestBody is POST /approvals. The basket is the revision's
// approval-basket document (mctl-approval-basket/v1): mctl-api canonicalizes
// it and computes the fingerprint itself. basket_fingerprint is optional and
// only compared: a value that differs is refused, and it is never stored.
// There is no tenant or owner field: both come from the subject token.
type ApprovalRequestBody struct {
	BasketID          string            `json:"basket_id"`
	Revision          int64             `json:"revision"`
	Basket            json.RawMessage   `json:"basket"`
	ItemNames         map[string]string `json:"item_names"`
	BasketFingerprint string            `json:"basket_fingerprint,omitempty"`
}

func (s *Service) approvals(ctx context.Context, sub subject, body []byte) (int, any, *glovojoin.Refusal) {
	var in ApprovalRequestBody
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || dec.More() || len(in.Basket) == 0 {
		return 0, nil, refusal(glovo.CodeInvalidRequest, "invalid_request:approvals_body")
	}
	snap, err := glovobasket.FreezeSnapshot(in.Basket, in.ItemNames)
	if err != nil {
		if glovobasket.IsInvalid(err) {
			return 0, nil, refusal(glovo.CodeInvalidRequest, "invalid_request:basket")
		}
		return 0, nil, refusal(glovo.CodeUnavailable, "dependency_unavailable:basket_contract")
	}
	ttl := s.ApprovalTTL
	if ttl <= 0 {
		ttl = glovobasket.DefaultApprovalTTL
	}
	ap, err := s.Approvals.RequestApprovalFromSnapshot(ctx, sub.owner, glovobasket.SnapshotApprovalInput{
		BasketID: in.BasketID, Revision: in.Revision, Snapshot: snap, BasketFingerprint: in.BasketFingerprint}, ttl)
	if err != nil {
		var ge *glovo.Error
		if errors.As(err, &ge) && glovo.Registered(ge.Code) {
			return 0, nil, &glovojoin.Refusal{Err: ge, Reason: "approvals:" + string(ge.Code)}
		}
		return 0, nil, refusal(glovo.CodeUnavailable, "dependency_unavailable:approvals")
	}
	if s.pageOrigin != "" {
		ap.ApprovalURL = s.pageOrigin + glovobasket.ApprovalPagePath + url.PathEscape(ap.ApprovalRef)
	}
	status := http.StatusOK
	if ap.Created {
		status = http.StatusCreated
	}
	return status, ap, nil
}

// String is for logs: never the token.
func (r Refused) String() string {
	return fmt.Sprintf("%s %s %d %s", r.Route, r.Code, r.Status, r.Reason)
}
