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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/delegation"
)

// fakeDelegation is a canned delegation.Resolver: it records every bound
// argument it was called with and answers whatever fn returns.
type fakeDelegation struct {
	fn   func(ref string, bound auth.AgentRun) (delegation.Grant, error)
	seen []auth.AgentRun
}

func (f *fakeDelegation) Resolve(_ context.Context, ref string, bound auth.AgentRun) (delegation.Grant, error) {
	f.seen = append(f.seen, bound)
	return f.fn(ref, bound)
}

type nextCapture struct {
	called bool
	user   *auth.User
}

func (c *nextCapture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.called = true
		c.user = auth.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func delegatedReq(method, path string, u *auth.User, ref string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	if u != nil {
		req = asUser(req, u)
	}
	if ref != "" {
		req.Header.Set(OnBehalfOfHeader, ref)
	}
	return req
}

func runGate(h *Handlers, req *http.Request) (*httptest.ResponseRecorder, *nextCapture) {
	next := &nextCapture{}
	rec := httptest.NewRecorder()
	h.agentPrincipalGate(next.handler()).ServeHTTP(rec, req)
	return rec, next
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	return body
}

const allowlistedRoute = "/api/v1/work-items/wi_1"

var alwaysGrant = func(ref string, bound auth.AgentRun) (delegation.Grant, error) {
	return delegation.Grant{Ref: ref, Kind: delegation.KindExecutionRequest, Subject: "github:alice", SubjectPrincipalID: "prn_ALICE"}, nil
}

// T10 (part 1): no context user, or an agent with no header, pass through
// unchanged.
func TestAgentPrincipalGate_PassesThroughWithNoUserOrNoHeader(t *testing.T) {
	h := &Handlers{opts: Options{Delegation: &fakeDelegation{fn: alwaysGrant}, AuditLog: audit.NewLogger()}}

	rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, nil, ""))
	if !next.called || rec.Code != http.StatusOK {
		t.Fatalf("no user: called=%v code=%d", next.called, rec.Code)
	}

	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	rec, next = runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, ""))
	if !next.called || rec.Code != http.StatusOK || next.user != agent {
		t.Fatalf("agent with no header: called=%v code=%d user=%v, want unchanged", next.called, rec.Code, next.user)
	}
}

// T7: X-MCTL-On-Behalf-Of sent by anyone that is not an agent principal is
// 400 delegation_not_accepted, whoever they are -- a human, a surface
// principal, a relayed subject, the service principal, the usage writer and
// the evidence writer. This gate runs ahead of every rate limiter
// (router.go), so none of these refusals write an
// agent_identity.delegation_refused audit row: that write must not be
// reachable, unthrottled, by every authenticated caller on every request --
// mirrors surfacePrincipalGate's !isSurface branch
// (handlers_surface_identity.go), which refuses the same way with no audit.
func TestAgentPrincipalGate_NonAgentWithHeaderIsRefused(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{Delegation: &fakeDelegation{fn: alwaysGrant}, AuditLog: log}}

	telegram := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"human":              auth.NewGitHubUser("alice", nil),
		"surface principal":  telegram,
		"relayed subject":    auth.NewRelayedUser("alice", nil, telegram),
		"service principal":  auth.NewServiceUser(),
		"usage writer":       auth.NewUsageWriterUser(),
		"evidence writer":    auth.NewEvidenceWriterUser(),
		"registry publisher": auth.NewRegistryPublisherUser(),
	} {
		t.Run(name, func(t *testing.T) {
			rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, u, "xr_1"))
			if next.called {
				t.Fatalf("%s: next must not run", name)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: code = %d, want 400", name, rec.Code)
			}
			if body := decodeBody(t, rec); body["code"] != delegationCodeNotAccepted {
				t.Fatalf("%s: code = %v, want %s", name, body["code"], delegationCodeNotAccepted)
			}
		})
	}
	var refusals int
	for _, e := range log.List(100) {
		if e.Operation == "agent_identity.delegation_refused" {
			refusals++
		}
	}
	if refusals != 0 {
		t.Fatalf("delegation_refused audit rows = %d, want 0 (non-agent refusal must not audit)", refusals)
	}
}

// T7 (route half): an agent principal sending the header on a route outside
// delegationRoutes is 400 delegation_not_supported.
func TestAgentPrincipalGate_NonAllowlistedRouteIsRefused(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{Delegation: &fakeDelegation{fn: alwaysGrant}, AuditLog: log}}
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})

	for _, route := range [][2]string{
		{http.MethodPost, "/api/v1/work-items"},
		{http.MethodPost, "/api/v1/agent-run-tokens"},
		{http.MethodPost, "/api/v1/agents/dev-loop/x/approve"},
		{http.MethodPost, "/api/v1/operations/deploy-service/execute"},
		{http.MethodPost, "/api/v1/surface-identities/redeem"},
	} {
		rec, next := runGate(h, delegatedReq(route[0], route[1], agent, "xr_1"))
		if next.called {
			t.Fatalf("%s %s: next must not run", route[0], route[1])
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: code = %d, want 400", route[0], route[1], rec.Code)
		}
		if body := decodeBody(t, rec); body["code"] != delegationCodeNotSupported {
			t.Fatalf("%s %s: code = %v, want %s", route[0], route[1], body["code"], delegationCodeNotSupported)
		}
	}
	for _, e := range log.List(100) {
		if e.Operation == "agent_identity.delegation_refused" && e.Parameters["reason"] != delegationCodeNotSupported {
			t.Errorf("unexpected reason %q", e.Parameters["reason"])
		}
	}
}

// T10 (part 2): a nil resolver makes a delegated request 503 and an
// undelegated one succeed unchanged.
func TestAgentPrincipalGate_NilResolverIsUnavailableOnlyWhenDelegating(t *testing.T) {
	h := &Handlers{opts: Options{AuditLog: audit.NewLogger()}}
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})

	rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
	if next.called || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil resolver with header: called=%v code=%d", next.called, rec.Code)
	}
	if body := decodeBody(t, rec); body["code"] != delegationCodeUnavailable {
		t.Fatalf("code = %v, want %s", body["code"], delegationCodeUnavailable)
	}

	rec, next = runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, ""))
	if !next.called || rec.Code != http.StatusOK || next.user != agent {
		t.Fatalf("nil resolver without header: called=%v code=%d user=%v", next.called, rec.Code, next.user)
	}
}

// grant_not_bound and grant_subject_unresolved map to 403.
func TestAgentPrincipalGate_ResolveErrorsMapToTypedRefusals(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	for name, tc := range map[string]struct {
		err      error
		wantCode int
		wantBody string
	}{
		"not bound":          {delegation.ErrNotBound, http.StatusForbidden, delegationCodeNotBound},
		"subject unresolved": {delegation.ErrSubjectUnresolved, http.StatusForbidden, delegationCodeUnresolved},
		"unavailable":        {delegation.ErrUnavailable, http.StatusServiceUnavailable, delegationCodeUnavailable},
		"unexpected error":   {errors.New("boom"), http.StatusServiceUnavailable, delegationCodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handlers{opts: Options{
				AuditLog:   audit.NewLogger(),
				Delegation: &fakeDelegation{fn: func(string, auth.AgentRun) (delegation.Grant, error) { return delegation.Grant{}, tc.err }},
			}}
			rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
			if next.called {
				t.Fatalf("%s: next must not run", name)
			}
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: code = %d, want %d", name, rec.Code, tc.wantCode)
			}
			if body := decodeBody(t, rec); body["code"] != tc.wantBody {
				t.Fatalf("%s: code = %v, want %s", name, body["code"], tc.wantBody)
			}
		})
	}
}

// A grant must name a human: a subject outside the github:/oidc: namespaces
// principalOf writes, or with an empty name, is grant_subject_unresolved
// before any principal is consulted (mctl-api#571 R9).
func TestAgentPrincipalGate_NonHumanSubjectIsUnresolved(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	for _, subj := range []string{"dex:alice", "service:mctl-agent", "agent:implementer", "github:", "oidc:", "alice", ""} {
		pr := &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE"}}
		h := &Handlers{opts: Options{
			AuditLog:   audit.NewLogger(),
			Principals: pr,
			Delegation: &fakeDelegation{fn: func(string, auth.AgentRun) (delegation.Grant, error) {
				return delegation.Grant{Kind: delegation.KindActionApproval, Subject: subj, SubjectPrincipalID: "prn_ALICE"}, nil
			}},
		}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "aar_1"))
		if next.called || rec.Code != http.StatusForbidden {
			t.Fatalf("subject %q: called=%v code=%d", subj, next.called, rec.Code)
		}
		if body := decodeBody(t, rec); body["code"] != delegationCodeUnresolved {
			t.Fatalf("subject %q: code = %v, want %s", subj, body["code"], delegationCodeUnresolved)
		}
		if len(pr.checked) != 0 || len(pr.seen) != 0 {
			t.Fatalf("subject %q: the principal store was consulted (%v, %v)", subj, pr.checked, pr.seen)
		}
	}
}

// A6 at the gate: a human with no GitHub identity (a ZITADEL sign-in,
// recorded as oidc:<name>) delegates through the grant's stored principal.
// The principal is checked, never resolved from the name, and the subject's
// principalOf reproduces the grant's subject string.
func TestAgentPrincipalGate_NonGitHubHumanDelegatesByPrincipal(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	pr := &relayPrincipals{byLogin: map[string]string{"zed@example.com": "prn_ZED"}}
	tenants := &countingTenants{}
	h := &Handlers{opts: Options{
		AuditLog:       audit.NewLogger(),
		TenantResolver: tenants,
		Principals:     pr,
		Delegation: &fakeDelegation{fn: func(ref string, _ auth.AgentRun) (delegation.Grant, error) {
			return delegation.Grant{Ref: ref, Kind: delegation.KindActionApproval, Subject: "oidc:zed@example.com", SubjectPrincipalID: "prn_ZED"}, nil
		}},
	}}
	rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "aar_1"))
	if !next.called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d %s", next.called, rec.Code, rec.Body.String())
	}
	u := next.user
	if u.PrincipalID() != "prn_ZED" || u.IsAdmin() || u.IsAgent() {
		t.Fatalf("subject = principal %q admin=%v agent=%v", u.PrincipalID(), u.IsAdmin(), u.IsAgent())
	}
	if _, gh := u.GitHubLogin(); gh {
		t.Fatal("a non-GitHub subject must not carry a GitHub login")
	}
	if got := principalOf(u); got != "oidc:zed@example.com" {
		t.Fatalf("principalOf = %q, want the grant's subject", got)
	}
	if id, _ := u.Identity(); id.Kind != auth.KindHuman {
		t.Fatalf("Identity().Kind = %q, want human", id.Kind)
	}
	if len(pr.checked) != 1 || pr.checked[0] != "prn_ZED" || len(pr.seen) != 0 {
		t.Fatalf("checked=%v seen=%v, want only a check of prn_ZED", pr.checked, pr.seen)
	}
	// Outside principal mode only a GitHub login has tenants to look up.
	if tenants.calls != 0 || len(u.Groups) != 0 {
		t.Fatalf("tenant lookups = %d, groups = %v, want none", tenants.calls, u.Groups)
	}
}

// An xr_/aar_/wi_ grant with no stored principal is refused at the gate too,
// whatever its subject string: the name is never a fallback.
func TestAgentPrincipalGate_EmptyStoredPrincipalIsUnresolved(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	for _, kind := range []string{delegation.KindExecutionRequest, delegation.KindActionApproval, delegation.KindWorkItem} {
		pr := &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE"}}
		h := &Handlers{opts: Options{
			AuditLog:   audit.NewLogger(),
			Principals: pr,
			Delegation: &fakeDelegation{fn: func(string, auth.AgentRun) (delegation.Grant, error) {
				return delegation.Grant{Kind: kind, Subject: "github:alice"}, nil
			}},
		}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
		if next.called || rec.Code != http.StatusForbidden {
			t.Fatalf("%s: called=%v code=%d", kind, next.called, rec.Code)
		}
		if body := decodeBody(t, rec); body["code"] != delegationCodeUnresolved {
			t.Fatalf("%s: code = %v, want %s", kind, body["code"], delegationCodeUnresolved)
		}
		if len(pr.seen) != 0 || len(pr.checked) != 0 {
			t.Fatalf("%s: the login was resolved (%v, %v)", kind, pr.seen, pr.checked)
		}
	}
}

// A sil_ grant stores no principal and is resolved from its mirrored GitHub
// identity, so a non-GitHub surface-link subject is refused.
func TestAgentPrincipalGate_SurfaceLinkNeedsGitHubSubject(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	pr := &relayPrincipals{byLogin: map[string]string{"dave": "prn_DAVE"}}
	h := &Handlers{opts: Options{
		AuditLog:   audit.NewLogger(),
		Principals: pr,
		Delegation: &fakeDelegation{fn: func(string, auth.AgentRun) (delegation.Grant, error) {
			return delegation.Grant{Kind: delegation.KindSurfaceLink, Subject: "oidc:dave"}, nil
		}},
	}}
	rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "sil_1"))
	if next.called || rec.Code != http.StatusForbidden {
		t.Fatalf("called=%v code=%d", next.called, rec.Code)
	}
	if body := decodeBody(t, rec); body["code"] != delegationCodeUnresolved {
		t.Fatalf("code = %v, want %s", body["code"], delegationCodeUnresolved)
	}
}

// resolveOnlyPrincipals resolves identities but cannot check a stored
// principal (no PrincipalChecker).
type resolveOnlyPrincipals string

func (p resolveOnlyPrincipals) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return string(p), nil
}

// countingTenants counts tenant lookups and grants none.
type countingTenants struct{ calls int }

func (c *countingTenants) GetTenantsForUser(string) ([]string, error) {
	c.calls++
	return nil, nil
}

// T8: fail closed on AttachPrincipal -- a disabled subject is 403, a refused
// identity is 403, and any other AttachPrincipal error is 503, unlike
// relaySubject, which degrades.
func TestAgentPrincipalGate_FailsClosedOnAttachPrincipalError(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	for name, tc := range map[string]struct {
		err      error
		wantCode int
		wantBody string
	}{
		"disabled":          {auth.ErrPrincipalDisabled, http.StatusForbidden, delegationCodeUnresolved},
		"identity refused":  {auth.ErrIdentityRefused, http.StatusForbidden, delegationCodeUnresolved},
		"store unreachable": {errors.New("dial tcp: connection refused"), http.StatusServiceUnavailable, delegationCodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			pr := &relayPrincipals{err: tc.err}
			h := &Handlers{opts: Options{
				AuditLog:   audit.NewLogger(),
				Principals: pr,
				Delegation: &fakeDelegation{fn: alwaysGrant},
			}}
			rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
			if next.called {
				t.Fatalf("%s: next must not run", name)
			}
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: code = %d, want %d", name, rec.Code, tc.wantCode)
			}
			if body := decodeBody(t, rec); body["code"] != tc.wantBody {
				t.Fatalf("%s: code = %v, want %s", name, body["code"], tc.wantBody)
			}
		})
	}
}

// A successful delegation replaces the context user with the delegated
// subject: never carrying admins, IsAgent()==false, PrincipalID() equal to
// the grant's stored column, ActingPrincipal()/ViaPrincipalID() naming the
// acting agent, and the agent's execution/work-item ids preserved (so
// clientmeta.go keeps stamping via_execution_id).
func TestAgentPrincipalGate_SuccessBuildsTheDelegatedSubject(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	pr := &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE"}}
	h := &Handlers{opts: Options{
		AuditLog:       audit.NewLogger(),
		TenantResolver: sidTenants{"alice": {"acme"}},
		Principals:     pr,
		Delegation: &fakeDelegation{fn: func(ref string, bound auth.AgentRun) (delegation.Grant, error) {
			if bound.ExecutionID != "we_1" || bound.WorkItemID != "wi_1" || bound.Agent != "implementer" {
				t.Fatalf("bound = %+v", bound)
			}
			return delegation.Grant{Ref: ref, Kind: delegation.KindExecutionRequest, Subject: "github:alice", SubjectPrincipalID: "prn_ALICE"}, nil
		}},
	}}
	rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
	if !next.called || rec.Code != http.StatusOK {
		t.Fatalf("success: called=%v code=%d %s", next.called, rec.Code, rec.Body.String())
	}
	u := next.user
	if u == nil {
		t.Fatal("next ran with no context user")
	}
	if u.IsAgent() {
		t.Error("the delegated subject must not be an agent")
	}
	if u.IsAdmin() {
		t.Error("delegation must never confer admin")
	}
	if u.PrincipalID() != "prn_ALICE" {
		t.Fatalf("PrincipalID() = %q, want prn_ALICE", u.PrincipalID())
	}
	if u.ActingPrincipal() != "agent:implementer" {
		t.Fatalf("ActingPrincipal() = %q", u.ActingPrincipal())
	}
	if u.ExecutionID() != "we_1" || u.WorkItemID() != "wi_1" {
		t.Fatalf("execution/work-item ids = %q/%q, want the agent's", u.ExecutionID(), u.WorkItemID())
	}
}

// A sil_ grant carries no stored SubjectPrincipalID; the gate fills it from
// whatever AttachPrincipal resolves and refuses if that is still empty.
func TestAgentPrincipalGate_SurfaceLinkPrincipalComesFromAttachPrincipal(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	silGrant := func(string, auth.AgentRun) (delegation.Grant, error) {
		return delegation.Grant{Kind: delegation.KindSurfaceLink, Subject: "github:dave", SubjectPrincipalID: ""}, nil
	}

	t.Run("resolved", func(t *testing.T) {
		pr := &relayPrincipals{byLogin: map[string]string{"dave": "prn_DAVE"}}
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: pr, Delegation: &fakeDelegation{fn: silGrant}}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "sil_1"))
		if !next.called || rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		if next.user.PrincipalID() != "prn_DAVE" {
			t.Fatalf("PrincipalID() = %q, want prn_DAVE", next.user.PrincipalID())
		}
	})

	t.Run("unresolved", func(t *testing.T) {
		pr := &relayPrincipals{byLogin: map[string]string{}} // resolves to ""
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: pr, Delegation: &fakeDelegation{fn: silGrant}}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "sil_1"))
		if next.called || rec.Code != http.StatusForbidden {
			t.Fatalf("called=%v code=%d", next.called, rec.Code)
		}
		if body := decodeBody(t, rec); body["code"] != delegationCodeUnresolved {
			t.Fatalf("code = %v, want %s", body["code"], delegationCodeUnresolved)
		}
	})
}

// The grant's stored principal is the subject (mctl-api#571 R9): a login
// that resolves to another principal today does not override it, and a
// stored principal that no longer exists is refused rather than replaced by
// the login's.
func TestAgentPrincipalGate_StoredPrincipalIsTheSubject(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	grantFor := func(prn string) *fakeDelegation {
		return &fakeDelegation{fn: func(string, auth.AgentRun) (delegation.Grant, error) {
			return delegation.Grant{Kind: delegation.KindExecutionRequest, Subject: "github:alice", SubjectPrincipalID: prn}, nil
		}}
	}
	t.Run("relinked login", func(t *testing.T) {
		pr := &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE_NOW", "old-alice": "prn_ALICE_THEN"}}
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: pr, Delegation: grantFor("prn_ALICE_THEN")}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
		if !next.called || rec.Code != http.StatusOK {
			t.Fatalf("called=%v code=%d %s", next.called, rec.Code, rec.Body.String())
		}
		if next.user.PrincipalID() != "prn_ALICE_THEN" {
			t.Fatalf("PrincipalID() = %q, want the stored prn_ALICE_THEN", next.user.PrincipalID())
		}
		if len(pr.seen) != 0 {
			t.Fatalf("the login was resolved: %v", pr.seen)
		}
	})
	t.Run("gone", func(t *testing.T) {
		pr := &relayPrincipals{byLogin: map[string]string{"alice": "prn_ALICE_LIVE"}}
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: pr, Delegation: grantFor("prn_ALICE_STALE")}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
		if next.called || rec.Code != http.StatusForbidden {
			t.Fatalf("called=%v code=%d", next.called, rec.Code)
		}
		if body := decodeBody(t, rec); body["code"] != delegationCodeUnresolved {
			t.Fatalf("code = %v, want %s", body["code"], delegationCodeUnresolved)
		}
	})
	t.Run("no checker", func(t *testing.T) {
		h := &Handlers{opts: Options{AuditLog: audit.NewLogger(), Principals: resolveOnlyPrincipals("prn_ALICE"), Delegation: grantFor("prn_ALICE")}}
		rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
		if next.called || rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("called=%v code=%d, want 503 with no way to check the principal", next.called, rec.Code)
		}
	})
}

// A failed tenant lookup grants no tenant access, exactly as the surface
// relay degrades (relaySubject).
func TestAgentPrincipalGate_FailedTenantLookupGrantsNoAccess(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})
	pr := &relayPrincipals{byLogin: map[string]string{"carol": "prn_CAROL"}}
	h := &Handlers{opts: Options{
		AuditLog:       audit.NewLogger(),
		TenantResolver: sidTenants{"carol": {"acme"}}, // sidTenants fails carol with a partial list
		Principals:     pr,
		Delegation: &fakeDelegation{fn: func(string, auth.AgentRun) (delegation.Grant, error) {
			return delegation.Grant{Kind: delegation.KindExecutionRequest, Subject: "github:carol", SubjectPrincipalID: "prn_CAROL"}, nil
		}},
	}}
	rec, next := runGate(h, delegatedReq(http.MethodGet, allowlistedRoute, agent, "xr_1"))
	if !next.called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d %s", next.called, rec.Code, rec.Body.String())
	}
	if len(next.user.Groups) != 0 {
		t.Fatalf("Groups = %v, want none after a failed tenant lookup", next.user.Groups)
	}
}
