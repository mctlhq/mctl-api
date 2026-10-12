package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/principals"
)

const (
	planPrnBoss  = "prn_01JAAAAAAAAAAAAAAAAAAAAAAA"
	planPrnDev   = "prn_01JBBBBBBBBBBBBBBBBBBBBBBB"
	planPrnZed   = "prn_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	planPrnGone  = "prn_01JGGGGGGGGGGGGGGGGGGGGGGG"
	planPrnSleep = "prn_01JSSSSSSSSSSSSSSSSSSSSSSS"
)

// planStore is the principal store as the plan sees it: github id ->
// principal, principal id -> status.
type planStore struct {
	byGitHubID map[string]string // numeric id -> principal id
	revoked    map[string]bool   // numeric id -> revoked
	status     map[string]string // principal id -> status
	lookupErr  error
}

func (s *planStore) LookupIdentity(_ context.Context, provider, issuer, subject string) (*principals.Principal, bool, error) {
	if provider != auth.ProviderGitHub || issuer != "" {
		return nil, false, fmt.Errorf("unexpected identity %s|%s", provider, issuer)
	}
	if s.lookupErr != nil {
		return nil, false, s.lookupErr
	}
	id, ok := s.byGitHubID[subject]
	if !ok {
		return nil, false, principals.ErrNotFound
	}
	return &principals.Principal{ID: id, Status: s.status[id]}, s.revoked[subject], nil
}

func (s *planStore) Get(_ context.Context, id string) (*principals.Principal, error) {
	st, ok := s.status[id]
	if !ok {
		return nil, principals.ErrNotFound
	}
	return &principals.Principal{ID: id, Status: st}, nil
}

type planEntries struct {
	all gitops.MemberEntries
	err error
}

func (p planEntries) AllMemberEntries() (gitops.MemberEntries, error) { return p.all, p.err }

// planGitHub answers login -> numeric id; a login it does not know fails
// the way GitHub's 404 does.
func planGitHub(ids map[string]int64, calls map[string]int) principals.GitHubIDLookup {
	return func(_ context.Context, login string) (int64, error) {
		calls[login]++
		if id, ok := ids[login]; ok {
			return id, nil
		}
		return 0, errors.New("github user lookup: HTTP 404")
	}
}

func TestMemberKeyPlan(t *testing.T) {
	store := &planStore{
		byGitHubID: map[string]string{"1": planPrnBoss, "2": planPrnDev, "3": planPrnSleep, "4": planPrnBoss},
		revoked:    map[string]bool{"5": true},
		status:     map[string]string{planPrnBoss: principals.StatusActive, planPrnDev: principals.StatusActive, planPrnZed: principals.StatusActive, planPrnSleep: principals.StatusDisabled},
	}
	store.byGitHubID["5"] = planPrnDev
	calls := map[string]int{}
	o := &MemberKeyPlanOptions{
		Store:    store,
		GitHubID: planGitHub(map[string]int64{"boss": 1, "dev": 2, "sleepy": 3, "impostor": 4, "revoked": 5, "stranger": 6}, calls),
	}
	e := func(user, prn string) gitops.MemberEntry {
		return gitops.MemberEntry{Tenant: "acme", UserID: user, PrincipalID: prn}
	}
	all := gitops.MemberEntries{Entries: []gitops.MemberEntry{
		e("boss", ""),             // propose boss
		e("boss", ""),             // same login again: one GitHub call
		e("dev", planPrnDev),      // already keyed, consistent
		e("", planPrnZed),         // principal-only, active
		e("ghost", ""),            // GitHub does not know the login
		e("stranger", ""),         // GitHub knows it, no identity linked
		e("revoked", ""),          // identity revoked
		e("sleepy", ""),           // principal disabled
		e("impostor", planPrnDev), // the login is someone else's principal
		e("", planPrnGone),        // principal does not exist
		e("dev", "prn_bad"),       // malformed key
		e("ghost", planPrnDev),    // key stands, login cannot be checked
	}}
	plan := buildMemberKeyPlan(context.Background(), o, all)

	want := []struct{ status, proposed, reason string }{
		{planPropose, planPrnBoss, ""},
		{planPropose, planPrnBoss, ""},
		{planKeyed, "", ""},
		{planKeyed, "", ""},
		{planUnresolved, "", "github_lookup_failed"},
		{planUnresolved, "", "no_linked_identity"},
		{planUnresolved, "", "identity_revoked"},
		{planUnresolved, "", "principal_disabled"},
		{planMismatch, "", "login_names_another_principal"},
		{planUnresolved, "", "principal_not_found"},
		{planInvalid, "", "malformed_principal_id"},
		{planUnverified, "", "login_unverified"},
	}
	for i, w := range want {
		got := plan.Entries[i]
		if got.Status != w.status || got.ProposedPrincipalID != w.proposed || got.Reason != w.reason {
			t.Errorf("entry %d (%s/%s) = %s %q %q, want %s %q %q", i, got.UserID, got.PrincipalID,
				got.Status, got.ProposedPrincipalID, got.Reason, w.status, w.proposed, w.reason)
		}
	}
	if plan.Complete || plan.Blockers != 8 {
		t.Errorf("complete=%v blockers=%d, want incomplete with 8", plan.Complete, plan.Blockers)
	}
	if calls["boss"] != 1 {
		t.Errorf("boss looked up %d times, want once per plan", calls["boss"])
	}
	if plan.Entries[0].GitHubID != 1 {
		t.Errorf("github id not reported: %+v", plan.Entries[0])
	}
}

func TestMemberKeyPlan_CompleteOnlyWithNothingBlocking(t *testing.T) {
	store := &planStore{byGitHubID: map[string]string{"1": planPrnBoss}, status: map[string]string{planPrnBoss: principals.StatusActive}}
	o := &MemberKeyPlanOptions{Store: store, GitHubID: planGitHub(map[string]int64{"boss": 1}, map[string]int{})}
	clean := []gitops.MemberEntry{{Tenant: "acme", UserID: "boss"}}

	if p := buildMemberKeyPlan(context.Background(), o, gitops.MemberEntries{Entries: clean}); !p.Complete || p.Blockers != 0 {
		t.Fatalf("clean plan: complete=%v blockers=%d", p.Complete, p.Blockers)
	}
	// A tenant the checkout could not read may hold unkeyed entries.
	if p := buildMemberKeyPlan(context.Background(), o, gitops.MemberEntries{Entries: clean, Unreadable: []string{"broken"}}); p.Complete {
		t.Fatal("a plan with an unreadable tenant is complete")
	}
	if p := buildMemberKeyPlan(context.Background(), o, gitops.MemberEntries{Entries: clean, KeyErrors: map[string]string{"acme": "duplicate"}}); p.Complete {
		t.Fatal("a plan with a tenant key error is complete")
	}
	// A store that cannot answer is a blocker, never a proposal or a skip.
	store.lookupErr = errors.New("connection refused")
	p := buildMemberKeyPlan(context.Background(), o, gitops.MemberEntries{Entries: clean})
	if p.Complete || p.Entries[0].Status != planUnresolved || p.Entries[0].Reason != "store_error" {
		t.Fatalf("store error: %+v", p)
	}
}

func TestTenantMemberPrincipalPlanEndpoint(t *testing.T) {
	admin := auth.NewGitHubUser("root", []string{"admins"})
	member := auth.NewGitHubUser("dev", []string{"acme"})
	store := &planStore{byGitHubID: map[string]string{"1": planPrnBoss}, status: map[string]string{planPrnBoss: principals.StatusActive}}
	ok := &MemberKeyPlanOptions{
		Entries:  planEntries{all: gitops.MemberEntries{Entries: []gitops.MemberEntry{{Tenant: "acme", UserID: "boss"}}}},
		Store:    store,
		GitHubID: planGitHub(map[string]int64{"boss": 1}, map[string]int{}),
	}
	stale := *ok
	stale.Entries = planEntries{err: errors.New("checkout never synced")}
	tests := []struct {
		name string
		user *auth.User
		opts *MemberKeyPlanOptions
		want int
	}{
		{"admin", admin, ok, http.StatusOK},
		{"non-admin", member, ok, http.StatusForbidden},
		{"relayed admin", auth.NewRelayedUser("root", []string{"admins"}, auth.NewSurfaceUser("telegram")), ok, http.StatusForbidden},
		{"not configured", admin, nil, http.StatusServiceUnavailable},
		{"checkout unreadable", admin, &stale, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewRouter(Options{AuthMiddleware: injectUser(tt.user), MemberKeyPlan: tt.opts})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenant-members/principal-plan", nil))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			if tt.want != http.StatusOK {
				return
			}
			var plan memberKeyPlan
			if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
				t.Fatal(err)
			}
			if !plan.Complete || len(plan.Entries) != 1 || plan.Entries[0].ProposedPrincipalID != planPrnBoss {
				t.Fatalf("plan = %+v", plan)
			}
		})
	}
}

// Review P3s on #590: one fix is one blocker, and a login is looked up
// once however it is spelled.
func TestMemberKeyPlan_CountsEachProblemOnce(t *testing.T) {
	store := &planStore{byGitHubID: map[string]string{"1": planPrnBoss}, status: map[string]string{planPrnBoss: principals.StatusActive}}
	calls := map[string]int{}
	o := &MemberKeyPlanOptions{Store: store, GitHubID: planGitHub(map[string]int64{"boss": 1, "Boss": 1, "BOSS": 1}, calls)}
	all := gitops.MemberEntries{
		Entries: []gitops.MemberEntry{
			{Tenant: "acme", UserID: "boss"}, {Tenant: "acme", UserID: "Boss"}, {Tenant: "acme", UserID: "BOSS"},
			{Tenant: "nobody", Index: 0}, // names nobody: one entry blocker, and its tenant's key error
			{Tenant: "dup", UserID: "boss", PrincipalID: planPrnBoss},
			{Tenant: "dup", UserID: "ghost", PrincipalID: planPrnBoss}, // unverified: a separate fix
		},
		KeyErrors: map[string]string{"nobody": "member 0 names neither", "dup": "lists a principalId twice"},
	}
	plan := buildMemberKeyPlan(context.Background(), o, all)
	if plan.Blockers != 3 { // nobody's entry, dup's unverified entry, dup's key error
		t.Errorf("blockers = %d, want 3", plan.Blockers)
	}
	if n := calls["boss"] + calls["Boss"] + calls["BOSS"]; n != 1 {
		t.Errorf("%d GitHub lookups for one login in three spellings, want 1", n)
	}
}
