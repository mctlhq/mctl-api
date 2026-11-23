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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

const accessURL = "/api/v1/glovo/access-request"

// memAccessStore is an in-memory GlovoAccessStore with injectable errors.
type memAccessStore struct {
	mu                          sync.Mutex
	rows                        map[string]glovoconsent.Access
	getErr, stateErr, reqErr    error
	rejectErr                   error
	reqCalls, rejectCalls       int
	lastRejectActor, lastReason string
}

func newMemAccessStore() *memAccessStore {
	return &memAccessStore{rows: map[string]glovoconsent.Access{}}
}

func (m *memAccessStore) set(pid string, st glovoconsent.AccessStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	m.rows[pid] = glovoconsent.Access{PrincipalID: pid, Status: st, RequestedAt: now, ExpiresAt: now.Add(glovoconsent.AccessRequestTTL)}
}

func (m *memAccessStore) GetAccess(_ context.Context, pid string) (glovoconsent.Access, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return glovoconsent.Access{}, m.getErr
	}
	if a, ok := m.rows[pid]; ok {
		return a, nil
	}
	return glovoconsent.Access{PrincipalID: pid, Status: glovoconsent.AccessNone}, nil
}

func (m *memAccessStore) AccessState(_ context.Context, pid string) (glovoconsent.AccessStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stateErr != nil {
		return "", m.stateErr
	}
	if a, ok := m.rows[pid]; ok {
		return a.Status, nil
	}
	return glovoconsent.AccessNone, nil
}

func (m *memAccessStore) RequestAccess(_ context.Context, pid string) (glovoconsent.Access, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqCalls++
	if m.reqErr != nil {
		return glovoconsent.Access{}, false, m.reqErr
	}
	if a, ok := m.rows[pid]; ok {
		switch a.Status {
		case glovoconsent.AccessApproved:
			return glovoconsent.Access{}, false, glovoconsent.ErrAccessApproved
		case glovoconsent.AccessPending:
			return a, false, nil
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	a := glovoconsent.Access{PrincipalID: pid, Status: glovoconsent.AccessPending, RequestedAt: now, ExpiresAt: now.Add(glovoconsent.AccessRequestTTL)}
	m.rows[pid] = a
	return a, true, nil
}

func (m *memAccessStore) RejectAccess(_ context.Context, pid, actor, reason string) (glovoconsent.Access, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectCalls++
	m.lastRejectActor, m.lastReason = actor, reason
	if m.rejectErr != nil {
		return glovoconsent.Access{}, m.rejectErr
	}
	a, ok := m.rows[pid]
	if !ok || a.Status != glovoconsent.AccessPending {
		return glovoconsent.Access{}, glovoconsent.ErrAccessNotPending
	}
	a.Status, a.DecidedBy = glovoconsent.AccessRejected, actor
	m.rows[pid] = a
	return a, nil
}

func accessEnv(t *testing.T, users map[string]*auth.User) (*consentEnv, *memConsentStore, *memAccessStore) {
	t.Helper()
	cs, as := newMemConsentStore(), newMemAccessStore()
	g := mountedConsent(cs, consentCap)
	g.Access = as
	return newConsentEnv(t, g, users), cs, as
}

func decodeAccess(t *testing.T, rec *httptest.ResponseRecorder) glovoAccessView {
	t.Helper()
	var v glovoAccessView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return v
}

func accessErrCode(rec *httptest.ResponseRecorder) string {
	var b struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return b.Code
}

// Every non-human caller class is refused on all three routes and never
// reaches the store; the human control proves the routes are live.
func TestGlovoAccessOnlyAHumanActingDirectly(t *testing.T) {
	users := matrixPrincipals(t)
	agent := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	surface := auth.NewSurfaceUser("telegram")
	users["delegated-with-prn"] = withPrincipal(t, auth.NewDelegatedUser("alice", []string{"acme"}, agent), consentPIDA)
	users["relayed-with-prn"] = withPrincipal(t, auth.NewRelayedUser("alice", []string{"acme"}, surface), consentPIDA)
	users["federated-service-with-prn"] = withPrincipal(t, auth.NewFederatedUser("other", "https://issuer.example", "svc", "svc", auth.KindService), consentPIDA)
	users["federated-agent-with-prn"] = withPrincipal(t, auth.NewFederatedUser("other", "https://issuer.example", "agt", "agt", auth.KindAgent), consentPIDA)
	users["consent-reader"] = consentService()
	users["human-unresolved"] = &auth.User{ID: "carol"}
	users["alice"] = consentHuman(t, "alice", consentPIDA)

	e, _, as := accessEnv(t, users)
	for who := range users {
		if who == "alice" {
			continue
		}
		for _, m := range []string{"GET", "PUT", "DELETE"} {
			rec := e.call(m, accessURL, who, "")
			if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
				t.Errorf("%s %s = %d %s", who, m, rec.Code, rec.Body.String())
			}
		}
	}
	if as.reqCalls != 0 || as.rejectCalls != 0 {
		t.Fatalf("non-human calls reached the store: %d %d", as.reqCalls, as.rejectCalls)
	}
	if rec := e.call("PUT", accessURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("control: alice = %d %s", rec.Code, rec.Body.String())
	}
	// Refused writes are audited under the access operations.
	if rec := e.call("PUT", accessURL, "agent", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("agent PUT = %d", rec.Code)
	}
	seen := map[string]bool{}
	for _, en := range e.audit.List(500) {
		if en.Status == "refused" && en.RefusalCode == gcCodeHumanOnly {
			seen[en.Operation] = true
		}
	}
	if !seen["glovo.access_request.open"] || !seen["glovo.access_request.withdraw"] {
		t.Fatalf("refusals not audited: %v", seen)
	}
}

func TestGlovoAccessLifecycle(t *testing.T) {
	e, _, as := accessEnv(t, standardConsentUsers(t))
	if rec := e.call("GET", accessURL, "alice", ""); rec.Code != 200 || decodeAccess(t, rec).Status != "none" {
		t.Fatalf("initial = %d %s", rec.Code, rec.Body.String())
	}
	rec := e.call("PUT", accessURL, "alice", "")
	v := decodeAccess(t, rec)
	if rec.Code != http.StatusCreated || v.Status != "pending" || v.RequestedAt == nil || v.ExpiresAt == nil {
		t.Fatalf("open = %d %s", rec.Code, rec.Body.String())
	}
	// Idempotent while pending: 200 and the same expiry.
	rec2 := e.call("PUT", accessURL, "alice", "")
	v2 := decodeAccess(t, rec2)
	if rec2.Code != http.StatusOK || v2.Status != "pending" || !v2.ExpiresAt.Equal(*v.ExpiresAt) {
		t.Fatalf("repeat = %d %s", rec2.Code, rec2.Body.String())
	}
	if rec := e.call("GET", accessURL, "alice", ""); decodeAccess(t, rec).ExpiresAt == nil {
		t.Fatalf("GET lost the times: %s", rec.Body.String())
	}
	// Another principal sees none.
	if rec := e.call("GET", accessURL, "bob", ""); decodeAccess(t, rec).Status != "none" {
		t.Fatalf("bob sees %s", rec.Body.String())
	}
	// Withdraw: acts as the requester, then the state reads none (not
	// rejected: the person withdrew it) and a new request can open.
	if rec := e.call("DELETE", accessURL, "alice", ""); rec.Code != 200 || decodeAccess(t, rec).Status != "none" {
		t.Fatalf("withdraw = %d %s", rec.Code, rec.Body.String())
	}
	if as.lastRejectActor != consentPIDA || as.lastReason != glovoAccessWithdrawReason {
		t.Fatalf("withdraw actor/reason = %q %q", as.lastRejectActor, as.lastReason)
	}
	// Withdrawing again changes nothing and still answers the state.
	if rec := e.call("DELETE", accessURL, "alice", ""); rec.Code != 200 || decodeAccess(t, rec).Status != "none" {
		t.Fatalf("second withdraw = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call("PUT", accessURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("reopen = %d", rec.Code)
	}
	var ops = map[string]string{}
	for _, en := range e.audit.List(100) {
		ops[en.Operation] += en.Status + ","
	}
	if ops["glovo.access_request.open"] == "" || ops["glovo.access_request.withdraw"] == "" {
		t.Fatalf("audit ops = %v", ops)
	}
}

func TestGlovoAccessApprovedIs409(t *testing.T) {
	e, _, as := accessEnv(t, standardConsentUsers(t))
	as.set(consentPIDA, glovoconsent.AccessApproved)
	rec := e.call("PUT", accessURL, "alice", "")
	if rec.Code != http.StatusConflict || accessErrCode(rec) != gcCodeAccessApproved {
		t.Fatalf("approved PUT = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call("GET", accessURL, "alice", ""); decodeAccess(t, rec).Status != "approved" {
		t.Fatalf("approved GET = %s", rec.Body.String())
	}
	// Withdrawing approved access is a no-op that reports approved.
	if rec := e.call("DELETE", accessURL, "alice", ""); rec.Code != 200 || decodeAccess(t, rec).Status != "approved" {
		t.Fatalf("approved DELETE = %d %s", rec.Code, rec.Body.String())
	}
}

// A store failure is 503 on every route, never state none.
func TestGlovoAccessStoreErrorIs503(t *testing.T) {
	boom := errors.New("db down")
	for name, tc := range map[string]struct {
		method string
		set    func(*memAccessStore)
	}{
		"get":         {"GET", func(m *memAccessStore) { m.getErr = boom }},
		"put":         {"PUT", func(m *memAccessStore) { m.reqErr = boom }},
		"delete":      {"DELETE", func(m *memAccessStore) { m.rejectErr = boom }},
		"delete-read": {"DELETE", func(m *memAccessStore) { m.getErr = boom }},
	} {
		e, _, as := accessEnv(t, standardConsentUsers(t))
		tc.set(as)
		rec := e.call(tc.method, accessURL, "alice", "")
		if rec.Code != http.StatusServiceUnavailable || accessErrCode(rec) != gcCodeUnavailable {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
		if got := decodeAccess(t, rec).Status; got != "" {
			t.Errorf("%s leaked status %q", name, got)
		}
	}
	// A store that answers about another principal is unreadable too.
	e, _, as := accessEnv(t, standardConsentUsers(t))
	as.set(consentPIDB, glovoconsent.AccessApproved)
	as.rows[consentPIDA] = as.rows[consentPIDB]
	if rec := e.call("GET", accessURL, "alice", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("foreign row = %d %s", rec.Code, rec.Body.String())
	}
}

func TestGlovoAccessRoutesAbsentWithoutAccessStore(t *testing.T) {
	cs := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(cs, consentCap), standardConsentUsers(t))
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if rec := e.call(m, accessURL, "alice", ""); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 404", m, rec.Code)
		}
	}
	// The service read keeps its old shape: no access field.
	rec := e.call("GET", consentReadURL(consentPIDA), "svc", "")
	if rec.Code != 200 || readState(t, rec).Access != "" {
		t.Fatalf("unwired read = %d %s", rec.Code, rec.Body.String())
	}
}

func TestGlovoAccessServiceReadField(t *testing.T) {
	for _, st := range []glovoconsent.AccessStatus{glovoconsent.AccessNone, glovoconsent.AccessPending,
		glovoconsent.AccessApproved, glovoconsent.AccessRejected, glovoconsent.AccessRevoked} {
		e, cs, as := accessEnv(t, standardConsentUsers(t))
		as.set(consentPIDA, st)
		// consent none
		rec := e.call("GET", consentReadURL(consentPIDA), "svc", "")
		got := readState(t, rec)
		if rec.Code != 200 || got.Access != string(st) || got.State != gcStateNone {
			t.Errorf("%s/no consent = %d %s", st, rec.Code, rec.Body.String())
		}
		// consent active: state and fields unchanged, access added
		cs.active[consentPIDA] = glovoconsent.Record{ID: "gcn_a", PrincipalID: consentPIDA, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
		rec = e.call("GET", consentReadURL(consentPIDA), "svc", "")
		got = readState(t, rec)
		if rec.Code != 200 || got.Access != string(st) || got.State != gcStateActive || got.ConsentVersion != glovoconsent.Version || got.RecordedAt == nil {
			t.Errorf("%s/active = %d %s", st, rec.Code, rec.Body.String())
		}
	}
}

// Only the access read fails while the consent read succeeds: the whole
// response is 503, with no state and no access field.
func TestGlovoAccessServiceReadErrorIs503(t *testing.T) {
	for name, active := range map[string]bool{"consent none": false, "consent active": true} {
		e, cs, as := accessEnv(t, standardConsentUsers(t))
		if active {
			cs.active[consentPIDA] = glovoconsent.Record{ID: "gcn_a", PrincipalID: consentPIDA, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
		}
		as.stateErr = errors.New("db down")
		rec := e.call("GET", consentReadURL(consentPIDA), "svc", "")
		if rec.Code != http.StatusServiceUnavailable || accessErrCode(rec) != gcCodeUnavailable {
			t.Fatalf("%s: = %d %s", name, rec.Code, rec.Body.String())
		}
		if got := readState(t, rec); got.State != "" || got.Access != "" {
			t.Fatalf("%s: partial body %s", name, rec.Body.String())
		}
	}
	// An unknown status from the store is unreadable, not none.
	e, _, as := accessEnv(t, standardConsentUsers(t))
	as.rows[consentPIDA] = glovoconsent.Access{PrincipalID: consentPIDA, Status: "bogus"}
	if rec := e.call("GET", consentReadURL(consentPIDA), "svc", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("bogus status = %d %s", rec.Code, rec.Body.String())
	}
}

// Only the consent reader reaches the field: every other caller is refused
// on the read route as before.
func TestGlovoAccessServiceReadStaysServiceOnly(t *testing.T) {
	e, _, _ := accessEnv(t, standardConsentUsers(t))
	for _, who := range []string{"alice", "bob"} {
		if rec := e.call("GET", consentReadURL(consentPIDA), who, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s read = %d", who, rec.Code)
		}
	}
}

// A withdrawal is stored as a rejection decided by the requester. It reads as
// none on the person's own GET and on the service read; an owner's rejection
// stays rejected on both. The audit entries of the access routes carry the
// principal and nothing about a consent version.
func TestGlovoAccessWithdrawnReadsNoneOwnerRejectionStays(t *testing.T) {
	e, _, as := accessEnv(t, standardConsentUsers(t))
	as.set(consentPIDA, glovoconsent.AccessRejected)
	as.mu.Lock()
	row := as.rows[consentPIDA]
	row.DecidedBy = consentPIDA
	as.rows[consentPIDA] = row
	as.mu.Unlock()
	if rec := e.call("GET", accessURL, "alice", ""); decodeAccess(t, rec).Status != "none" {
		t.Fatalf("own GET after withdrawal = %s", rec.Body.String())
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDA), "svc", "")); got.Access != "none" {
		t.Fatalf("service read after withdrawal = %q, want none", got.Access)
	}
	as.mu.Lock()
	row.DecidedBy = "owner"
	as.rows[consentPIDA] = row
	as.mu.Unlock()
	if rec := e.call("GET", accessURL, "alice", ""); decodeAccess(t, rec).Status != "rejected" {
		t.Fatalf("own GET after an owner rejection = %s", rec.Body.String())
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDA), "svc", "")); got.Access != "rejected" {
		t.Fatalf("service read after an owner rejection = %q, want rejected", got.Access)
	}
	// A failed full read behind a rejected state is a 503, not a guess.
	as.mu.Lock()
	as.getErr = errors.New("boom")
	as.mu.Unlock()
	if rec := e.call("GET", consentReadURL(consentPIDA), "svc", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("service read with a failed row read = %d, want 503", rec.Code)
	}
	as.mu.Lock()
	as.getErr = nil
	as.mu.Unlock()
	e.call("PUT", accessURL, "alice", "")
	for _, en := range e.audit.List(100) {
		if strings.HasPrefix(en.Operation, "glovo.access_request.") {
			if _, has := en.Parameters["consent_version"]; has || en.Parameters["principal"] == "" {
				t.Fatalf("%s params = %v, want principal only", en.Operation, en.Parameters)
			}
		}
	}
}
