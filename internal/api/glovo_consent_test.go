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

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

const (
	consentSvcProvider = "glovo-consent-svc"
	consentSvcSubject  = "system:serviceaccount:glovo:mctl-glovo"
	consentPIDA        = "prn_01HZZZZZZZZZZZZZZZZZZZZZZA"
	consentPIDB        = "prn_01HZZZZZZZZZZZZZZZZZZZZZZB"
	consentHumanURL    = "/api/v1/glovo/link-consent"
	// mctlGlovoConsentVersion is mctl-glovo's linkflow.ConsentVersion, as a
	// literal: the recorded version must equal it, not merely the constant.
	mctlGlovoConsentVersion = "c2-link-v1"
)

func consentReadURL(pid string) string {
	return "/api/v1/assistants/glovo-consent/v1/principals/" + pid
}

// memConsentStore is an in-memory glovoconsent.Store with injectable errors.
type memConsentStore struct {
	mu                           sync.Mutex
	active                       map[string]glovoconsent.Record
	activeErr, recordErr, revErr error
	recordCalls                  int
	// lastCap is the capacity the handler passed on the last Record.
	lastCap int
}

func newMemConsentStore() *memConsentStore {
	return &memConsentStore{active: map[string]glovoconsent.Record{}}
}

func (m *memConsentStore) Record(_ context.Context, pid, _ string, capacity int) (glovoconsent.Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordCalls++
	m.lastCap = capacity
	if m.recordErr != nil {
		return glovoconsent.Record{}, false, m.recordErr
	}
	if r, ok := m.active[pid]; ok && r.Version == glovoconsent.Version {
		return r, false, nil
	}
	if capacity <= 0 || len(m.active) >= capacity {
		return glovoconsent.Record{}, false, glovoconsent.ErrCapacityReached
	}
	r := glovoconsent.Record{ID: "gcn_" + pid, PrincipalID: pid, Version: glovoconsent.Version, RecordedAt: time.Now().UTC()}
	m.active[pid] = r
	return r, true, nil
}

func (m *memConsentStore) Revoke(_ context.Context, pid, _ string) (glovoconsent.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revErr != nil {
		return glovoconsent.Record{}, m.revErr
	}
	r, ok := m.active[pid]
	if !ok {
		return glovoconsent.Record{}, glovoconsent.ErrNoConsent
	}
	now := time.Now().UTC()
	r.RevokedAt = &now
	delete(m.active, pid)
	return r, nil
}

func (m *memConsentStore) Active(_ context.Context, pid string) (glovoconsent.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeErr != nil {
		return glovoconsent.Record{}, m.activeErr
	}
	r, ok := m.active[pid]
	if !ok {
		return glovoconsent.Record{}, glovoconsent.ErrNoConsent
	}
	return r, nil
}

type consentEnv struct {
	t      *testing.T
	store  *memConsentStore
	audit  *audit.Logger
	router http.Handler
	users  map[string]*auth.User
}

func consentService() *auth.User {
	return auth.NewFederatedUser(consentSvcProvider, "https://issuer.example", consentSvcSubject, "mctl-glovo", auth.KindService)
}

func consentHuman(t *testing.T, subject, pid string) *auth.User {
	return withPrincipal(t, auth.NewFederatedUser("zitadel", "https://issuer.example", subject, subject, auth.KindHuman), pid)
}

func newConsentEnv(t *testing.T, g *GlovoConsentRoutes, users map[string]*auth.User) *consentEnv {
	t.Helper()
	e := &consentEnv{t: t, audit: audit.NewLogger(), users: users}
	if g != nil {
		if s, ok := g.Store.(*memConsentStore); ok {
			e.store = s
		}
	}
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	e.router = NewRouter(Options{AuthMiddleware: mw, GlovoConsent: g, AuditLog: e.audit,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })})
	return e
}

func mountedConsent(store glovoconsent.Store, capacity int) *GlovoConsentRoutes {
	return &GlovoConsentRoutes{Enabled: true, Store: store, Capacity: capacity, ServiceProvider: consentSvcProvider, ServiceSubject: consentSvcSubject}
}

func (e *consentEnv) call(method, path, who, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if who != "" {
		req.Header.Set("Authorization", "Bearer "+who)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func readState(t *testing.T, rec *httptest.ResponseRecorder) GlovoConsentReadResponse {
	t.Helper()
	var out GlovoConsentReadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("read body %q: %v", rec.Body.String(), err)
	}
	return out
}

func standardConsentUsers(t *testing.T) map[string]*auth.User {
	return map[string]*auth.User{
		"svc":   consentService(),
		"alice": consentHuman(t, "alice", consentPIDA),
		"bob":   consentHuman(t, "bob", consentPIDB),
	}
}

// consentCap is a capacity the non-capacity tests never reach.
const consentCap = 10

// Dark by default: unmounted, every consent route is 404 for everyone.
func TestGlovoConsentUnmountedIs404(t *testing.T) {
	users := standardConsentUsers(t)
	store := newMemConsentStore()
	for name, g := range map[string]*GlovoConsentRoutes{
		"nil":          nil,
		"flag off":     {Store: store, ServiceProvider: consentSvcProvider, ServiceSubject: consentSvcSubject},
		"no store":     {Enabled: true, ServiceProvider: consentSvcProvider, ServiceSubject: consentSvcSubject},
		"no subject":   {Enabled: true, Store: store, ServiceProvider: consentSvcProvider},
		"reserved svc": {Enabled: true, Store: store, ServiceProvider: "service", ServiceSubject: consentSvcSubject},
	} {
		e := newConsentEnv(t, g, users)
		for who := range users {
			for _, rt := range [][2]string{{"GET", consentHumanURL}, {"PUT", consentHumanURL}, {"DELETE", consentHumanURL}, {"GET", consentReadURL(consentPIDA)}} {
				if rec := e.call(rt[0], rt[1], who, ""); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s: %s %s %s = %d, want 404", name, who, rt[0], rt[1], rec.Code)
				}
			}
		}
		if store.recordCalls != 0 {
			t.Fatalf("%s: a record reached the store", name)
		}
	}
}

// T1: the capacity cap. A new consent claims a slot; at the cap the answer
// is the fixed 409 capacity_reached, audited, and nothing is recorded. A
// re-record by the holder takes no second slot and is not refused; a
// revoke frees the slot. A closed cap (0) admits nobody new. The handler
// passes the configured cap to the store, whose claim is atomic
// (TestPGConcurrentClaimsForTheLastSlot).
func TestGlovoConsentCapacity(t *testing.T) {
	store := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(store, 1), standardConsentUsers(t))
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("alice claims the only slot = %d %s", rec.Code, rec.Body.String())
	}
	if store.lastCap != 1 {
		t.Fatalf("handler passed cap %d, configured 1", store.lastCap)
	}
	rec := e.call("PUT", consentHumanURL, "bob", "")
	if rec.Code != http.StatusConflict || gateCode(rec) != gcCodeCapacityReached || gcCodeCapacityReached != "capacity_reached" {
		t.Fatalf("bob at the cap = %d %s", rec.Code, rec.Body.String())
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDB), "svc", "")); got.State != "none" {
		t.Fatalf("bob's consent after the capacity refusal = %+v", got)
	}
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("alice re-record at a full cap = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call("DELETE", consentHumanURL, "alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("alice revoke = %d", rec.Code)
	}
	if rec := e.call("PUT", consentHumanURL, "bob", ""); rec.Code != http.StatusCreated {
		t.Fatalf("bob after alice freed the slot = %d %s", rec.Code, rec.Body.String())
	}
	refused := false
	for _, entry := range e.audit.List(100) {
		if entry.Operation == "glovo.link_consent.record" && entry.Status == "refused" && entry.RefusalCode == gcCodeCapacityReached {
			refused = true
		}
	}
	if !refused {
		t.Fatal("no audit row for the capacity refusal")
	}

	closed := newMemConsentStore()
	ec := newConsentEnv(t, mountedConsent(closed, 0), standardConsentUsers(t))
	if rec := ec.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusConflict || gateCode(rec) != gcCodeCapacityReached {
		t.Fatalf("closed cap = %d %s", rec.Code, rec.Body.String())
	}
	if closed.lastCap != 0 {
		t.Fatalf("closed cap passed as %d", closed.lastCap)
	}

	// A store failure on record is 503, never a recorded consent.
	broken := newMemConsentStore()
	broken.recordErr = errors.New("db down")
	eb := newConsentEnv(t, mountedConsent(broken, consentCap), standardConsentUsers(t))
	if rec := eb.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusServiceUnavailable || gateCode(rec) != gcCodeUnavailable {
		t.Fatalf("record store error = %d %s", rec.Code, rec.Body.String())
	}
}

// T2: no agent, service, CI, surface, relayed or delegated identity can
// record consent, even with a resolved principal and a free slot. A
// federated human with that principal can (positive control).
func TestGlovoConsentOnlyAHumanActingDirectlyRecords(t *testing.T) {
	users := matrixPrincipals(t)
	agent := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	surface := auth.NewSurfaceUser("telegram")
	users["delegated-with-prn"] = withPrincipal(t, auth.NewDelegatedUser("alice", []string{"acme"}, agent), consentPIDA)
	users["relayed-with-prn"] = withPrincipal(t, auth.NewRelayedUser("alice", []string{"acme"}, surface), consentPIDA)
	users["federated-service-with-prn"] = withPrincipal(t, auth.NewFederatedUser("other", "https://issuer.example", "svc", "svc", auth.KindService), consentPIDA)
	users["federated-agent-with-prn"] = withPrincipal(t, auth.NewFederatedUser("other", "https://issuer.example", "agt", "agt", auth.KindAgent), consentPIDA)
	users["consent-reader"] = consentService()
	users["human-unresolved"] = &auth.User{ID: "carol"}
	for who, u := range users {
		if who == "human" || who == "admin-human" {
			continue
		}
		if u == nil {
			t.Fatalf("%s: nil principal", who)
		}
	}
	users["alice"] = consentHuman(t, "alice", consentPIDA)

	store := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(store, consentCap), users)
	for who := range users {
		if who == "alice" {
			continue
		}
		rec := e.call("PUT", consentHumanURL, who, "")
		if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
			t.Errorf("%s recorded consent: %d %s", who, rec.Code, rec.Body.String())
		}
	}
	if store.recordCalls != 0 {
		t.Fatalf("%d non-human records reached the store", store.recordCalls)
	}
	// Every refused write is audited with its refusal code.
	if rec := e.call("DELETE", consentHumanURL, "agent", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("agent revoke = %d", rec.Code)
	}
	refused := map[string]int{}
	for _, entry := range e.audit.List(500) {
		if entry.Status == "refused" && entry.RefusalCode == gcCodeHumanOnly {
			refused[entry.Operation]++
		}
	}
	if refused["glovo.link_consent.record"] == 0 || refused["glovo.link_consent.revoke"] == 0 {
		t.Fatalf("refused writes not audited: %v", refused)
	}
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("control: alice = %d %s", rec.Code, rec.Body.String())
	}
}

// The human predicate itself, for each excluded kind with a principal.
func TestGlovoConsentHumanPredicate(t *testing.T) {
	agent := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1"})
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"delegated": withPrincipal(t, auth.NewDelegatedUser("alice", nil, agent), consentPIDA),
		"relayed":   withPrincipal(t, auth.NewRelayedUser("alice", nil, surface), consentPIDA),
		"service":   withPrincipal(t, consentService(), consentPIDA),
		"agent":     withPrincipal(t, agent, consentPIDA),
		"surface":   withPrincipal(t, surface, consentPIDA),
		"admin-svc": withPrincipal(t, auth.NewServiceUser(), consentPIDA),
		"ci":        withPrincipal(t, auth.NewCIUser("mctlhq/mctl-api", "1"), consentPIDA),
	} {
		if _, ok, _ := glovoConsentHuman(u); ok {
			t.Errorf("%s accepted as a human acting directly", name)
		}
	}
	if pid, ok, _ := glovoConsentHuman(consentHuman(t, "alice", consentPIDA)); !ok || pid != consentPIDA {
		t.Fatal("control: a federated human must be accepted")
	}
	if _, ok, _ := glovoConsentHuman(withPrincipal(t, &auth.User{ID: "alice"}, consentPIDA)); ok {
		t.Fatal("a caller with no proven identity was accepted")
	}
}

// T3: the consent version comes from the server. A version, or a principal,
// in the body or the query is ignored.
func TestGlovoConsentBodyVersionIgnored(t *testing.T) {
	store := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(store, consentCap), standardConsentUsers(t))
	body := `{"consent_version":"c2-link-v999","version":"evil","principal_id":"` + consentPIDB + `"}`
	rec := e.call("PUT", consentHumanURL+"?consent_version=evil&principal_id="+consentPIDB, "alice", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record = %d %s", rec.Code, rec.Body.String())
	}
	var view glovoConsentView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || view.Consent == nil || view.Consent.Version != mctlGlovoConsentVersion {
		t.Fatalf("recorded = %+v %v", view, err)
	}
	got := readState(t, e.call("GET", consentReadURL(consentPIDA), "svc", ""))
	if got.State != "active" || got.ConsentVersion != mctlGlovoConsentVersion {
		t.Fatalf("service read = %+v", got)
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDB), "svc", "")); got.State != "none" {
		t.Fatalf("a principal named in the body got a consent: %+v", got)
	}
}

// T4: revoke means the service read returns none; a revoke is audited, and
// so is the record before it.
func TestGlovoConsentRevokeReadsNone(t *testing.T) {
	store := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(store, consentCap), standardConsentUsers(t))
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("record = %d", rec.Code)
	}
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("second record = %d, want 200 unchanged", rec.Code)
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDA), "svc", "")); got.State != "active" {
		t.Fatalf("before revoke = %+v", got)
	}
	// The human GET shows the caller's own active consent.
	var own glovoConsentView
	if rec := e.call("GET", consentHumanURL, "alice", ""); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &own) != nil ||
		own.State != "active" || own.Consent == nil || own.Consent.PrincipalID != consentPIDA || own.Consent.Version != glovoconsent.Version || own.Consent.ID == "" {
		t.Fatalf("human GET before revoke = %d %+v", rec.Code, own)
	}
	if rec := e.call("DELETE", consentHumanURL, "alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	got := readState(t, e.call("GET", consentReadURL(consentPIDA), "svc", ""))
	if got.State != "none" || got.ConsentVersion != "" {
		t.Fatalf("after revoke = %+v, want none", got)
	}
	var mine glovoConsentView
	_ = json.Unmarshal(e.call("GET", consentHumanURL, "alice", "").Body.Bytes(), &mine)
	if mine.State != "none" {
		t.Fatalf("own view after revoke = %+v", mine)
	}
	// Idempotent.
	if rec := e.call("DELETE", consentHumanURL, "alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("second revoke = %d", rec.Code)
	}
	ops := map[string]string{}
	for _, entry := range e.audit.List(100) {
		if strings.HasPrefix(entry.Operation, "glovo.link_consent.") {
			if entry.Parameters["principal"] != consentPIDA || entry.Parameters["consent_version"] != mctlGlovoConsentVersion {
				t.Fatalf("audit params = %v", entry.Parameters)
			}
			ops[entry.Operation+":"+entry.Status] = entry.Parameters["consent_id"]
		}
	}
	if ops["glovo.link_consent.record:recorded"] == "" || ops["glovo.link_consent.revoke:revoked"] == "" {
		t.Fatalf("audit = %v, want record and revoke rows with a consent id", ops)
	}
}

// T5: a store error on read is 503 on both reads, never none and never a
// consent. An inconsistent store answer is not a consent either.
func TestGlovoConsentReadErrorIsNotNone(t *testing.T) {
	store := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(store, consentCap), standardConsentUsers(t))
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("record = %d", rec.Code)
	}
	store.activeErr = errors.New("connection reset")
	for _, c := range []struct{ path, who string }{{consentReadURL(consentPIDA), "svc"}, {consentReadURL(consentPIDB), "svc"}, {consentHumanURL, "alice"}} {
		rec := e.call("GET", c.path, c.who, "")
		if rec.Code != http.StatusServiceUnavailable || gateCode(rec) != gcCodeUnavailable {
			t.Errorf("%s %s with store error = %d %s, want 503", c.who, c.path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), `"state"`) {
			t.Errorf("%s: a failed read carried a state: %s", c.path, rec.Body.String())
		}
	}
	store.activeErr = nil
	store.revErr = errors.New("connection reset")
	if rec := e.call("DELETE", consentHumanURL, "alice", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoke with store error = %d", rec.Code)
	}
	store.revErr = nil
	store.recordErr = errors.New("connection reset")
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("record with store error = %d", rec.Code)
	}
	store.recordErr = nil

	// A store row that is not an active consent of this principal is
	// unreadable for every reader: the service read, the human GET and the
	// row a record returns.
	now := time.Now().UTC()
	for name, row := range map[string]glovoconsent.Record{
		"another principal": {ID: "x", PrincipalID: consentPIDA, Version: glovoconsent.Version},
		"revoked":           {ID: "x", PrincipalID: consentPIDB, Version: glovoconsent.Version, RevokedAt: &now},
		"no version":        {ID: "x", PrincipalID: consentPIDB},
	} {
		store.active[consentPIDB] = row
		if rec := e.call("GET", consentReadURL(consentPIDB), "svc", ""); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("service read, %s row = %d %s, want 503", name, rec.Code, rec.Body.String())
		}
		if rec := e.call("GET", consentHumanURL, "bob", ""); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"x"`) {
			t.Errorf("human GET, %s row = %d %s, want 503 without the row", name, rec.Code, rec.Body.String())
		}
	}
	// Record answering with someone else's row (mem store returns the
	// stored row unchanged when its version is current).
	store.active[consentPIDB] = glovoconsent.Record{ID: "x", PrincipalID: consentPIDA, Version: glovoconsent.Version}
	if rec := e.call("PUT", consentHumanURL, "bob", ""); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"x"`) {
		t.Fatalf("record returning another principal's row = %d %s, want 503", rec.Code, rec.Body.String())
	}
}

// T6: an unauthenticated read is refused, and so is every caller other than
// the configured reader. The reader reaches nothing else.
func TestGlovoConsentReadOnlyByTheService(t *testing.T) {
	users := matrixPrincipals(t)
	users["svc"] = consentService()
	users["alice"] = consentHuman(t, "alice", consentPIDA)
	users["svc-other-subject"] = auth.NewFederatedUser(consentSvcProvider, "https://issuer.example", "other", "x", auth.KindService)
	users["svc-as-human"] = auth.NewFederatedUser(consentSvcProvider, "https://issuer.example", consentSvcSubject, "x", auth.KindHuman)
	store := newMemConsentStore()
	g := mountedConsent(store, consentCap)
	e := newConsentEnv(t, g, users)
	if rec := e.call("GET", consentReadURL(consentPIDA), "svc", ""); rec.Code != http.StatusOK {
		t.Fatalf("control: service read = %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.call("GET", consentReadURL(consentPIDA), "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credential = %d", rec.Code)
	}
	for who := range users {
		if who == "svc" {
			continue
		}
		if rec := e.call("GET", consentReadURL(consentPIDA), who, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s read = %d %s, want 401", who, rec.Code, rec.Body.String())
		}
	}
	for _, rt := range [][2]string{{"GET", consentHumanURL}, {"PUT", consentHumanURL}, {"DELETE", consentHumanURL}, {"GET", "/api/v1/whoami"}, {"POST", "/mcp"}} {
		if rec := e.call(rt[0], rt[1], "svc", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("service on %s %s = %d, want 401", rt[0], rt[1], rec.Code)
		}
	}
	// Without any authentication middleware, the gate alone refuses.
	bare := NewRouter(Options{GlovoConsent: g, mcpHandler: http.NotFoundHandler()})
	rec := httptest.NewRecorder()
	bare.ServeHTTP(rec, httptest.NewRequest("GET", consentReadURL(consentPIDA), nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no user in context = %d, want 401", rec.Code)
	}
	if rec := e.call("GET", consentReadURL("github:alice"), "svc", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed pid = %d", rec.Code)
	}
}

// T7: one principal can neither read nor record nor revoke another's
// consent through the human routes: there is no principal parameter, and
// each acts on its own.
func TestGlovoConsentPrincipalsAreIsolated(t *testing.T) {
	store := newMemConsentStore()
	e := newConsentEnv(t, mountedConsent(store, consentCap), standardConsentUsers(t))
	if rec := e.call("PUT", consentHumanURL+"?principal_id="+consentPIDB, "alice", `{"principal_id":"`+consentPIDB+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("alice record = %d", rec.Code)
	}
	var bobView glovoConsentView
	_ = json.Unmarshal(e.call("GET", consentHumanURL+"?principal_id="+consentPIDA, "bob", "").Body.Bytes(), &bobView)
	if bobView.State != "none" || bobView.Consent != nil {
		t.Fatalf("bob sees %+v", bobView)
	}
	if rec := e.call("DELETE", consentHumanURL+"?principal_id="+consentPIDA, "bob", `{"principal_id":"`+consentPIDA+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("bob revoke = %d", rec.Code)
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDA), "svc", "")); got.State != "active" {
		t.Fatalf("bob's revoke withdrew alice's consent: %+v", got)
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDB), "svc", "")); got.State != "none" {
		t.Fatalf("alice's record made a consent for bob: %+v", got)
	}
	for _, path := range []string{consentHumanURL + "/" + consentPIDA, "/api/v1/glovo/link-consent/principals/" + consentPIDA} {
		if rec := e.call("GET", path, "bob", ""); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("a principal-scoped human route exists: %s = %d", path, rec.Code)
		}
	}
}

// The service read is rate limited per principal.
func TestGlovoConsentReadRateLimited(t *testing.T) {
	g := mountedConsent(newMemConsentStore(), consentCap)
	g.ReadsPerPrincipalPerMinute = 3
	e := newConsentEnv(t, g, standardConsentUsers(t))
	for i := 0; i < 3; i++ {
		if rec := e.call("GET", consentReadURL(consentPIDA), "svc", ""); rec.Code != http.StatusOK {
			t.Fatalf("read %d = %d", i, rec.Code)
		}
	}
	if rec := e.call("GET", consentReadURL(consentPIDA), "svc", ""); rec.Code != http.StatusTooManyRequests || gateCode(rec) != gcCodeRateLimited {
		t.Fatalf("4th read = %d %s, want 429", rec.Code, rec.Body.String())
	}
	if rec := e.call("GET", consentReadURL(consentPIDB), "svc", ""); rec.Code != http.StatusOK {
		t.Fatalf("other principal = %d, want its own budget", rec.Code)
	}
}

// The read handler refuses a non-service caller on its own, without the gate
// in front of it.
func TestGlovoConsentReadHandlerRefusesWithoutGate(t *testing.T) {
	store := newMemConsentStore()
	store.active[consentPIDA] = glovoconsent.Record{ID: "gcn_a", PrincipalID: consentPIDA, Version: glovoconsent.Version, RecordedAt: time.Now()}
	h := &Handlers{opts: Options{GlovoConsent: mountedConsent(store, consentCap)}}
	for name, u := range map[string]*auth.User{"none": nil, "human": consentHuman(t, "alice", consentPIDA), "admin-service": auth.NewServiceUser()} {
		req := httptest.NewRequest("GET", consentReadURL(consentPIDA), nil)
		if u != nil {
			req = req.WithContext(auth.WithUser(req.Context(), u))
		}
		rec := httptest.NewRecorder()
		h.ReadGlovoLinkConsent(rec, req)
		if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "c2-link") {
			t.Errorf("%s = %d %s, want 401", name, rec.Code, rec.Body.String())
		}
	}
}

// fakeIdentity is a glovoconsent.IdentitySource that records the principal
// it was asked about.
type fakeIdentity struct {
	facts map[string]glovoconsent.IdentityFacts
	err   error
	asked []string
}

func (f *fakeIdentity) IdentityFacts(_ context.Context, pid string) (glovoconsent.IdentityFacts, error) {
	f.asked = append(f.asked, pid)
	if f.err != nil {
		return glovoconsent.IdentityFacts{}, f.err
	}
	return f.facts[pid], nil
}

func maskedConsentEnv(t *testing.T, id glovoconsent.IdentitySource) *consentEnv {
	t.Helper()
	store := newMemConsentStore()
	g := mountedConsent(store, consentCap)
	g.Identity = id
	e := newConsentEnv(t, g, standardConsentUsers(t))
	if rec := e.call("PUT", consentHumanURL, "alice", ""); rec.Code != http.StatusCreated {
		t.Fatalf("record = %d %s", rec.Code, rec.Body.String())
	}
	return e
}

const maskedQuery = "?include=masked_identity"

// The label is returned only when asked for, only for an active consent, and
// never carries more than the first character.
func TestGlovoConsentReadMaskedIdentity(t *testing.T) {
	const rawLogin = "alice-the-real-login"
	id := &fakeIdentity{facts: map[string]glovoconsent.IdentityFacts{
		consentPIDA: {Identities: []glovoconsent.IdentityFact{{Provider: "github", Display: rawLogin}}},
	}}
	e := maskedConsentEnv(t, id)

	rec := e.call("GET", consentReadURL(consentPIDA)+maskedQuery, "svc", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("read = %d %s", rec.Code, rec.Body.String())
	}
	if got := readState(t, rec); got.State != "active" || got.MaskedIdentity != "github:a***" {
		t.Fatalf("read = %+v, want active with label github:a***", got)
	}
	if strings.Contains(rec.Body.String(), rawLogin) || strings.Contains(rec.Body.String(), "alice-") {
		t.Fatalf("body leaks the raw login: %s", rec.Body.String())
	}

	// Without the opt-in the answer is unchanged and the source is not asked.
	id.asked = nil
	rec = e.call("GET", consentReadURL(consentPIDA), "svc", "")
	if got := readState(t, rec); got.MaskedIdentity != "" || strings.Contains(rec.Body.String(), "masked_identity") || len(id.asked) != 0 {
		t.Fatalf("plain read carried a label or asked the source: %s asked=%v", rec.Body.String(), id.asked)
	}

	// No consent: no label, and the source is not asked.
	id.asked = nil
	rec = e.call("GET", consentReadURL(consentPIDB)+maskedQuery, "svc", "")
	if got := readState(t, rec); got.State != "none" || got.MaskedIdentity != "" || len(id.asked) != 0 {
		t.Fatalf("none read = %s asked=%v", rec.Body.String(), id.asked)
	}

	// Revoked consent: no label.
	if rec := e.call("DELETE", consentHumanURL, "alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	id.asked = nil
	rec = e.call("GET", consentReadURL(consentPIDA)+maskedQuery, "svc", "")
	if got := readState(t, rec); got.State != "none" || got.MaskedIdentity != "" || len(id.asked) != 0 {
		t.Fatalf("revoked read = %s asked=%v", rec.Body.String(), id.asked)
	}
}

// A label that cannot be built is a 503 for that request, never an omitted
// field on a 200 and never a raw value.
func TestGlovoConsentMaskedIdentityUnavailableIs503(t *testing.T) {
	for name, id := range map[string]glovoconsent.IdentitySource{
		"source error":     &fakeIdentity{err: errors.New("principal store down")},
		"nothing readable": &fakeIdentity{facts: map[string]glovoconsent.IdentityFacts{}},
		"no source":        nil,
	} {
		e := maskedConsentEnv(t, id)
		rec := e.call("GET", consentReadURL(consentPIDA)+maskedQuery, "svc", "")
		if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "masked_identity") || strings.Contains(rec.Body.String(), "principal store down") {
			t.Errorf("%s: %d %s, want a bare 503", name, rec.Code, rec.Body.String())
		}
		// The ordinary read is unaffected.
		if rec := e.call("GET", consentReadURL(consentPIDA), "svc", ""); rec.Code != http.StatusOK {
			t.Errorf("%s: plain read = %d", name, rec.Code)
		}
	}
}

// The label is built for the principal in the path only, and the human
// routes never carry it.
func TestGlovoConsentMaskedIdentityIsPerPrincipalAndServiceOnly(t *testing.T) {
	id := &fakeIdentity{facts: map[string]glovoconsent.IdentityFacts{
		consentPIDA: {Identities: []glovoconsent.IdentityFact{{Provider: "github", Display: "alice"}}},
		consentPIDB: {Identities: []glovoconsent.IdentityFact{{Provider: "github", Display: "bob"}}},
	}}
	e := maskedConsentEnv(t, id)
	if rec := e.call("PUT", consentHumanURL, "bob", ""); rec.Code != http.StatusCreated {
		t.Fatalf("bob record = %d", rec.Code)
	}
	if got := readState(t, e.call("GET", consentReadURL(consentPIDB)+maskedQuery, "svc", "")); got.MaskedIdentity != "github:b***" {
		t.Fatalf("bob label = %q", got.MaskedIdentity)
	}
	if rec := e.call("GET", consentHumanURL+maskedQuery, "alice", ""); strings.Contains(rec.Body.String(), "masked_identity") {
		t.Fatalf("the human route carries a label: %s", rec.Body.String())
	}
	if rec := e.call("GET", consentReadURL(consentPIDA)+maskedQuery, "alice", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a human read of the service route = %d, want 401", rec.Code)
	}
}
