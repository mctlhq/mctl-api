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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

type sidEnv struct {
	t      *testing.T
	router http.Handler
	audit  *audit.Logger
	pool   *pgxpool.Pool
	users  map[string]*auth.User
	tenant string
}

// sidTenants is the TenantResolver the relay reads the subject's groups
// from.
type sidTenants map[string][]string

func (s sidTenants) GetTenantsForUser(login string) ([]string, error) {
	if login == "carol" {
		// A resolver that fails but still hands back a partial list.
		return s[login], errors.New("gitops read timed out")
	}
	return s[login], nil
}

// newSIDEnv builds the real router with a stand-in auth middleware that
// picks the caller from the X-Test-User header, so the surface gate is
// exercised exactly where NewRouter puts it.
func newSIDEnv(t *testing.T) *sidEnv {
	t.Helper()
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres-backed surface identity handler test")
	}
	ctx := context.Background()
	store, err := surfaceid.NewStore(ctx, connStr, 0)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	wipe := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM surface_identity_links")
		_, _ = pool.Exec(ctx, "DELETE FROM surface_identity_challenges")
	}
	wipe()
	items, err := workitems.NewStore(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("sid-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		wipe()
		_, _ = pool.Exec(ctx, `DELETE FROM work_items WHERE tenant = $1`, tenant)
		pool.Close()
		store.Close()
		items.Close()
	})
	e := &sidEnv{t: t, audit: audit.NewLogger(), pool: pool, tenant: tenant, users: map[string]*auth.User{
		"alice":    auth.NewGitHubUser("alice", []string{"acme"}),
		"bob":      auth.NewGitHubUser("bob", []string{"acme"}),
		"carol":    auth.NewGitHubUser("carol", nil),
		"root":     auth.NewGitHubUser("root", []string{"admins"}),
		"dex":      {ID: "alice", Groups: []string{"acme"}},
		"service":  auth.NewServiceUser(),
		"telegram": auth.NewSurfaceUser("telegram"),
		"portal":   auth.NewSurfaceUser("portal"),
	}}
	fakeAuth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := e.users[r.Header.Get("X-Test-User")]
			if u == nil {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	e.router = NewRouter(Options{
		AuthMiddleware: fakeAuth, SurfaceIdentities: store, WorkItems: items, AuditLog: e.audit,
		// alice is an admin in her own right; relaying must not carry it.
		TenantResolver: sidTenants{"alice": {tenant, "admins"}, "bob": {"acme"}, "carol": {tenant}},
	})
	return e
}

func (e *sidEnv) do(who, method, path string, body any, headers ...string) (int, map[string]any) {
	e.t.Helper()
	var raw []byte
	switch b := body.(type) {
	case nil:
	case string:
		raw = []byte(b)
	default:
		raw, _ = json.Marshal(b)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("X-Test-User", who)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (e *sidEnv) challenge(who, surface string) string {
	e.t.Helper()
	code, body := e.do(who, "POST", "/api/v1/surface-identities/challenges", map[string]any{"surface": surface})
	if code != http.StatusCreated {
		e.t.Fatalf("challenge for %s = %d %v", who, code, body)
	}
	return body["challenge"].(map[string]any)["code"].(string)
}

func (e *sidEnv) redeem(who, code, externalID string) (int, map[string]any) {
	return e.do(who, "POST", "/api/v1/surface-identities/redeem", map[string]any{"code": code}, SurfaceActorHeader, externalID)
}

func TestSurfaceIdentity_OnlyAGitHubHumanCreatesAChallenge(t *testing.T) {
	e := newSIDEnv(t)
	e.challenge("alice", "telegram")
	for who, want := range map[string]int{
		"service":  http.StatusForbidden, // mctl-agent never links anyone
		"dex":      http.StatusForbidden, // a Dex username is not a proven GitHub login
		"telegram": http.StatusForbidden, // gated: not a surface route
		"portal":   http.StatusForbidden,
	} {
		if code, body := e.do(who, "POST", "/api/v1/surface-identities/challenges", map[string]any{"surface": "telegram"}); code != want {
			t.Errorf("%s: %d %v", who, code, body)
		}
	}
	for _, forged := range []map[string]any{
		{"surface": "telegram", "principal": "github:bob"},
		{"surface": "telegram", "github_login": "bob"},
		{"surface": "telegram", "actor": "github:bob"},
	} {
		if code, body := e.do("alice", "POST", "/api/v1/surface-identities/challenges", forged); code != http.StatusBadRequest || body["code"] != "actor_not_accepted" {
			t.Errorf("forged %v: %d %v", forged, code, body)
		}
	}
	if code, _ := e.do("alice", "POST", "/api/v1/surface-identities/challenges", map[string]any{"surface": "slack"}); code != http.StatusBadRequest {
		t.Errorf("unknown surface = %d", code)
	}
	if code, _ := e.do("alice", "POST", "/api/v1/surface-identities/challenges", map[string]any{"surface": "telegram", "ttl": "1y"}); code != http.StatusBadRequest {
		t.Errorf("unknown field = %d", code)
	}
}

func TestSurfaceIdentity_OnlyTheRightSurfaceRedeemsOnce(t *testing.T) {
	e := newSIDEnv(t)
	code := e.challenge("alice", "telegram")
	// Humans and the service principal cannot redeem, and trying does not
	// consume the challenge.
	for _, who := range []string{"alice", "bob", "service", "root"} {
		if status, body := e.do(who, "POST", "/api/v1/surface-identities/redeem", map[string]any{"code": code}); status != http.StatusForbidden || body["code"] != "surface_principal_required" {
			t.Errorf("%s redeem = %d %v", who, status, body)
		}
	}
	// The body can never say whom to link.
	if status, body := e.do("telegram", "POST", "/api/v1/surface-identities/redeem",
		map[string]any{"code": code, "principal": "github:bob"}, SurfaceActorHeader, "4242"); status != http.StatusBadRequest || body["code"] != "actor_not_accepted" {
		t.Errorf("forged principal on redeem = %d %v", status, body)
	}
	// The observed identity comes from the header, never the body.
	if status, body := e.do("telegram", "POST", "/api/v1/surface-identities/redeem",
		map[string]any{"code": code, "external_id": "4242"}, SurfaceActorHeader, "4242"); status != http.StatusBadRequest {
		t.Errorf("external_id in the body = %d %v", status, body)
	}
	if status, body := e.do("telegram", "POST", "/api/v1/surface-identities/redeem", map[string]any{"code": code}); status != http.StatusBadRequest {
		t.Errorf("redeem naming no identity = %d %v", status, body)
	}
	status, body := e.redeem("telegram", code, "4242")
	if status != http.StatusCreated {
		t.Fatalf("redeem = %d %v", status, body)
	}
	link := body["link"].(map[string]any)
	if link["principal"] != "github:alice" || link["surface"] != "telegram" || link["external_id"] != "4242" {
		t.Fatalf("link = %v", link)
	}
	if status, body := e.redeem("telegram", code, "4242"); status != http.StatusForbidden || body["code"] != "challenge_invalid" {
		t.Errorf("reused challenge = %d %v", status, body)
	}

	// Redeemed by the other surface: refused and burnt.
	other := e.challenge("bob", "telegram")
	if status, body := e.redeem("portal", other, "bob-session"); status != http.StatusForbidden || body["code"] != "challenge_invalid" {
		t.Errorf("portal redeeming a telegram challenge = %d %v", status, body)
	}
	if status, _ := e.redeem("telegram", other, "777"); status != http.StatusForbidden {
		t.Errorf("challenge still valid after exposure to another surface: %d", status)
	}

	// Expired.
	late := e.challenge("bob", "telegram")
	if _, err := e.pool.Exec(context.Background(), `UPDATE surface_identity_challenges SET expires_at=$1 WHERE principal='github:bob' AND consumed_at IS NULL`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if status, body := e.redeem("telegram", late, "777"); status != http.StatusForbidden || body["code"] != "challenge_invalid" {
		t.Errorf("expired challenge = %d %v", status, body)
	}

	// Another human cannot take over alice's telegram identity.
	steal := e.challenge("bob", "telegram")
	if status, body := e.redeem("telegram", steal, "4242"); status != http.StatusConflict || body["code"] != "link_conflict" {
		t.Errorf("second principal on a linked identity = %d %v", status, body)
	}
	if status, _ := e.redeem("telegram", e.challenge("bob", "telegram"), "not-a-number"); status != http.StatusBadRequest {
		t.Errorf("malformed telegram id = %d", status)
	}
}

func TestSurfaceIdentity_GateConfinesSurfacePrincipals(t *testing.T) {
	e := newSIDEnv(t)
	for _, who := range []string{"telegram", "portal"} {
		for _, route := range [][2]string{
			{"GET", "/api/v1/tenants"},
			{"GET", "/api/v1/surface-identities"},
			{"POST", "/api/v1/surface-identities/challenges"},
			{"POST", "/api/v1/surface-identities/sil_x/revoke"},
			{"GET", "/api/v1/whoami"},
			{"GET", "/api/v1/work-items"},
			{"PATCH", "/api/v1/work-items/wi_x"},
			{"POST", "/api/v1/work-items/wi_x/executions"},
			{"GET", "/api/v1/work-items/wi_x/events"},
		} {
			if code, body := e.do(who, route[0], route[1], nil); code != http.StatusForbidden || body["code"] != "surface_route_not_allowed" {
				t.Errorf("%s %s %s = %d %v", who, route[0], route[1], code, body)
			}
		}
	}
	// No one else may name a surface actor.
	for _, who := range []string{"alice", "service", "root"} {
		if code, body := e.do(who, "GET", "/api/v1/surface-identities", nil, SurfaceActorHeader, "4242"); code != http.StatusBadRequest || body["code"] != "actor_not_accepted" {
			t.Errorf("%s sending %s = %d %v", who, SurfaceActorHeader, code, body)
		}
	}
}

func TestSurfaceIdentity_OneEndUserCannotSpendTheSurfacesBudget(t *testing.T) {
	e := newSIDEnv(t)
	limited := false
	for i := 0; i < 25 && !limited; i++ {
		code, _ := e.redeem("telegram", "AAAA-AAAA", "111")
		limited = code == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("one telegram user was never rate limited")
	}
	// Another user of the same surface still has their own budget.
	if code, body := e.redeem("telegram", e.challenge("alice", "telegram"), "222"); code != http.StatusCreated {
		t.Fatalf("second telegram user = %d %v", code, body)
	}
}

// The per-end-user split must not lift the ceiling on the surface itself:
// rotating the actor header is still capped, and the header value must be
// one of the surface's own ids before any limiter keys on it.
func TestSurfaceIdentity_TheSurfaceKeepsAnAggregateCeiling(t *testing.T) {
	e := newSIDEnv(t)
	// Refused by the gate, before any limiter mints a key for it: however
	// often it is sent, it never reaches a bucket (the write bucket would
	// answer 429 from the 21st).
	for _, bad := range []string{"abc", "0", strings.Repeat("9", 21)} {
		for i := 0; i < 25; i++ {
			if code, body := e.do("telegram", "POST", "/api/v1/surface-identities/redeem", "x", SurfaceActorHeader, bad); code != http.StatusBadRequest || body["code"] != "invalid_request" {
				t.Fatalf("actor %q, attempt %d = %d %v", bad, i, code, body)
			}
		}
	}
	limited := 0
	for i := 1; i <= surfaceAggregateLimitPerMinute+5; i++ {
		if code, _ := e.do("telegram", "POST", "/api/v1/surface-identities/redeem", "x", SurfaceActorHeader, strconv.Itoa(i)); code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("a surface rotating its actor header was never throttled")
	}
	// The ceiling is the surface's own: another surface is unaffected.
	if code, _ := e.do("portal", "POST", "/api/v1/surface-identities/redeem", "x", SurfaceActorHeader, "p-1"); code == http.StatusTooManyRequests {
		t.Fatal("the portal surface shares telegram's ceiling")
	}
}

func TestSurfaceIdentity_ListAndRevoke(t *testing.T) {
	e := newSIDEnv(t)
	_, body := e.redeem("telegram", e.challenge("alice", "telegram"), "4242")
	id := body["link"].(map[string]any)["id"].(string)

	code, list := e.do("alice", "GET", "/api/v1/surface-identities", nil)
	if links, _ := list["links"].([]any); code != http.StatusOK || len(links) != 1 {
		t.Fatalf("alice lists %d %v", code, list)
	}
	if code, _ := e.do("bob", "GET", "/api/v1/surface-identities?principal=github:alice", nil); code != http.StatusForbidden {
		t.Errorf("bob listing alice = %d", code)
	}
	if code, list := e.do("root", "GET", "/api/v1/surface-identities?principal=github:alice", nil); code != http.StatusOK || len(list["links"].([]any)) != 1 {
		t.Errorf("admin listing alice = %d %v", code, list)
	}
	if code, _ := e.do("bob", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil); code != http.StatusNotFound {
		t.Errorf("bob revoking alice's link = %d", code)
	}
	// mctl-agent is an admin, but has no say over human links.
	if code, _ := e.do("service", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil); code != http.StatusForbidden {
		t.Errorf("service revoke = %d", code)
	}
	if code, _ := e.do("service", "GET", "/api/v1/surface-identities?principal=github:alice", nil); code != http.StatusForbidden {
		t.Errorf("service listing alice = %d", code)
	}
	if code, body := e.do("alice", "POST", "/api/v1/surface-identities/"+id+"/revoke", nil); code != http.StatusOK || body["link"].(map[string]any)["revoked_at"] == nil {
		t.Fatalf("alice revoke = %d %v", code, body)
	}
	// A human admin may revoke anyone's link.
	_, body = e.redeem("telegram", e.challenge("bob", "telegram"), "555")
	bobLink := body["link"].(map[string]any)["id"].(string)
	if code, body := e.do("root", "POST", "/api/v1/surface-identities/"+bobLink+"/revoke", nil); code != http.StatusOK || body["link"].(map[string]any)["revoked_by"] != "github:root" {
		t.Fatalf("admin revoke = %d %v", code, body)
	}
}

func TestSurfaceIdentity_AuditKeepsBothIdentitiesAndNeverTheCode(t *testing.T) {
	e := newSIDEnv(t)
	code := e.challenge("alice", "telegram")
	e.redeem("portal", e.challenge("alice", "telegram"), "x")
	e.redeem("telegram", code, "4242")
	var linked bool
	for _, entry := range e.audit.List(100) {
		raw, _ := json.Marshal(entry)
		if strings.Contains(string(raw), code) || strings.Contains(string(raw), strings.ReplaceAll(code, "-", "")) {
			t.Fatalf("a challenge code reached the audit log: %s", raw)
		}
		if entry.Operation == "surface_identity.linked" {
			linked = true
			if entry.Parameters["acting_principal"] != "surface:telegram" || entry.Parameters["subject"] != "github:alice" || entry.Parameters["external_id"] != "4242" {
				t.Fatalf("linked audit = %v", entry.Parameters)
			}
		}
	}
	if !linked {
		t.Fatal("no linked audit row")
	}
}

func TestSurfaceIdentity_UnconfiguredAnswers503(t *testing.T) {
	h := &Handlers{}
	req := httptest.NewRequest("POST", "/api/v1/surface-identities/challenges", strings.NewReader(`{"surface":"telegram"}`))
	req = req.WithContext(auth.WithUser(req.Context(), auth.NewGitHubUser("alice", nil)))
	rec := httptest.NewRecorder()
	h.CreateSurfaceChallenge(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("= %d", rec.Code)
	}
}

func TestSurfaceIdentityRoutesAreRegistered(t *testing.T) {
	router, ok := NewRouter(Options{}).(chi.Routes)
	if !ok {
		t.Fatal("the router does not expose its routes")
	}
	found := map[string]bool{}
	_ = chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		found[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	for _, want := range []string{
		"POST /api/v1/surface-identities/challenges",
		"POST /api/v1/surface-identities/redeem",
		"GET /api/v1/surface-identities",
		"POST /api/v1/surface-identities/{id}/revoke",
	} {
		if !found[want] {
			t.Errorf("route not registered: %s", want)
		}
	}
}

func TestSurfaceIdentity_BodyIsParsedStrictly(t *testing.T) {
	e := newSIDEnv(t)
	for body, want := range map[string]int{
		`{"surface":"telegram"}{"surface":"portal"}`:                 http.StatusBadRequest,
		`{"surface":"telegram"} x`:                                   http.StatusBadRequest,
		`{"surface":"` + strings.Repeat("t", sidMaxBodyBytes) + `"}`: http.StatusRequestEntityTooLarge,
	} {
		if code, out := e.do("alice", "POST", "/api/v1/surface-identities/challenges", body); code != want {
			t.Errorf("%.40s… = %d %v, want %d", body, code, out, want)
		}
	}
}
