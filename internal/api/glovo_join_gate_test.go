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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovojoin/contract"
)

// T2: the join surface is confined in both directions. The facade principal
// reaches only the join prefix (every other path, /mcp included, is 401), and
// no other principal reaches the join prefix.
func TestGlovoJoinGateConfinesBothDirections(t *testing.T) {
	principals := map[string]*auth.User{
		"facade":         auth.NewGlovoFacadeUser(),
		"service":        auth.NewServiceUser(),
		"worker":         auth.NewGlovoWorkerUser(),
		"control-worker": auth.NewGlovoControlWorkerUser(),
		"human":          {ID: "dan", Groups: []string{"acme"}},
	}
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := principals[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	reached := false
	router := NewRouter(Options{AuthMiddleware: mw,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusOK) })})
	call := func(method, path, who string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+who)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	bodyCode := func(rec *httptest.ResponseRecorder) string {
		var b struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		if b.Code != "" {
			return b.Code
		}
		return b.Error
	}
	join := "/api/v1/assistants/glovo/v1alpha1/connection"

	// The facade off its prefix.
	for _, rt := range [][2]string{
		{"GET", "/api/v1/whoami"}, {"GET", "/api/v1/services"}, {"POST", "/mcp"}, {"GET", "/mcp"},
		{"POST", "/api/v1/glovo/worker/check"}, {"GET", "/api/v1/assistants/glovo/v1alpha1"},
	} {
		reached = false
		rec := call(rt[0], rt[1], "facade")
		if rec.Code != http.StatusUnauthorized || bodyCode(rec) != "not_authorized" || reached {
			t.Errorf("facade on %s %s = %d %q (mcp reached %v), want 401 not_authorized", rt[0], rt[1], rec.Code, bodyCode(rec), reached)
		}
	}
	// The facade on its prefix is past the gate (the route table decides).
	if rec := call("GET", join, "facade"); rec.Code == http.StatusUnauthorized {
		t.Errorf("facade on the join prefix refused by the gate: %d %s", rec.Code, rec.Body.String())
	}
	// Everyone else on the join prefix.
	for name := range principals {
		if name == "facade" {
			continue
		}
		rec := call("GET", join, name)
		if rec.Code != http.StatusUnauthorized || bodyCode(rec) != "not_authorized" {
			t.Errorf("%s on the join prefix = %d %q, want 401 not_authorized", name, rec.Code, bodyCode(rec))
		}
	}
}

// matrixPrincipals is every kind of caller the API knows, built the way the
// middleware builds them. The facade is the only one the join prefix accepts.
func matrixPrincipals(t *testing.T) map[string]*auth.User {
	t.Helper()
	agent := auth.NewAgentUser("implementer", auth.AgentRun{Agent: "implementer", ExecutionID: "we_1", WorkItemID: "wi_1", RunID: "art_1", Permissions: []string{"deploy"}})
	surface := auth.NewSurfaceUser("telegram")
	support := newSupportEnv(t)
	sup, err := support.oauth.ValidateJWT(support.token(t, testSupportResource))
	if err != nil || !sup.IsSupportAudience() {
		t.Fatalf("support-audience principal: %+v, %v", sup, err)
	}
	return map[string]*auth.User{
		"facade":           auth.NewGlovoFacadeUser(),
		"admin-service":    auth.NewServiceUser(),
		"admin-human":      {ID: "root", Groups: []string{"admins"}},
		"human":            {ID: "dan", Groups: []string{"acme"}},
		"support-aud":      sup,
		"agent":            agent,
		"delegated-agent":  auth.NewDelegatedUser("dan", []string{"acme", "admins"}, agent),
		"surface":          surface,
		"surface-relay":    auth.NewRelayedUser("dan", []string{"acme"}, surface),
		"ci":               auth.NewCIUser("mctlhq/mctl-api", "1"),
		"ci-job":           auth.NewCIJobUser("mctlhq/mctl-api", "1", "mctlhq/mctl-api/.github/workflows/x.yml@refs/heads/main"),
		"glovo-worker":     auth.NewGlovoWorkerUser(),
		"control-worker":   auth.NewGlovoControlWorkerUser(),
		"usage-writer":     auth.NewUsageWriterUser(),
		"evidence-writer":  auth.NewEvidenceWriterUser(),
		"registry-pub":     auth.NewRegistryPublisherUser(),
		"support-incident": auth.NewSupportIncidentProducerUser(),
		"bridge-provider":  auth.NewBridgeProviderUser("gbr_1"),
	}
}

func matrixRouter(t *testing.T, principals map[string]*auth.User, mcpReached *bool) http.Handler {
	t.Helper()
	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := principals[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
	return NewRouter(Options{AuthMiddleware: mw, GlovoJoin: &GlovoJoinRoutes{Enabled: true},
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { *mcpReached = true; w.WriteHeader(http.StatusOK) })})
}

func gateCode(rec *httptest.ResponseRecorder) string {
	var b struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.Code != "" {
		return b.Code
	}
	return b.Error
}

// T2 (full matrix): with the join routes mounted, EVERY caller kind other than
// the facade is 401 not_authorized on EVERY join route, and the facade is 401
// not_authorized on EVERY other route the router has (found by walking the
// router, so a route added later is covered without editing this test).
func TestGlovoJoinGateMatrixOverEveryRoute(t *testing.T) {
	principals := matrixPrincipals(t)
	reached := false
	router := matrixRouter(t, principals, &reached)
	call := func(method, path, who string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+who)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	fill := func(path string) string {
		path = strings.ReplaceAll(path, "*", "x")
		for {
			i := strings.Index(path, "{")
			if i < 0 {
				return path
			}
			j := strings.Index(path[i:], "}")
			path = path[:i] + "x" + path[i+j+1:]
		}
	}

	joinRoutes := 0
	for _, rt := range contract.MustLoad().Routes {
		path := fill(contract.BasePath + rt.Path)
		joinRoutes++
		for name := range principals {
			if name == "facade" {
				continue
			}
			rec := call(rt.Method, path, name)
			want := gateCode(rec) == "not_authorized"
			if name == "support-aud" {
				// The support-audience gate runs first and answers every path
				// outside its own allowlist as an invalid token; still a 401.
				want = want || gateCode(rec) == "invalid_token"
			}
			if rec.Code != http.StatusUnauthorized || !want {
				t.Errorf("%s on join route %s %s = %d %q, want 401 not_authorized", name, rt.Method, path, rec.Code, gateCode(rec))
			}
		}
	}
	if joinRoutes != 9 {
		t.Fatalf("the contract lists %d join routes, want 9", joinRoutes)
	}

	other, public := 0, 0
	err := chi.Walk(router.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		path := fill(route)
		if glovoJoinPath.MatchString(path + "/") {
			return nil
		}
		// A route outside the authenticated group (health, metrics, oauth, docs,
		// signed webhooks) does not answer an unknown bearer with the
		// middleware's own refusal: no bearer credential is read there,
		// so the facade token means nothing on it.
		if probe := call(method, path, "nobody"); probe.Code != http.StatusUnauthorized || probe.Body.String() != "no\n" {
			public++
			return nil
		}
		other++
		reached = false
		if rec := call(method, path, "facade"); rec.Code != http.StatusUnauthorized || gateCode(rec) != "not_authorized" || reached {
			t.Errorf("facade on %s %s = %d %q (mcp reached %v), want 401 not_authorized", method, path, rec.Code, gateCode(rec), reached)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if other < 50 || public < 5 {
		t.Fatalf("walked %d authenticated and %d public non-join routes; the router walk is not seeing the table", other, public)
	}
	t.Logf("facade refused on %d authenticated non-join routes (%d public routes skipped)", other, public)
}

// G4/G5: the two owner-decision helpers also name the facade. The join gate
// stops the facade before any handler (above), so these clauses are a second
// wall; this pins that the facade identity, handed to them directly, is not an
// owner and not a tenant owner.
func TestGlovoOwnerHelpersRefuseTheFacadeIdentity(t *testing.T) {
	f := auth.NewGlovoFacadeUser()
	if isGlovoOwnerCandidate(f) {
		t.Error("the facade identity is an owner candidate")
	}
	h := &Handlers{}
	r := httptest.NewRequest("POST", "/x", nil).WithContext(auth.WithUser(context.Background(), f))
	rec := httptest.NewRecorder()
	if _, ok := h.requireGlovoTenantOwner(rec, r, "route", "acme"); ok {
		t.Error("the facade identity is a tenant owner")
	}
	if rec.Code == http.StatusOK || rec.Code == 0 {
		t.Errorf("tenant-owner refusal wrote %d", rec.Code)
	}
}
