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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovobasketjoin"
)

const (
	basketSvcProvider = "glovo-basket-svc"
	basketSvcSubject  = "svc-glovo-basket"
	basketJoinPath    = "/api/v1/assistants/glovo-basket/v1/resolve"
)

func basketService() *auth.User {
	return auth.NewFederatedUser(basketSvcProvider, "https://issuer.example", basketSvcSubject, "glovo-basket", auth.KindService)
}

type basketJoinRouter struct {
	router  http.Handler
	reached map[string]bool
}

func newBasketJoinRouter(t *testing.T, g *GlovoBasketJoinRoutes, principals map[string]*auth.User) *basketJoinRouter {
	t.Helper()
	b := &basketJoinRouter{reached: map[string]bool{}}
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
	if g != nil && g.Handler == nil {
		g.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { b.reached["join"] = true; w.WriteHeader(http.StatusOK) })
	}
	b.router = NewRouter(Options{AuthMiddleware: mw, GlovoBasketJoin: g,
		mcpHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { b.reached["mcp"] = true; w.WriteHeader(http.StatusOK) })})
	return b
}

func (b *basketJoinRouter) call(method, path, who string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+who)
	rec := httptest.NewRecorder()
	b.router.ServeHTTP(rec, req)
	return rec
}

// Dark by default: without GLOVO_BASKET_JOIN_ENABLED, or without the full
// service identity, or naming a built-in namespace, the prefix is 404 for
// everyone, the configured service included.
func TestGlovoBasketJoinUnmountedIs404(t *testing.T) {
	principals := map[string]*auth.User{"svc": basketService(), "human": {ID: "dan", Groups: []string{"acme"}}}
	for name, g := range map[string]*GlovoBasketJoinRoutes{
		"nil":              nil,
		"flag off":         {Enabled: false, ServiceProvider: basketSvcProvider, ServiceSubject: basketSvcSubject},
		"no subject":       {Enabled: true, ServiceProvider: basketSvcProvider},
		"no provider":      {Enabled: true, ServiceSubject: basketSvcSubject},
		"reserved service": {Enabled: true, ServiceProvider: "service", ServiceSubject: basketSvcSubject},
		"reserved github":  {Enabled: true, ServiceProvider: "github", ServiceSubject: basketSvcSubject},
	} {
		b := newBasketJoinRouter(t, g, principals)
		for who := range principals {
			if rec := b.call("POST", basketJoinPath, who); rec.Code != http.StatusNotFound || b.reached["join"] {
				t.Errorf("%s: %s on the prefix = %d (reached %v), want 404", name, who, rec.Code, b.reached["join"])
			}
		}
	}
}

// Mounted, the surface is confined in both directions: the basket service
// reaches only the basket join prefix, and no one else reaches it, the
// Glovo facade, another service of the same provider and a human of the
// same subject included.
func TestGlovoBasketJoinGateConfinesBothDirections(t *testing.T) {
	principals := matrixPrincipals(t)
	principals["svc"] = basketService()
	principals["svc-other-subject"] = auth.NewFederatedUser(basketSvcProvider, "https://issuer.example", "svc-other", "x", auth.KindService)
	principals["svc-other-provider"] = auth.NewFederatedUser("other-provider", "https://issuer.example", basketSvcSubject, "x", auth.KindService)
	principals["svc-as-human"] = auth.NewFederatedUser(basketSvcProvider, "https://issuer.example", basketSvcSubject, "x", auth.KindHuman)
	b := newBasketJoinRouter(t, &GlovoBasketJoinRoutes{Enabled: true, ServiceProvider: basketSvcProvider, ServiceSubject: basketSvcSubject}, principals)

	if rec := b.call("POST", basketJoinPath, "svc"); rec.Code != http.StatusOK || !b.reached["join"] {
		t.Fatalf("service on its prefix = %d %s", rec.Code, rec.Body.String())
	}
	for _, rt := range [][2]string{
		{"GET", "/api/v1/whoami"}, {"GET", "/api/v1/services"}, {"POST", "/mcp"}, {"GET", "/mcp"},
		{"GET", "/api/v1/assistants/glovo/v1alpha1/connection"}, {"GET", "/api/v1/action-approvals/aar_x"},
		{"POST", "/api/v1/action-approvals/aar_x/decide"}, {"GET", "/api/v1/assistants/glovo-basket/v1"},
	} {
		b.reached = map[string]bool{}
		if rec := b.call(rt[0], rt[1], "svc"); rec.Code != http.StatusUnauthorized || gateCode(rec) != "not_authorized" || b.reached["mcp"] {
			t.Errorf("service on %s %s = %d %q, want 401 not_authorized", rt[0], rt[1], rec.Code, gateCode(rec))
		}
	}
	for who := range principals {
		if who == "svc" {
			continue
		}
		b.reached = map[string]bool{}
		// 401 from this gate, or from an earlier one (the support audience is
		// refused before it); never the handler.
		if rec := b.call("POST", basketJoinPath, who); rec.Code != http.StatusUnauthorized || b.reached["join"] {
			t.Errorf("%s on the basket join prefix = %d %q (reached %v), want 401", who, rec.Code, gateCode(rec), b.reached["join"])
		}
	}
}

// The basket service never decides an approval, even with a resolved
// principal: isGlovoOwnerCandidate refuses anything that is not a human.
func TestGlovoBasketServiceIsNeverADecider(t *testing.T) {
	human := withPrincipal(t, auth.NewFederatedUser(basketSvcProvider, "https://issuer.example", "olga", "olga", auth.KindHuman), glovoOwnerPRN)
	if !isGlovoOwnerCandidate(human) {
		t.Fatal("control: a federated human with a principal must be a candidate")
	}
	svc := withPrincipal(t, basketService(), glovoOwnerPRN)
	if svc.PrincipalID() != glovoOwnerPRN {
		t.Fatalf("the service principal did not resolve: %q", svc.PrincipalID())
	}
	if isGlovoOwnerCandidate(svc) || isGlovoOwnerDecider(svc, nil) {
		t.Fatal("the basket service identity is an owner candidate")
	}
}

// The resolve answer's can_decide uses the approval page's decider role.
func TestGlovoBasketJoinDeciderRoleMatchesThePage(t *testing.T) {
	if glovobasketjoin.DeciderRole != glovoMinDeciderRole {
		t.Fatalf("join decider role %s, page %s", glovobasketjoin.DeciderRole, glovoMinDeciderRole)
	}
}
