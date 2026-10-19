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

package customerdelete

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/principals"
)

func TestProvidersVerifyDeleteAndRetry(t *testing.T) {
	deleted, deletes, sessions, cleanups := false, 0, 0, 0
	wrongOrg, malformedLinks, partialSession := false, false, false
	d := &principals.CustomerDeletion{Tenant: "acme", PrincipalID: "prn_01M45DR1GWC87109EH88VBJX25", Subject: "7001", GitHubID: "123", Login: "alice"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/v2/token":
			id, secret, ok := r.BasicAuth()
			if !ok || id != "lifecycle" || secret != "secret" {
				t.Error("machine credential not sent as Basic auth")
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if !strings.Contains(r.Form.Get("scope"), "urn:zitadel:iam:org:project:id:worker-project:aud") {
				t.Error("Worker audience missing")
			}
			_, _ = w.Write([]byte(`{"access_token":"machine-jwt"}`))
		case "/v2/users/7001":
			if r.Method == "DELETE" {
				deleted = true
				deletes++
				_, _ = w.Write([]byte(`{}`))
				return
			}
			if deleted {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"code":5}`))
				return
			}
			org := "customers"
			if wrongOrg {
				org = "staff"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"user": map[string]any{"userId": "7001", "human": map[string]any{}, "details": map[string]string{"resourceOwner": org}}})
		case "/v2/users/7001/links/_search":
			if malformedLinks {
				_, _ = w.Write([]byte(`{"result":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"details":{"totalResult":"1"},"result":[{"idpId":"github-idp","userId":"123"}]}`))
		case "/api/internal/customer-sessions/revoke":
			sessions++
			if partialSession {
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"complete":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"github_id":"123","subject":"7001","complete":true}`))
		case "/api/tenant-management/internal/tenants/acme/cleanup":
			cleanups++
			_, _ = w.Write([]byte(`{"tenant":"acme","cleaned":true,"scope":"customer"}`))
		default:
			t.Errorf("unexpected provider path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	p := &Providers{Issuer: server.URL, CustomerOrg: "customers", GitHubIDP: "github-idp", ClientID: "lifecycle", ClientSecret: "secret", SessionAudience: "worker-project", SiteBase: server.URL, PortalBase: server.URL, PortalToken: "portal"}
	ctx := context.Background()
	wrongOrg = true
	if err := p.DeleteCustomer(ctx, d); err == nil {
		t.Fatal("staff target was deletable")
	}
	if deletes != 0 {
		t.Fatal("staff mutation occurred")
	}
	wrongOrg = false
	malformedLinks = true
	if err := p.VerifyCustomer(ctx, d); err == nil {
		t.Fatal("unknown link observation accepted")
	}
	malformedLinks = false
	if err := p.VerifyCustomer(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteCustomer(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteCustomer(ctx, d); err != nil {
		t.Fatal("delete retry:", err)
	}
	if deletes != 1 {
		t.Fatalf("IdP mutation count=%d", deletes)
	}
	partialSession = true
	if err := p.RevokeSiteSessions(ctx, d); err == nil {
		t.Fatal("partial session cleanup reported complete")
	}
	partialSession = false
	if err := p.RevokeSiteSessions(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanPortal(ctx, d); err != nil {
		t.Fatal(err)
	}
	if sessions != 2 || cleanups != 1 {
		t.Fatal("expected cleanup calls missing")
	}
}

func TestProvidersDoNotForwardCredentialsOnRedirect(t *testing.T) {
	forwarded := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer server.Close()
	p := &Providers{Issuer: server.URL, ClientID: "lifecycle", ClientSecret: "secret"}
	if err := p.VerifyCustomer(context.Background(), &principals.CustomerDeletion{Subject: "7001"}); err == nil {
		t.Fatal("redirect accepted")
	}
	if forwarded {
		t.Fatal("credential was forwarded to another origin")
	}
}

func TestCleanPortalRequiresCustomerScope(t *testing.T) {
	for _, scope := range []string{"", "workspace", "customer"} {
		t.Run(scope, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"tenant": "acme", "cleaned": true, "scope": scope})
			}))
			defer server.Close()
			p := &Providers{PortalBase: server.URL, PortalToken: "test"}
			err := p.CleanPortal(context.Background(), &principals.CustomerDeletion{Tenant: "acme", PrincipalID: "prn_01M45DR1GWC87109EH88VBJX25", Login: "alice"})
			if (err == nil) != (scope == "customer") {
				t.Fatalf("scope=%q error=%v", scope, err)
			}
		})
	}
}

func TestSignupSiteUsesLifecycleCredentialAndReportsSafeFailureStage(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		authStatus, siteStatus int
		stage                  string
		wantStatus             int
	}{
		{"authentication", 401, 200, "service_authentication", 401}, {"site", 200, 403, "site_response", 403}, {"redirect", 200, 302, "site_response", 302}, {"success", 200, 200, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/v2/token" {
					if id, secret, ok := r.BasicAuth(); !ok || id != "lifecycle" || secret != "fixture-secret" {
						t.Error("missing lifecycle authentication")
					}
					w.WriteHeader(tc.authStatus)
					_, _ = w.Write([]byte(`{"access_token":"fixture-jwt"}`))
					return
				}
				calls++
				if r.URL.Path != "/api/internal/invitations/requests" || r.Header.Get("Authorization") != "Bearer fixture-jwt" {
					t.Error("wrong bridge route or credential")
				}
				w.Header().Set("Location", "https://unrelated.example")
				w.WriteHeader(tc.siteStatus)
				_, _ = w.Write([]byte(`{"requests":[]}`))
			}))
			defer server.Close()
			provider := &Providers{Issuer: server.URL, SiteBase: server.URL, ClientID: "lifecycle", ClientSecret: "fixture-secret", SessionAudience: "worker-project"}
			_, err := provider.SignupSite(context.Background(), "GET", "/api/internal/invitations/requests", nil)
			if tc.stage == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var failure *SignupSiteError
				if !errors.As(err, &failure) || failure.Stage != tc.stage || failure.Status != tc.wantStatus {
					t.Fatalf("wrong safe diagnostic: %#v", failure)
				}
				if strings.Contains(err.Error(), "fixture-secret") {
					t.Fatal("credential in error text")
				}
			}
			if tc.authStatus != 200 && calls != 0 {
				t.Fatal("bridge called without service authentication")
			}
			before := calls
			if _, err := provider.SignupSite(context.Background(), "GET", "/api/internal/invitations-evil/requests", nil); err == nil || calls != before {
				t.Fatal("prefix escape reached a provider")
			}
		})
	}
}
