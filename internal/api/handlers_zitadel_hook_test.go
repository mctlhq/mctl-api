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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/zitadelhook"
)

type zitadelHookTenants struct{}

func (zitadelHookTenants) ListTenantsStrict() ([]gitops.Tenant, error) {
	return []gitops.Tenant{{Name: "acme"}}, nil
}

func zitadelHookRouter(t *testing.T) http.Handler {
	t.Helper()
	hook, err := zitadelhook.New(zitadelhook.Config{
		CustomersOrgID:    "org-c",
		GitHubIdPID:       "idp-gh",
		LoginClientUserID: "login",
		ClaimClientIDs:    []string{"web"},
	}, zitadelHookTenants{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(Options{ZitadelHook: &ZitadelHookOptions{
		Hook:       hook,
		IntentKeys: []string{"k-intent"},
		CreateKeys: []string{"k-create"},
		TokenKeys:  []string{"k-token"},
	}})
}

func postZitadelHook(router http.Handler, path, body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if sig != "" {
		req.Header.Set(zitadelhook.SignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestZitadelHook_NotConfiguredFailsClosed(t *testing.T) {
	body := `{"function":"function/preuserinfo"}`
	for _, p := range []string{zitadelHookIntentPath, zitadelHookCreatePath, zitadelHookTokenPath} {
		rec := postZitadelHook(NewRouter(Options{}), p, body, zitadelhook.Sign([]byte(body), "k", time.Now()))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: %d, want 503", p, rec.Code)
		}
	}
}

func TestZitadelHook_SignaturePerTarget(t *testing.T) {
	router := zitadelHookRouter(t)
	body := `{"function":"function/preuserinfo","user":{"id":"u","resource_owner":"other"},"application":{"client_id":"web"}}`
	now := time.Now()
	if rec := postZitadelHook(router, zitadelHookTokenPath, body, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", rec.Code)
	}
	// Another target's key must not open this one.
	if rec := postZitadelHook(router, zitadelHookTokenPath, body, zitadelhook.Sign([]byte(body), "k-intent", now)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("intent key on token target: %d", rec.Code)
	}
	if rec := postZitadelHook(router, zitadelHookTokenPath, body, zitadelhook.Sign([]byte(body), "k-token", now.Add(-10*time.Minute))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale: %d", rec.Code)
	}
	rec := postZitadelHook(router, zitadelHookTokenPath, body, zitadelhook.Sign([]byte(body), "k-token", now))
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "{}" {
		t.Fatalf("signed: %d %q", rec.Code, rec.Body.String())
	}
}

func TestZitadelHook_CreateGateRefusalIsForwarded(t *testing.T) {
	router := zitadelHookRouter(t)
	body := `{"fullMethod":"/zitadel.management.v1.ManagementService/AddHumanUser","orgID":"org-c","request":{"userName":"x"}}`
	rec := postZitadelHook(router, zitadelHookCreatePath, body, zitadelhook.Sign([]byte(body), "k-create", time.Now()))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"forwardedStatusCode":403`) {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestZitadelHook_TooLarge(t *testing.T) {
	body := strings.Repeat("a", maxZitadelHookBytes+1)
	rec := postZitadelHook(zitadelHookRouter(t), zitadelHookIntentPath, body, zitadelhook.Sign([]byte(body), "k-intent", time.Now()))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", rec.Code)
	}
}
