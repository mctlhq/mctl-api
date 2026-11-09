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

package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/operations"
)

const bridgeTestCmdID = "cmd_01HZZZZZZZZZZZZZZZZZZZZZZZ"

type fakeBridge struct {
	err    error
	claims int
	caller bridge.Caller
}

func (f *fakeBridge) Claim(_ context.Context, c bridge.Caller, _ int, _ time.Duration) ([]bridge.Claimed, error) {
	f.claims++
	f.caller = c
	if f.err != nil {
		return nil, f.err
	}
	return []bridge.Claimed{{CommandID: bridgeTestCmdID, Command: []byte(`{"command_id":"` + bridgeTestCmdID + `"}`)}}, nil
}

func (f *fakeBridge) SubmitResult(_ context.Context, c bridge.Caller, id string, _ []byte) (*bridge.SubmitOutcome, error) {
	f.caller = c
	if f.err != nil {
		return nil, f.err
	}
	return &bridge.SubmitOutcome{CommandID: id, Status: "completed", EffectState: "none", ResultDigest: "sha256:x"}, nil
}

func (f *fakeBridge) IssueWritePermit(_ context.Context, c bridge.Caller, id, _ string) (*bridge.Permit, error) {
	f.caller = c
	if f.err != nil {
		return nil, f.err
	}
	return &bridge.Permit{CommandID: id, FenceRef: "fence_x", IssuedAt: time.Now()}, nil
}

func bridgeRouter(t *testing.T, enabled bool, fb *fakeBridge) (http.Handler, *audit.Logger) {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "true")
	log := audit.NewLogger()
	opts := mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: &fakeGitReader{}, ArgoCD: &fakeArgoCD{}, AuditLog: log, Executor: &fakeExecutor{},
		BridgeEnabled:   enabled,
		BridgeProviders: map[string]auth.BridgeProviderConfig{"glovo": {Ref: "glovo", Tenants: []string{"acme"}}},
	}
	if fb != nil {
		opts.Bridge = fb
	}
	return mctlapi.NewRouter(opts), log
}

func bridgePost(router http.Handler, path, body string, user *auth.User) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithUser(req.Context(), user))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

var bridgeRoutes = []string{
	"/api/v1/bridge/commands/claim",
	"/api/v1/bridge/commands/" + bridgeTestCmdID + "/result",
	"/api/v1/bridge/commands/" + bridgeTestCmdID + "/write-permit",
}

func TestBridgeRoutesAre404WhenDisabled(t *testing.T) {
	router, _ := bridgeRouter(t, false, &fakeBridge{})
	for _, p := range bridgeRoutes {
		if w := bridgePost(router, p, "{}", auth.NewBridgeProviderUser("glovo")); w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", p, w.Code)
		}
	}
}

func TestBridgeRoutesRefuseEveryNonBridgePrincipal(t *testing.T) {
	fb := &fakeBridge{}
	router, _ := bridgeRouter(t, true, fb)
	users := map[string]*auth.User{
		"admin": adminUser, "owner": ownerUser, "service": auth.NewServiceUser(), "usage-writer": auth.NewUsageWriterUser(),
		"security-provider": auth.NewSecurityProviderUser("trivy"),
	}
	for name, u := range users {
		for _, p := range bridgeRoutes {
			if w := bridgePost(router, p, "{}", u); w.Code != http.StatusForbidden {
				t.Errorf("%s %s: got %d, want 403", name, p, w.Code)
			}
		}
	}
	if fb.claims != 0 {
		t.Fatal("a non-bridge principal reached the store")
	}
}

func TestBridgeProviderIsDeniedEverywhereElse(t *testing.T) {
	router, _ := bridgeRouter(t, true, &fakeBridge{})
	bp := auth.NewBridgeProviderUser("glovo")
	for _, p := range []string{
		"/api/v1/agents/dev-loop/dev-loop-x/approve", "/api/v1/operations/deploy-service/execute", "/api/v1/work-items",
		"/api/v1/whoami",
	} {
		if w := bridgePost(router, p, "{}", bp); w.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", p, w.Code)
		}
	}
	for _, p := range []string{"/api/v1/whoami", "/api/v1/work-items"} {
		if w := getAs(t, router, p, bp); w.Code != http.StatusForbidden {
			t.Errorf("GET %s: got %d, want 403", p, w.Code)
		}
	}
}

func TestBridgeHandlersMapTypedErrorsAndRedactAudit(t *testing.T) {
	fb := &fakeBridge{}
	router, log := bridgeRouter(t, true, fb)
	bp := auth.NewBridgeProviderUser("glovo")

	w := bridgePost(router, bridgeRoutes[0], "", bp)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), bridgeTestCmdID) {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	if fb.caller.ProviderRef != "glovo" || len(fb.caller.Tenants) != 1 || fb.caller.Tenants[0] != "acme" {
		t.Fatalf("caller not derived from server config: %+v", fb.caller)
	}
	if w := bridgePost(router, bridgeRoutes[0], `{"tenant":"other"}`, bp); w.Code != http.StatusBadRequest {
		t.Errorf("unknown claim field: %d", w.Code)
	}
	if w := bridgePost(router, bridgeRoutes[1], "{}", bp); w.Code != http.StatusOK {
		t.Errorf("result: %d", w.Code)
	}
	if w := bridgePost(router, "/api/v1/bridge/commands/brc_01HZZZZZZZZZZZZZZZZZZZZZZZ/result", "{}", bp); w.Code != http.StatusBadRequest {
		t.Errorf("brc_ id: %d", w.Code)
	}
	if w := bridgePost(router, bridgeRoutes[2], `{"lease_token":"lt_0123456789abcdef0123","extra":1}`, bp); w.Code != http.StatusBadRequest {
		t.Errorf("permit extra field: %d", w.Code)
	}
	if w := bridgePost(router, bridgeRoutes[2], `{"lease_token":"lt_0123456789abcdef0123"}`, bp); w.Code != http.StatusOK {
		t.Errorf("permit: %d", w.Code)
	}
	for err, want := range map[error]int{
		bridge.ErrLeaseStale: 409, bridge.ErrCommandExpired: 409, bridge.ErrResultConflict: 409, bridge.ErrCommandCancelled: 409, bridge.ErrCommandNotFound: 404,
		bridge.ErrWriteFenceUnavailable: 503, bridge.ErrWriteFenceRefused: 403, bridge.ErrResultInconsistent: 422,
	} {
		fb.err = err
		if w := bridgePost(router, bridgeRoutes[2], `{"lease_token":"lt_0123456789abcdef0123"}`, bp); w.Code != want {
			t.Errorf("%v: got %d, want %d", err, w.Code, want)
		}
	}
	for _, e := range log.List(100) {
		for k, v := range e.Parameters {
			lk := strings.ToLower(k)
			if strings.HasPrefix(v, "lt_") || strings.Contains(lk, "nonce") || strings.Contains(lk, "token") || strings.Contains(lk, "payload") || strings.Contains(lk, "lease") {
				t.Errorf("audit entry %s leaks %s=%s", e.Operation, k, v)
			}
		}
	}
}

func TestBridgeUnavailableWithoutStore(t *testing.T) {
	router, _ := bridgeRouter(t, true, nil)
	if w := bridgePost(router, bridgeRoutes[0], "", auth.NewBridgeProviderUser("glovo")); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", w.Code)
	}
}
