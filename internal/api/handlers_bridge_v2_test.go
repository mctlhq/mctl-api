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

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/bridge"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// versionedBridge returns one fixed command and records the caller.
type versionedBridge struct {
	fakeBridge
	command []byte
}

func (v *versionedBridge) Claim(_ context.Context, c bridge.Caller, _ int, _ time.Duration) ([]bridge.Claimed, error) {
	v.caller = c
	return []bridge.Claimed{{CommandID: bridgeTestCmdID, Command: v.command}}, nil
}

func versionedRouter(t *testing.T, b mctlapi.BridgeService, versions []string) http.Handler {
	t.Helper()
	t.Setenv("AUTH_REQUIRED", "true")
	return mctlapi.NewRouter(mctlapi.Options{
		Registry: operations.NewRegistry(), GitReader: &fakeGitReader{}, ArgoCD: &fakeArgoCD{}, AuditLog: audit.NewLogger(), Executor: &fakeExecutor{},
		BridgeEnabled: true, Bridge: b,
		BridgeProviders: map[string]auth.BridgeProviderConfig{"glovo": {Ref: "glovo", Tenants: []string{"acme"}, SupportedVersions: versions}},
	})
}

// T4h: the claim envelope follows the provider's declared versions and each
// response validates against the vendored claim-response schema.
func TestBridgeClaimEnvelopeFollowsProviderVersions(t *testing.T) {
	v1cmd, err := os.ReadFile("../bridge/schema/testdata/command.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	readCmd, err := os.ReadFile("../bridge/schema/v1alpha2/fixtures/read-command.history.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		versions []string
		command  []byte
		envelope string
	}{
		{"no key", nil, v1cmd, bridge.SchemaVersion},
		{"v1alpha1 only", []string{bridge.WireV1alpha1}, v1cmd, bridge.SchemaVersion},
		{"v1alpha1 and v1alpha2", []string{bridge.WireV1alpha1, bridge.WireV1alpha2}, readCmd, bridge.ClaimEnvelopeV1alpha2},
	} {
		vb := &versionedBridge{command: tc.command}
		router := versionedRouter(t, vb, tc.versions)
		w := bridgePost(router, bridgeRoutes[0], "", auth.NewBridgeProviderUser("glovo"))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
		var env struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.SchemaVersion != tc.envelope {
			t.Fatalf("%s: envelope %q, want %q", tc.name, env.SchemaVersion, tc.envelope)
		}
		if err := bridge.ValidateClaimResponse(w.Body.Bytes()); err != nil {
			t.Errorf("%s: response fails claim-response.schema.json: %v", tc.name, err)
		}
		if tc.versions != nil && strings.Join(vb.caller.Versions, ",") != strings.Join(tc.versions, ",") {
			t.Errorf("%s: caller versions %v, want %v", tc.name, vb.caller.Versions, tc.versions)
		}
	}
}

// T7: a body over bridgeMaxBody is 400 invalid_document at the route; the
// Store's own cap and the read sentinels never surface as 500.
func TestBridgeResultOverCapAndReadSentinels(t *testing.T) {
	fb := &fakeBridge{}
	router, _ := bridgeRouter(t, true, fb)
	bp := auth.NewBridgeProviderUser("glovo")
	over, err := os.ReadFile("../bridge/schema/v1alpha2/fixtures/read-result.over-cap.json")
	if err != nil {
		t.Fatal(err)
	}
	w := bridgePost(router, bridgeRoutes[1], string(over), bp)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_document") {
		t.Fatalf("over-cap: %d %s", w.Code, w.Body.String())
	}
	for err, want := range map[error]int{
		bridge.ErrPayloadTooLarge: http.StatusRequestEntityTooLarge, bridge.ErrReadUnavailable: http.StatusServiceUnavailable,
		bridge.ErrReadNotAuthorized: http.StatusForbidden,
	} {
		fb.err = err
		if w := bridgePost(router, bridgeRoutes[1], "{}", bp); w.Code != want {
			t.Errorf("%v: got %d, want %d", err, w.Code, want)
		}
	}
}
