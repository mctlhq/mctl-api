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

package glovo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTransitionTableExhaustive(t *testing.T) {
	allowed := map[[2]ConnectionState]bool{
		{PendingHandoff, PendingProvider}: true, {PendingHandoff, Failed}: true,
		{PendingHandoff, Expired}: true, {PendingHandoff, Revoked}: true,
		{PendingProvider, Active}: true, {PendingProvider, Failed}: true,
		{PendingProvider, Expired}: true, {PendingProvider, Revoked}: true,
		{Active, Expired}: true, {Active, Failed}: true, {Active, Revoked}: true,
	}
	for _, from := range allStates {
		for _, to := range allStates {
			if got := CanTransition(from, to); got != allowed[[2]ConnectionState{from, to}] {
				t.Errorf("CanTransition(%s,%s)=%v", from, to, got)
			}
		}
		if from.Terminal() && len(transitions[from]) != 0 {
			t.Errorf("terminal %s has exits", from)
		}
		if from.Live() == from.Terminal() {
			t.Errorf("%s is both or neither live and terminal", from)
		}
	}
	if CanTransition("bogus", Active) || CanTransition(Active, "bogus") {
		t.Fatal("unknown state allowed")
	}
}

func TestOwnerAndActorValidate(t *testing.T) {
	good := Owner{"t", "prn_X"}
	if good.validate() != nil {
		t.Fatal("good owner refused")
	}
	for _, o := range []Owner{{"", "prn_X"}, {"t", ""}, {"t", "usr_X"}, {"t", "prn"}} {
		mustCode(t, o.validate(), CodeInvalidRequest)
	}
	okActors := []Actor{{"prn_1", ActorUser}, {"prn_1", ActorOwner}, {"prn_1", ActorAdmin}, {"worker", ActorWorker}, {"system", ActorSystem}}
	for _, a := range okActors {
		if a.validate() != nil {
			t.Errorf("%v refused", a)
		}
	}
	for _, a := range []Actor{{"", ActorUser}, {"x", ActorUser}, {"prn_1", "root"}, {"prn_1", ActorWorker}, {"", ActorSystem}, {"worker", ActorSystem}, {}} {
		mustCode(t, a.validate(), CodeInvalidRequest)
	}
}

func TestIDPrefixes(t *testing.T) {
	for _, p := range []string{prefixInstall, prefixConnection, prefixAudit, prefixSecretRef} {
		id, err := newPrefixedID(p, time.Now())
		if err != nil || !strings.HasPrefix(id, p) || len(id) != len(p)+26 {
			t.Fatalf("%q %v", id, err)
		}
		other, _ := newPrefixedID(p, time.Now())
		if other == id {
			t.Fatal("ids repeat")
		}
	}
}

func TestErrorMessageIsFixed(t *testing.T) {
	for _, c := range Codes() {
		e := refuse(c)
		if e.Error() != string(c)+": "+codeInfo[c].desc || e.Description == "" {
			t.Errorf("%s: %q", c, e.Error())
		}
		if Status(c) < 400 {
			t.Errorf("%s status %d", c, Status(c))
		}
	}
	if refuse(CodeNotFound).Error() != ErrNotFound.Error() {
		t.Fatal("not_found differs")
	}
}

// TestStatusMapping pins glovo.Status to mctl-api#957 design 4.1.
func TestStatusMapping(t *testing.T) {
	want := map[Code]int{
		CodeNotReady: 503, CodeUnavailable: 503, CodeNotAuthorized: 403, CodeInvalidRequest: 400,
		CodeNotFound: 404, CodeNoConnection: 404,
		CodeNoInstall: 403, CodeAmbiguousTenant: 403, CodeNoTenant: 403, CodeScopeUnsupported: 403,
		CodeNotInPilot: 403, CodeStaleInstall: 403, CodeRateLimited: 429,
		CodeStaleVersion: 409, CodeConnectionExists: 409, CodeConnectionRevoked: 409, CodeConnectionExpired: 409,
		CodeInvalidTransition: 409, CodeIdempotencyReused: 409, CodeFingerprintChanged: 409,
		CodeApprovalInvalid: 409, CodeApprovalExpired: 409, CodeApprovalReplayed: 409,
		CodeIntentMismatch: 409, CodeBasketChanged: 409, CodeTenantBusy: 409,
	}
	if len(want) != len(codeInfo) {
		t.Fatalf("registry has %d codes, table %d", len(codeInfo), len(want))
	}
	for c, st := range want {
		if Status(c) != st {
			t.Errorf("Status(%s)=%d want %d", c, Status(c), st)
		}
		w := httptest.NewRecorder()
		WriteError(w, refuse(c))
		if w.Code != st {
			t.Errorf("WriteError(%s)=%d want %d", c, w.Code, st)
		}
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != string(c) || body["error_description"] == "" {
			t.Errorf("%s body %v", c, body)
		}
	}
}

func TestWriteUnregisteredCodeFailsClosed(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, &Error{Code: "made_up", Description: "x"})
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusServiceUnavailable || body["error"] != "unavailable" {
		t.Fatalf("%d %v", w.Code, body)
	}
	if Status("made_up") != 503 {
		t.Fatal("unregistered status")
	}
}

func TestWriteUnauthenticated(t *testing.T) {
	w := httptest.NewRecorder()
	WriteUnauthenticated(w, "")
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "" || !strings.Contains(w.Body.String(), `"not_authorized"`) {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String())
	}
	w = httptest.NewRecorder()
	WriteUnauthenticated(w, `Bearer realm="x"`)
	if w.Header().Get("WWW-Authenticate") != `Bearer realm="x"` {
		t.Fatal("header not set")
	}
}

func TestGrantsGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/grants.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := grantsSnapshot(); got != string(want) {
		t.Fatalf("grant registry differs from testdata/grants.golden:\n%s", got)
	}
}

func TestRegisterGrantsRejectsBadRows(t *testing.T) {
	for _, r := range []GrantRow{
		{Table: "glovo_installs", Privileges: []string{"SELECT"}, Description: "dup"},
		{Table: "x", Privileges: []string{"TRUNCATE"}, Description: "bad priv"},
		{Table: "y", Privileges: []string{"SELECT"}},
		{Table: "z", Privileges: []string{"UPDATE"}, UpdateColumns: []string{"a"}, Description: "both"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("row %+v accepted", r)
				}
			}()
			RegisterGrants(r)
		}()
	}
}

func TestRefusingSecretRefs(t *testing.T) {
	var r RefusingSecretRefs
	ctx := context.Background()
	if _, err := r.Reserve(ctx, Owner{}, ""); err != ErrSecretBackendUnavailable {
		t.Fatal(err)
	}
	if err := r.Release(ctx, SecretRef{}); err != ErrSecretBackendUnavailable {
		t.Fatal(err)
	}
}

func TestApplySchemaRejectsHostileRoleName(t *testing.T) {
	// Refused before any connection is attempted.
	for _, r := range []string{`x"; DROP ROLE y; --`, "", "Upper", "a b", strings.Repeat("a", 64)} {
		err := ApplySchema(context.Background(), "postgres://invalid", r)
		if err == nil || !strings.Contains(err.Error(), "invalid runtime role") {
			t.Errorf("%q: %v", r, err)
		}
	}
}
