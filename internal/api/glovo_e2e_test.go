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
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// glovoRoutePaths walks the real router and returns every /api/v1/glovo/
// route except the pilot allowlist routes of #960, with path parameters
// filled in. A route added later is picked up here, so it cannot be left out
// of the feature-off and the gate matrices.
func glovoRoutePaths(t *testing.T, e *e2eEnv) [][2]string {
	t.Helper()
	rt, ok := e.router.(chi.Routes)
	if !ok {
		t.Fatal("router is not a chi.Routes")
	}
	var out [][2]string
	err := chi.Walk(rt, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/glovo/") || strings.HasPrefix(route, "/api/v1/glovo/pilot/") {
			return nil
		}
		p := strings.NewReplacer("{tenant}", "alpha", "{id}", "gcn_01JAAAAAAAAAAAAAAAAAAAAAAA").Replace(route)
		out = append(out, [2]string{method, p})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 11 {
		t.Fatalf("route inventory found only %d glovo routes: %v", len(out), out)
	}
	return out
}

// T1: with the feature off every /api/v1/glovo/* route is 503 not_ready,
// before the body is decoded; with it off nothing else changes.
func TestGlovoE2EFeatureOffEveryRoute(t *testing.T) {
	e := newE2E(t, e2eOpts{disabled: true})
	for _, rt := range glovoRoutePaths(t, e) {
		for _, tok := range []string{"tu:owner", "tu:root", e2eWorkerTok} {
			// A body that would not decode: the gate answers before reading it.
			code, m := e.callJSON(rt[0], rt[1], tok, "{not json")
			// The worker is confined to its own routes by glovoWorkerGate,
			// which runs ahead of the feature gate.
			if tok == e2eWorkerTok && !strings.HasPrefix(rt[1], "/api/v1/glovo/worker/") {
				if code != http.StatusForbidden {
					t.Errorf("%s %s as worker: %d", rt[0], rt[1], code)
				}
				continue
			}
			if code != http.StatusServiceUnavailable || errCode(m) != "not_ready" {
				t.Errorf("%s %s as %s: %d %v", rt[0], rt[1], tok, code, m)
			}
		}
	}
	// A Glovo-audience token is not admitted at all while the switch is off.
	tok := e.forge(glovoRes, prnA1, "tgr_x", "alpha")
	if code, _ := e.call(http.MethodGet, facade+"/context", tok, nil); code != http.StatusUnauthorized && code != http.StatusServiceUnavailable {
		t.Errorf("glovo token with the switch off: %d", code)
	}
}

// T2: the happy path of a1 in alpha.
func TestGlovoE2EHappyPath(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.allow("alpha", prnA1)
	rev := e.installTenant("alpha")
	tok := e.mint(prnA1, "alpha")

	code, m := e.callJSON(http.MethodGet, facade+"/context", tok, nil)
	if code != http.StatusOK || m["tenant"] != "alpha" || m["principal_id"] != prnA1 || len(m["connections"].([]any)) != 0 {
		t.Fatalf("context: %d %v", code, m)
	}
	id := e.connectAs(tok)
	if code, m := e.callJSON(http.MethodGet, facade+"/connections/"+id, tok, nil); code != http.StatusOK || m["state"] != "pending" {
		t.Fatalf("get: %d %v", code, m)
	}
	ref := e.handoffAs(tok, id)
	if !strings.HasPrefix(ref, "ghr_") {
		t.Fatalf("handoff ref %q", ref)
	}
	if code, m := e.check(id, rev); code != http.StatusOK || m["allowed"] != false || m["state"] != "pending" {
		t.Fatalf("check before activation: %d %v", code, m)
	}
	code, m = e.activate(id, rev, ref)
	if code != http.StatusOK || m["state"] != "active" || m["expires_at"] == nil {
		t.Fatalf("activate: %d %v", code, m)
	}
	code, m = e.check(id, rev)
	if code != http.StatusOK || m["allowed"] != true || m["tenant"] != "alpha" || m["owner_principal_id"] != prnA1 {
		t.Fatalf("check: %d %v", code, m)
	}
	if code, m := e.callJSON(http.MethodGet, facade+"/context", tok, nil); code != http.StatusOK ||
		m["connections"].([]any)[0].(map[string]any)["state"] != "active" {
		t.Fatalf("context after activation: %d %v", code, m)
	}
	if code, m := e.callJSON(http.MethodPost, facade+"/connections/"+id+"/revoke", tok, nil); code != http.StatusOK || m["state"] != "revoked" {
		t.Fatalf("revoke: %d %v", code, m)
	}
	if code, m := e.check(id, rev); code != http.StatusConflict || errCode(m) != "connection_revoked" {
		t.Fatalf("check after revoke: %d %v", code, m)
	}
}
