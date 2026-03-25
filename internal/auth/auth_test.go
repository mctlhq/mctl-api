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

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsJWT(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{"header.payload.signature", true},
		{"ghp_abcdefghijklmnopqrstuvwxyz", false},
		{"", false},
		{"only.two", false},
		{"a.b.c.d", false},
		{"a.b.c", true},
	}
	for _, c := range cases {
		if got := isJWT(c.token); got != c.want {
			t.Errorf("isJWT(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}

func TestHasTenantAccess(t *testing.T) {
	admin := &User{ID: "admin", Groups: []string{"admins", "billing"}}
	member := &User{ID: "alice", Groups: []string{"billing", "data-team"}}
	noAccess := &User{ID: "bob", Groups: []string{"other-team"}}

	if !admin.HasTenantAccess("billing") {
		t.Error("admin should have access to billing")
	}
	if !admin.HasTenantAccess("any-team") {
		t.Error("admin should have access to any tenant")
	}
	if !member.HasTenantAccess("billing") {
		t.Error("member should have access to billing")
	}
	if !member.HasTenantAccess("data-team") {
		t.Error("member should have access to data-team")
	}
	if member.HasTenantAccess("other-team") {
		t.Error("member should not have access to other-team")
	}
	if noAccess.HasTenantAccess("billing") {
		t.Error("bob should not have access to billing")
	}
}

func TestIsAdmin(t *testing.T) {
	admin := &User{ID: "admin", Groups: []string{"admins"}}
	notAdmin := &User{ID: "alice", Groups: []string{"billing"}}
	empty := &User{ID: "bob", Groups: nil}

	if !admin.IsAdmin() {
		t.Error("user with admins group should be admin")
	}
	if notAdmin.IsAdmin() {
		t.Error("user without admins group should not be admin")
	}
	if empty.IsAdmin() {
		t.Error("user with no groups should not be admin")
	}
}

func TestWriteUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	writeUnauthorized(w, "test error message")

	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json Content-Type, got %q", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] != "test error message" {
		t.Errorf("expected error message in body, got %q", body["error"])
	}
}

func TestGitHubValidatorIsAdmin(t *testing.T) {
	v := NewGitHubValidator([]string{"alice", "BOB"})

	if !v.IsAdmin("alice") {
		t.Error("alice should be admin")
	}
	if !v.IsAdmin("Alice") {
		t.Error("Alice (case-insensitive) should be admin")
	}
	if !v.IsAdmin("bob") {
		t.Error("bob (case-insensitive) should be admin")
	}
	if v.IsAdmin("charlie") {
		t.Error("charlie should not be admin")
	}
}

func TestWithUser(t *testing.T) {
	u := &User{ID: "alice", Groups: []string{"billing"}}
	ctx := WithUser(context.Background(), u)
	got := UserFromContext(ctx)
	if got == nil {
		t.Fatal("expected user in context, got nil")
	}
	if got.ID != "alice" {
		t.Errorf("expected ID alice, got %q", got.ID)
	}
}

func TestUserFromContext_nil(t *testing.T) {
	got := UserFromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil user from empty context, got %+v", got)
	}
}

func TestMiddlewareAcceptsMctlAgentServiceToken(t *testing.T) {
	t.Setenv("AUTH_REQUIRED", "true")
	t.Setenv("MCTL_AGENT_SERVICE_TOKEN", "svc-token-123")

	mw := Middleware(NewGitHubValidator(nil), nil, nil, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			t.Fatal("expected user in context")
		}
		if user.ID != "mctl-agent" {
			t.Fatalf("expected mctl-agent user, got %q", user.ID)
		}
		if !user.IsAdmin() {
			t.Fatal("expected service user to be admin")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	req.Header.Set("Authorization", "Bearer svc-token-123")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
