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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

type fakeOwnerChecker struct {
	owners map[string]bool
	err    error
	calls  *int
}

func (f fakeOwnerChecker) IsTenantOwner(_ context.Context, u *auth.User, tenant string) (bool, error) {
	if f.calls != nil {
		*f.calls++
	}
	if f.err != nil {
		// (true, err) on purpose: the filter must hide on the error alone.
		return true, f.err
	}
	return tenant == "erpact" && f.owners[u.ID], nil
}

var erpactToolNames = []string{"mctl_erpact_list_sites", "mctl_erpact_create_site", "mctl_erpact_site_status"}

// listToolNames drives the real tools/list path with ctx.
func listToolNames(t *testing.T, s *Server, ctx context.Context) map[string]bool {
	t.Helper()
	mcpSrv := s.NewMCPServer()
	resp := mcpSrv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	b, _ := json.Marshal(resp)
	var out struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode tools/list: %v: %.200s", err, b)
	}
	names := map[string]bool{}
	for _, tl := range out.Result.Tools {
		names[tl.Name] = true
	}
	if len(names) < 10 {
		t.Fatalf("tools/list returned %d tools; filter must only drop the erpact ones", len(names))
	}
	return names
}

func TestToolsList_ErpactToolsOwnerOnly(t *testing.T) {
	owner := auth.NewGitHubUser("olga-owner", []string{"erpact"})
	member := auth.NewGitHubUser("vic-viewer", []string{"erpact"})
	outsider := auth.NewGitHubUser("outsider", []string{"acme"})
	admin := auth.NewGitHubUser("some-admin", []string{"admins"})
	checker := fakeOwnerChecker{owners: map[string]bool{"olga-owner": true, "some-admin": true}}

	cases := []struct {
		name    string
		user    *auth.User
		checker TenantOwnerChecker
		visible bool
	}{
		{"owner", owner, checker, true},
		{"admin", admin, checker, true},
		{"member-not-owner", member, checker, false},
		{"outsider", outsider, checker, false},
		{"anonymous", nil, checker, false},
		{"lookup-error", owner, fakeOwnerChecker{err: errors.New("gitops unreadable")}, false},
		// No checker (stdio): not filtered, the API enforces at call time.
		{"no-checker-stdio", owner, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewServer("http://localhost:8080", "")
			if c.checker != nil {
				s.SetTenantOwnerChecker(c.checker)
			}
			ctx := context.Background()
			if c.user != nil {
				ctx = auth.WithUser(ctx, c.user)
			}
			names := listToolNames(t, s, ctx)
			for _, n := range erpactToolNames {
				if names[n] != c.visible {
					t.Errorf("%s visible=%v, want %v", n, names[n], c.visible)
				}
			}
			if !names["mctl_whoami"] {
				t.Errorf("an unrelated tool vanished from tools/list")
			}
		})
	}
}

// A tool hidden from tools/list must also be refused on tools/call: the
// filter is the visibility control and must not be a cosmetic one.
func TestToolsCall_HiddenErpactToolIsRefused(t *testing.T) {
	s := NewServer("http://localhost:8080", "")
	s.SetTenantOwnerChecker(fakeOwnerChecker{owners: map[string]bool{}})
	ctx := auth.WithUser(context.Background(), auth.NewGitHubUser("vic-viewer", []string{"erpact"}))

	resp := s.NewMCPServer().HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mctl_erpact_list_sites","arguments":{}}}`))
	b, _ := json.Marshal(resp)
	if !strings.Contains(string(b), `"error"`) || !strings.Contains(string(b), "not found") {
		t.Fatalf("tools/call on a hidden tool was not refused: %.300s", b)
	}
}

// One role lookup per tools/list, not one per restricted tool.
func TestToolsList_OneLookupPerList(t *testing.T) {
	n := 0
	s := NewServer("http://localhost:8080", "")
	s.SetTenantOwnerChecker(fakeOwnerChecker{owners: map[string]bool{"olga-owner": true}, calls: &n})
	ctx := auth.WithUser(context.Background(), auth.NewGitHubUser("olga-owner", []string{"erpact"}))
	names := listToolNames(t, s, ctx)
	if !names["mctl_erpact_list_sites"] || n != 1 {
		t.Fatalf("visible=%v lookups=%d, want visible with exactly 1 lookup", names["mctl_erpact_list_sites"], n)
	}
}

func callErpactTool(t *testing.T, s *Server, ctx context.Context) string {
	t.Helper()
	resp := s.NewMCPServer().HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mctl_erpact_list_sites","arguments":{}}}`))
	b, _ := json.Marshal(resp)
	return string(b)
}

// "Could not observe" must not be reported as "observed absent": a failed
// role lookup on tools/call is an explicit could-not-verify, never "not found",
// while a decided non-owner still gets "not found" and tools/list stays hidden.
func TestToolsCall_RoleLookupErrorIsNotReportedAsNotFound(t *testing.T) {
	ctx := auth.WithUser(context.Background(), auth.NewGitHubUser("olga-owner", []string{"erpact"}))

	t.Run("non-owner call is not found", func(t *testing.T) {
		s := NewServer("http://localhost:8080", "")
		s.SetTenantOwnerChecker(fakeOwnerChecker{owners: map[string]bool{}})
		if got := callErpactTool(t, s, ctx); !strings.Contains(got, "not found") {
			t.Fatalf("non-owner call: want not found, got %.300s", got)
		}
	})
	t.Run("lookup error on call is an explicit could-not-verify", func(t *testing.T) {
		s := NewServer("http://localhost:8080", "")
		s.SetTenantOwnerChecker(fakeOwnerChecker{err: errors.New("gitops unreadable")})
		got := callErpactTool(t, s, ctx)
		if strings.Contains(got, "not found") || !strings.Contains(got, "could not verify your role") {
			t.Fatalf("lookup error on call: want could-not-verify and not 'not found', got %.300s", got)
		}
	})
	t.Run("lookup error on list stays hidden", func(t *testing.T) {
		s := NewServer("http://localhost:8080", "")
		s.SetTenantOwnerChecker(fakeOwnerChecker{err: errors.New("gitops unreadable")})
		names := listToolNames(t, s, ctx)
		for _, n := range erpactToolNames {
			if names[n] {
				t.Errorf("%s visible on tools/list despite a failed role lookup", n)
			}
		}
	})
}

// A decided owner must get through the middleware to the tool handler: the
// refusal tests alone would stay green if the gate dropped owners too.
func TestToolsCall_OwnerReachesHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/tenants/erpact/sites" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"sites":["erpact-acme"]}`))
	}))
	defer backend.Close()

	s := NewServer(backend.URL, "")
	s.SetTenantOwnerChecker(fakeOwnerChecker{owners: map[string]bool{"olga-owner": true}})
	ctx := auth.WithUser(context.Background(), auth.NewGitHubUser("olga-owner", []string{"erpact"}))

	got := callErpactTool(t, s, ctx)
	if !strings.Contains(got, "erpact-acme") || strings.Contains(got, `"isError":true`) || strings.Contains(got, `"error"`) {
		t.Fatalf("owner call did not reach the handler: %.300s", got)
	}
}
