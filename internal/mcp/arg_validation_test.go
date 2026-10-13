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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// mctl-api#608: a missing, misnamed or mistyped required argument must be a
// tool error naming the argument, never a handler panic (which surfaced to
// callers as a bare HTTP 500).

// requiredStringArgs lists, per tool, the required string arguments that used
// to be read with an unchecked type assertion.
var requiredStringArgs = map[string][]string{
	"mctl_get_service_status":   {"team", "service"},
	"mctl_get_workflow_status":  {"workflow_name"},
	"mctl_get_resource_usage":   {"team"},
	"mctl_get_tenant":           {"name"},
	"mctl_get_service_config":   {"team", "service"},
	"mctl_list_repos":           {"team"},
	"mctl_grant_repo_access":    {"team", "repo"},
	"mctl_sync_repos":           {"team"},
	"mctl_add_custom_domain":    {"team", "service", "domain"},
	"mctl_get_operation":        {"name"},
	"mctl_list_previews":        {"team"},
	"mctl_get_incident":         {"id"},
	"mctl_acknowledge_incident": {"id"},
	"mctl_resolve_incident":     {"id"},
}

// callToolJSON drives the real tools/call path and returns the raw response.
func callToolJSON(t *testing.T, s *Server, name string, args map[string]any) string {
	t.Helper()
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s.NewMCPServer().HandleMessage(context.Background(), req))
	return string(b)
}

func TestRequiredStringArgs_AreToolErrorsNotPanics(t *testing.T) {
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()
	s := NewServer(api.URL, "")

	for tool, keys := range requiredStringArgs {
		for _, key := range keys {
			valid := map[string]any{}
			for _, k := range keys {
				valid[k] = "x"
			}

			missing := map[string]any{}
			for k, v := range valid {
				if k != key {
					missing[k] = v
				}
			}
			// The misnamed case from the incident: the right value under a
			// wrong key is the same as the key being absent.
			missing[key+"_typo"] = "x"
			wrongType := map[string]any{}
			for k, v := range valid {
				wrongType[k] = v
			}
			wrongType[key] = 123

			for label, args := range map[string]map[string]any{
				fmt.Sprintf("required argument %q not found", key): missing,
				fmt.Sprintf("argument %q is not a string", key):    wrongType,
			} {
				got := callToolJSON(t, s, tool, args)
				if !strings.Contains(got, `"isError":true`) || !strings.Contains(got, strings.ReplaceAll(label, `"`, `\"`)) {
					t.Errorf("%s %v: want a tool error %q, got %.400s", tool, args, label, got)
				}
			}
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("a call with a bad argument reached the API %d times", n)
	}
}

// The backstop: a handler that still panics yields a JSON-RPC error, it does
// not unwind through HandleMessage.
func TestToolHandlerPanicIsRecovered(t *testing.T) {
	s := NewServer("http://localhost:8080", "")
	srv := s.NewMCPServer()
	srv.AddTool(mcplib.NewTool("mctl_test_panics"), func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		panic("boom")
	})
	resp := srv.HandleMessage(context.Background(),
		json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mctl_test_panics","arguments":{}}}`))
	b, _ := json.Marshal(resp)
	if !strings.Contains(string(b), `"error"`) || !strings.Contains(string(b), "panic recovered") {
		t.Fatalf("want a recovered-panic error, got %.400s", b)
	}
}

// Keeps the class from coming back: no handler in this package may read a
// tool argument with a single-value type assertion. A type switch is safe and
// is allowed.
func TestNoUncheckedArgumentAssertions(t *testing.T) {
	unchecked := regexp.MustCompile(`(args|GetArguments\(\))\["[A-Za-z_]+"\]\.\([^)]+\)`)
	checked := regexp.MustCompile(`,\s*(ok|_)\s*:?=`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if unchecked.MatchString(line) && !checked.MatchString(line) && !strings.Contains(line, ".(type)") {
				t.Errorf("%s:%d: unchecked argument assertion, use req.RequireString or the two-value form: %s",
					f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
