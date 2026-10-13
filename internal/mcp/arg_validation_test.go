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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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

// callTool drives the real tools/call path. It returns the tool result, or
// the JSON-RPC error message when the call failed at the protocol level.
func callTool(t *testing.T, srv *server.MCPServer, name string, args map[string]any) (*mcplib.CallToolResult, string) {
	t.Helper()
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(srv.HandleMessage(context.Background(), req))
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("decode response %s: %v", b, err)
	}
	if resp.Error != nil {
		return nil, resp.Error.Message
	}
	res, err := mcplib.ParseCallToolResult(&resp.Result)
	if err != nil {
		t.Fatalf("decode result %s: %v", resp.Result, err)
	}
	return res, ""
}

func TestRequiredStringArgs_AreToolErrorsNotPanics(t *testing.T) {
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()
	srv := NewServer(api.URL, "").NewMCPServer()

	for tool, keys := range requiredStringArgs {
		for _, key := range keys {
			missing := map[string]any{}
			wrongType := map[string]any{}
			for _, k := range keys {
				if k != key {
					missing[k] = "x"
				}
				wrongType[k] = "x"
			}
			// The misnamed case from the incident: the right value under a
			// wrong key is the same as the key being absent.
			missing[key+"_typo"] = "x"
			wrongType[key] = 123

			for want, args := range map[string]map[string]any{
				fmt.Sprintf("required argument %q not found", key): missing,
				fmt.Sprintf("argument %q is not a string", key):    wrongType,
			} {
				res, rpcErr := callTool(t, srv, tool, args)
				if res == nil || !res.IsError || resultText(t, res) != want {
					t.Errorf("%s %v: want tool error %q, got result %+v, rpc error %q", tool, args, want, res, rpcErr)
				}
			}
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("a call with a bad argument reached the API %d times", n)
	}
}

// The backstop: a handler that still panics yields a JSON-RPC error, logs the
// panic with its stack, and marks the tool span failed.
func TestToolHandlerPanicIsRecoveredLoggedAndTraced(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	oldTP := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	defer otel.SetTracerProvider(oldTP)
	var logs bytes.Buffer
	oldLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(oldLog)

	srv := NewServer("http://localhost:8080", "").NewMCPServer()
	srv.AddTool(mcplib.NewTool("mctl_test_panics"), func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		panic("boom")
	})
	_, rpcErr := callTool(t, srv, "mctl_test_panics", map[string]any{})
	if !strings.Contains(rpcErr, "panic recovered in mctl_test_panics tool handler: boom") {
		t.Errorf("rpc error %q, want the recovered panic", rpcErr)
	}

	var entry struct {
		Msg   string `json:"msg"`
		Tool  string `json:"tool"`
		Panic string `json:"panic"`
		Stack string `json:"stack"`
	}
	// Scan rather than expect a single line: other middleware may log too.
	for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
		if err := json.Unmarshal(line, &entry); err == nil && entry.Msg == "mcp tool handler panic" {
			break
		}
		entry.Msg = ""
	}
	if entry.Msg == "" {
		t.Fatalf("no panic log line in %q", logs.String())
	}
	if entry.Tool != "mctl_test_panics" || entry.Panic != "boom" ||
		!strings.Contains(entry.Stack, "arg_validation_test.go") {
		t.Errorf("log entry %+v, want the panic with a stack through the handler", entry)
	}

	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Status.Code != codes.Error {
		t.Fatalf("spans %+v, want one span with status Error", spans)
	}
	status := ""
	for _, a := range spans[0].Attributes {
		if a.Key == telemetry.KeyToolStatus {
			status = a.Value.AsString()
		}
	}
	if status != "error" {
		t.Errorf("tool status %q, want error", status)
	}
}

// Keeps the class from coming back: no single-value type assertion on an
// indexed value anywhere in the package's non-test code. A two-value
// assertion and a type switch are both safe and allowed.
func TestNoUncheckedArgumentAssertions(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		checked := map[*ast.TypeAssertExpr]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			var rhs []ast.Expr
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == 2 {
					rhs = n.Rhs
				}
			case *ast.ValueSpec:
				if len(n.Names) == 2 {
					rhs = n.Values
				}
			}
			if len(rhs) == 1 {
				if ta, ok := rhs[0].(*ast.TypeAssertExpr); ok {
					checked[ta] = true
				}
			}
			return true
		})
		ast.Inspect(file, func(n ast.Node) bool {
			ta, ok := n.(*ast.TypeAssertExpr)
			// Type == nil is the x.(type) of a type switch.
			if !ok || ta.Type == nil || checked[ta] {
				return true
			}
			if _, indexed := ast.Unparen(ta.X).(*ast.IndexExpr); indexed {
				t.Errorf("%s: single-value type assertion on an indexed value; use req.RequireString or the two-value form",
					fset.Position(ta.Pos()))
			}
			return true
		})
	}
}
