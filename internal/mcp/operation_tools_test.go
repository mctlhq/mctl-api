package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-api/internal/operations"
)

// T13: every RequiresConfirm operation is reachable through a named MCP tool
// that refuses without confirm (no HTTP request) and forwards confirm=yes.
func TestRequiresConfirmParity(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]string
	var paths []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m := map[string]string{}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies = append(bodies, m)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer api.Close()
	srv := NewServer(api.URL, "").NewMCPServer()

	reg := operations.NewRegistry()
	for _, op := range reg.List() {
		if !op.RequiresConfirm || op.HandlerOnly {
			continue
		}
		tool, ok := operationTools[op.Name]
		if !ok {
			t.Errorf("operation %s has RequiresConfirm but operationTools names no MCP tool", op.Name)
			continue
		}
		args := map[string]any{}
		for _, p := range op.Parameters {
			if p.Required {
				args[p.Name] = "x-test"
			}
		}
		mu.Lock()
		before := len(paths)
		mu.Unlock()
		res, msg := callTool(t, srv, tool, args)
		if msg != "" || res == nil || !res.IsError {
			t.Errorf("%s without confirm: want a tool error, got res=%+v msg=%q", tool, res, msg)
		}
		mu.Lock()
		if len(paths) != before {
			t.Errorf("%s without confirm reached the API", tool)
		}
		mu.Unlock()

		args["confirm"] = "yes"
		res, msg = callTool(t, srv, tool, args)
		if msg != "" || res == nil || res.IsError {
			t.Errorf("%s with confirm: res=%+v msg=%q", tool, res, msg)
			continue
		}
		mu.Lock()
		if len(paths) != before+1 || paths[len(paths)-1] != "/api/v1/operations/"+op.Name+"/execute" ||
			bodies[len(bodies)-1]["confirm"] != "yes" {
			t.Errorf("%s with confirm: paths=%v last body=%v", tool, paths[before:], bodies[len(bodies)-1])
		}
		mu.Unlock()
	}
}

// Every execute-route literal in the package names an operation in
// operationTools when that operation requires confirmation, so a new tool
// cannot escape the parity test.
func TestRequiresConfirmSourceScan(t *testing.T) {
	re := regexp.MustCompile(`/api/v1/operations/([a-z0-9-]+)/execute`)
	reg := operations.NewRegistry()
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if filepath.Ext(f) != ".go" || len(f) > 8 && f[len(f)-8:] == "_test.go" {
			continue
		}
		src, err := os.ReadFile(f) //nolint:gosec // G304: the package's own source files, from a Glob
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			op, ok := reg.Get(m[1])
			if !ok {
				continue
			}
			if _, mapped := operationTools[m[1]]; op.RequiresConfirm && !mapped {
				t.Errorf("%s posts to %s (RequiresConfirm) but operationTools does not name it", f, m[1])
			}
		}
	}
	for opName := range operationTools {
		if op, ok := reg.Get(opName); !ok || !op.RequiresConfirm {
			t.Errorf("operationTools names %s which is not a RequiresConfirm operation", opName)
		}
	}
}
