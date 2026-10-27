package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

// T8 and T9 through the real router and the in-process MCP server
// (mctl-api#813): one support tool call that makes one loopback REST call
// yields exactly one row, which lists the loopback call. While that call is
// open, a request carrying its parent id from a non-loopback address, or
// from another run of the same scope, still writes its own row.
func TestSupportAudit_EndToEndOneRowPerToolCall(t *testing.T) {
	sup := auditedSupportRun(t, "labs")
	other := auth.NewAgentUser("mctl-support", auth.AgentRun{
		Agent: "mctl-support", ExecutionID: "we_sup2", WorkItemID: "wi_sup2", RunID: "art_sup2",
		Scope: auth.AgentScopeSupport, Tenant: "labs", RequestedBy: "pr_bob",
	})
	users := map[string]*auth.User{"tok-sup": sup, "tok-other": other}
	log := audit.NewLogger()

	backend := httptest.NewUnstartedServer(nil)
	srv := mctlmcp.NewServer("http://"+backend.Listener.Addr().String(), "")
	router := NewRouter(Options{
		AuthMiddleware: tokenUsers(users),
		MCPServer:      srv,
		AuditLog:       log,
		GitReader:      supportTenants{},
	})

	var forged []int
	backend.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get(mctlmcp.AuditParentHeader); id != "" && strings.HasPrefix(r.URL.Path, "/api/v1/resources/") {
			// The parent is open now: forge children of it.
			for _, c := range []struct{ remote, token string }{
				{"10.0.0.5:4000", "tok-sup"},    // not loopback
				{"127.0.0.1:4000", "tok-other"}, // another run's token
			} {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/labs", nil)
				req.RemoteAddr = c.remote
				req.Header.Set("Authorization", "Bearer "+c.token)
				req.Header.Set(mctlmcp.AuditParentHeader, id)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				forged = append(forged, rec.Code)
			}
		}
		router.ServeHTTP(w, r)
	})
	backend.Start()
	defer backend.Close()

	// Through POST /mcp on the router, as a client would: the outer
	// transport request must not write a row of its own.
	sid := mcpPost(t, backend.URL, "tok-sup", "", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "t", "version": "0"}},
	}).header.Get("Mcp-Session-Id")
	mcpPost(t, backend.URL, "tok-sup", sid, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	mcpPost(t, backend.URL, "tok-sup", sid, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	resp := mcpPost(t, backend.URL, "tok-sup", sid, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "mctl_get_resource_usage", "arguments": map[string]any{"team": "labs"}},
	})
	body := resp.body
	if resp.status != http.StatusOK || strings.Contains(string(body), `"isError":true`) || !strings.Contains(string(body), "labs") {
		t.Fatalf("tool call: %d %s", resp.status, body)
	}
	if len(forged) != 2 {
		t.Fatalf("forged children = %v, want 2 (the loopback call never reached the backend)", forged)
	}

	mine, err := log.ListSupport(context.Background(), audit.SupportFilter{ExecutionID: "we_sup1"})
	if err != nil {
		t.Fatal(err)
	}
	var mcpRows, restRows []audit.Entry
	for _, e := range mine {
		switch e.Parameters["layer"] {
		case "mcp":
			mcpRows = append(mcpRows, e)
		case "rest":
			restRows = append(restRows, e)
		}
	}
	if len(mine) != 2 {
		t.Errorf("rows for the run = %d, want the tool call and the non-loopback forgery only: %+v", len(mine), mine)
	}
	if len(mcpRows) != 1 {
		t.Fatalf("mcp rows = %d, want 1: %+v", len(mcpRows), mine)
	}
	row := mcpRows[0]
	if row.Parameters["tool"] != "mctl_get_resource_usage" || row.Status != "succeeded" ||
		row.Parameters["loopback"] != "GET /api/v1/resources/labs 200" ||
		row.PrincipalID != "pr_alice" || row.ViaPrincipalID != "prn_SUPPORT_AGENT" || row.Tenant != "labs" {
		t.Errorf("mcp row = %+v", row)
	}
	// The folded loopback call wrote no row of its own; the forged
	// non-loopback child did.
	if len(restRows) != 1 || restRows[0].Parameters["route"] != "GET /api/v1/resources/labs" {
		t.Errorf("rest rows for we_sup1 = %+v, want exactly the non-loopback forgery", restRows)
	}
	// A stale parent id (the call has closed) from loopback and the same
	// run no longer folds.
	stale := httptest.NewRequest(http.MethodGet, "/api/v1/resources/labs", nil)
	stale.RemoteAddr = "127.0.0.1:4000"
	stale.Header.Set("Authorization", "Bearer tok-sup")
	stale.Header.Set(mctlmcp.AuditParentHeader, row.ID)
	router.ServeHTTP(httptest.NewRecorder(), stale)
	after, _ := log.ListSupport(context.Background(), audit.SupportFilter{ExecutionID: "we_sup1"})
	if len(after) != len(mine)+1 {
		t.Errorf("stale parent header: rows %d -> %d, want one more", len(mine), len(after))
	}
	theirs, _ := log.ListSupport(context.Background(), audit.SupportFilter{ExecutionID: "we_sup2"})
	if len(theirs) != 1 {
		t.Errorf("another run's forged child wrote %d rows, want 1", len(theirs))
	}
}

// mcpReply is a POST /mcp response, read in full and closed.
type mcpReply struct {
	status int
	header http.Header
	body   []byte
}

func mcpPost(t *testing.T, base, token, session string, msg map[string]any) mcpReply {
	t.Helper()
	b, _ := json.Marshal(msg)
	req, _ := http.NewRequest(http.MethodPost, base+"/mcp", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return mcpReply{status: resp.StatusCode, header: resp.Header, body: body}
}

func tokenUsers(users map[string]*auth.User) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			u := users[token]
			if u == nil {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
			// As auth.Middleware does: the MCP tools reuse the caller's token.
			next.ServeHTTP(w, r.WithContext(auth.WithUser(auth.WithToken(r.Context(), token), u)))
		})
	}
}
