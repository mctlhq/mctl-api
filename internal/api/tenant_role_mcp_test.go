package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

// REST and MCP must refuse the same call the same way (mctl-api#478). An MCP
// tool is a client of the REST API carrying the caller's own token, so the
// gate has one implementation; this drives a real tools/call into the real
// router and compares it with the direct REST call, so the claim is checked
// rather than assumed. If a tool ever grew its own path around the REST
// handler, the two answers here would part.

// tokenAuth stands in for the auth middleware: a bearer token names a user.
func tokenAuth(users map[string]*auth.User) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := users[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if u == nil {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
		})
	}
}

func callTool(t *testing.T, srv *mctlmcp.Server, token, name string, args map[string]string) (text string, isError bool) {
	t.Helper()
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	resp := srv.NewMCPServer().HandleMessage(auth.WithToken(context.Background(), token), json.RawMessage(req))
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Result.Content) == 0 {
		t.Fatalf("tools/call %s: no content: %s", name, raw)
	}
	return out.Result.Content[0].Text, out.Result.IsError
}

func TestMCPAndRESTRefuseTheSameWay(t *testing.T) {
	users := map[string]*auth.User{
		"tok-owner":  member("olga-owner"),
		"tok-dev":    member("dan-dev"),
		"tok-viewer": member("vic-viewer"),
	}
	type call struct {
		tool, op string
		args     map[string]string // REST body; the tool also gets confirm=yes
	}
	calls := []call{
		{"mctl_delete_tenant", "delete-tenant", deleteTenantBody},
		{"mctl_retire_service", "retire-service", retireBody},
		{"mctl_rollback_service", "rollback-service", rollbackBody},
	}
	// Who may do what; everything else must be refused on both routes.
	allowed := map[string]bool{
		"tok-owner/delete-tenant": true, "tok-owner/retire-service": true, "tok-owner/rollback-service": true,
		"tok-dev/rollback-service": true,
	}

	for token := range users {
		for _, c := range calls {
			t.Run(token+"/"+c.op, func(t *testing.T) {
				// Two fixtures, so one route's submission cannot be mistaken
				// for the other's.
				restF, mcpF := newRoleFixture(t), newRoleFixture(t)

				rest := postAs(t, restF.router, "/api/v1/operations/"+c.op+"/execute", c.args, users[token])

				backend := httptest.NewServer(tokenAuth(users)(mcpF.router))
				defer backend.Close()
				toolArgs := map[string]string{"confirm": "yes"}
				for k, v := range c.args {
					toolArgs[k] = v
				}
				text, isError := callTool(t, mctlmcp.NewServer(backend.URL, ""), token, c.tool, toolArgs)

				want := allowed[token+"/"+c.op]
				if (rest.Code == http.StatusAccepted) != want {
					t.Fatalf("REST: status %d, allowed should be %v; body: %s", rest.Code, want, rest.Body.String())
				}
				if isError == want {
					t.Fatalf("MCP: isError=%v, allowed should be %v; text: %s", isError, want, text)
				}
				if (len(restF.exec.submitted) == 1) != want || (len(mcpF.exec.submitted) == 1) != want {
					t.Fatalf("submitted: REST %v, MCP %v; allowed should be %v", restF.exec.submitted, mcpF.exec.submitted, want)
				}
				if want {
					return
				}
				// The refusal reads the same and is audited the same.
				restMsg, _ := decodeJSON(t, rest)["error"].(string)
				if restMsg == "" || !strings.Contains(text, restMsg) {
					t.Fatalf("MCP refusal %q does not carry the REST refusal %q", text, restMsg)
				}
				if !strings.Contains(restMsg, "requires role") {
					t.Fatalf("refusal does not name the required role: %q", restMsg)
				}
				re, me := restF.lastAudit(t), mcpF.lastAudit(t)
				if re.Status != "denied" || me.Status != "denied" || re.Operation != me.Operation || re.UserID != me.UserID || re.Message != me.Message {
					t.Fatalf("audit entries differ: REST %+v, MCP %+v", re, me)
				}
			})
		}
	}
}
