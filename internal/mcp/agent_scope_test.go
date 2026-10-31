package mcp

import (
	"context"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func runScope(t *testing.T, ctx context.Context, tool string) (*mcplib.CallToolResult, bool) {
	t.Helper()
	req := mcplib.CallToolRequest{}
	req.Params.Name = tool
	ran := false
	srv := &Server{}
	srv.SetScopedCallAuditor(&recordingAuditor{})
	res, err := srv.agentScopeMiddleware(func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran = true
		return mcplib.NewToolResultText("ok"), nil
	})(ctx, req)
	if err != nil {
		t.Fatalf("middleware error: %v", err)
	}
	return res, ran
}

func TestAgentScopeMiddleware_ScopedRunCallsOnlyItsTools(t *testing.T) {
	ctx := auth.WithUser(context.Background(), auth.NewAgentUser("issue-investigator", auth.AgentRun{
		WorkItemID: "wi_a", ExecutionID: "we_a", Scope: auth.AgentScopeInvestigate,
	}))
	if _, ran := runScope(t, ctx, "mctl_get_logs"); !ran {
		t.Error("a read tool was refused")
	}
	for _, tool := range []string{"mctl_resolve_incident", "mctl_deploy_service", "mctl_trigger_issue", "mctl_list_work_item_intents"} {
		res, ran := runScope(t, ctx, tool)
		if ran {
			t.Errorf("%s ran for a scoped investigate run", tool)
			continue
		}
		if !res.IsError || !strings.Contains(res.Content[0].(mcplib.TextContent).Text, AgentScopeCodeDenied) {
			t.Errorf("%s refusal = %+v, want %s", tool, res, AgentScopeCodeDenied)
		}
	}
}

func TestAgentScopeMiddleware_OthersPassThrough(t *testing.T) {
	unscoped := auth.WithUser(context.Background(), auth.NewAgentUser("issue-investigator", auth.AgentRun{WorkItemID: "wi_a"}))
	if _, ran := runScope(t, unscoped, "mctl_resolve_incident"); !ran {
		t.Error("an unscoped run token was refused by the scope middleware")
	}
	// A shadowing service call is counted, never refused.
	shadow := auth.WithShadowAgentScope(auth.WithUser(context.Background(), auth.NewServiceUser()), auth.AgentScopeInvestigate)
	if _, ran := runScope(t, shadow, "mctl_deploy_service"); !ran {
		t.Error("a shadowed call was refused")
	}
}

func TestAgentScopeMiddleware_UnknownScopeAdmitsNothing(t *testing.T) {
	ctx := auth.WithUser(context.Background(), auth.NewAgentUser("issue-investigator", auth.AgentRun{
		WorkItemID: "wi_a", Scope: "no-such-scope",
	}))
	res, ran := runScope(t, ctx, "mctl_get_logs")
	if ran || !res.IsError {
		t.Fatal("a run token with a scope the server does not define called a tool")
	}
}

// TestReadToolsAreRecordedReadOnly holds the scope's read-tool naming rule
// to the recorded annotations: a tool the rule would admit must be recorded
// read-only.
func TestReadToolsAreRecordedReadOnly(t *testing.T) {
	admitted := 0
	for name, h := range recordedHints {
		if !auth.IsReadTool(name) {
			continue
		}
		admitted++
		if !h.readOnly {
			t.Errorf("%s is named as a read, so scoped runs may call it, but is recorded readOnly=false", name)
		}
	}
	if admitted == 0 {
		t.Fatal("no recorded tool is a read: the check proves nothing")
	}
}

func runScopeArgs(t *testing.T, ctx context.Context, tool string, args map[string]any) (*mcplib.CallToolResult, bool) {
	t.Helper()
	req := mcplib.CallToolRequest{}
	req.Params.Name = tool
	req.Params.Arguments = args
	ran := false
	srv := &Server{}
	srv.SetScopedCallAuditor(&recordingAuditor{})
	res, err := srv.agentScopeMiddleware(func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran = true
		return mcplib.NewToolResultText("ok"), nil
	})(ctx, req)
	if err != nil {
		t.Fatalf("middleware error: %v", err)
	}
	return res, ran
}

func TestSupportToolsAreRegisteredReads(t *testing.T) {
	for _, n := range auth.SupportToolNames() {
		h, ok := recordedHints["mctl_"+n]
		if !ok {
			t.Errorf("support tool %s is not a registered tool", n)
			continue
		}
		if !h.readOnly {
			t.Errorf("support tool %s is not recorded read-only", n)
		}
	}
}

func TestAgentScopeMiddleware_SupportIsBoundToItsTenant(t *testing.T) {
	ctx := auth.WithUser(context.Background(), auth.NewAgentUser("mctl-support", auth.AgentRun{
		ExecutionID: "we_a", Scope: auth.AgentScopeSupport, Tenant: "labs",
	}))
	allowed := []struct {
		tool string
		args map[string]any
	}{
		{"mctl_get_service_status", map[string]any{"team": "labs", "service": "x"}},
		{"mctl_list_incidents", map[string]any{"team": "labs"}},
		{"mctl_get_service_logs", map[string]any{"team": "labs", "service": "x"}},
	}
	for _, c := range allowed {
		if _, ran := runScopeArgs(t, ctx, c.tool, c.args); !ran {
			t.Errorf("%s %v was refused", c.tool, c.args)
		}
	}
	denied := []struct {
		tool string
		args map[string]any
	}{
		{"mctl_get_service_status", map[string]any{"team": "karabu", "service": "x"}},
		{"mctl_list_services", map[string]any{}},
		{"mctl_get_resource_usage", map[string]any{"team": "karabu"}},
		{"mctl_list_domains", map[string]any{"team_name": "karabu"}},
		{"mctl_list_incidents", map[string]any{"tenant": "karabu"}},
		{"mctl_deploy_service", map[string]any{"team_name": "labs"}},
		{"mctl_list_tenants", map[string]any{}},
	}
	for _, c := range denied {
		res, ran := runScopeArgs(t, ctx, c.tool, c.args)
		if ran {
			t.Errorf("%s %v ran for a support run", c.tool, c.args)
			continue
		}
		if !res.IsError || !strings.Contains(res.Content[0].(mcplib.TextContent).Text, AgentScopeCodeDenied) {
			t.Errorf("%s refusal = %+v, want %s", c.tool, res, AgentScopeCodeDenied)
		}
	}
}

type recordingAuditor struct{ recs []ScopedToolCallRecord }

func (a *recordingAuditor) AuditScopedToolCall(_ context.Context, rec ScopedToolCallRecord) {
	a.recs = append(a.recs, rec)
}

func supportCtx() context.Context {
	return auth.WithUser(context.Background(), auth.NewAgentUser("mctl-support", auth.AgentRun{
		ExecutionID: "we_a", RunID: "art_a", Scope: auth.AgentScopeSupport, Tenant: "labs", RequestedBy: "pr_alice",
	}))
}

func callSupport(srv *Server, tool string, args map[string]any, h server.ToolHandlerFunc) (*mcplib.CallToolResult, error) {
	req := mcplib.CallToolRequest{}
	req.Params.Name = tool
	req.Params.Arguments = args
	return srv.agentScopeMiddleware(h)(supportCtx(), req)
}

func TestSupportAudit_OneRowPerCall(t *testing.T) {
	aud := &recordingAuditor{}
	srv := &Server{}
	srv.SetScopedCallAuditor(aud)

	var parent string
	res, _ := callSupport(srv, "mctl_get_service_status", map[string]any{"team": "labs", "service": "x"},
		func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			parent = loopbackCollectorFromContext(ctx).id
			if run, ok := srv.OpenAuditParent(parent); !ok || run != "art_a" {
				t.Errorf("parent not open during the call: %q %v", run, ok)
			}
			loopbackCollectorFromContext(ctx).add("GET /api/v1/status/labs/x 200")
			return mcplib.NewToolResultError("SENTINEL"), nil
		})
	if !res.IsError || len(aud.recs) != 1 {
		t.Fatalf("res=%v recs=%d", res, len(aud.recs))
	}
	r := aud.recs[0]
	if r.Verdict != "allowed" || r.Result != "failed" || r.Tool != "mctl_get_service_status" || r.EntryID != parent ||
		len(r.Loopback) != 1 {
		t.Errorf("record = %+v", r)
	}
	if _, ok := srv.OpenAuditParent(parent); ok {
		t.Error("parent still open after the call")
	}

	aud.recs = nil
	_, _ = callSupport(srv, "mctl_list_tenants", nil, func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		t.Error("refused tool ran")
		return nil, nil
	})
	if len(aud.recs) != 1 || aud.recs[0].Verdict != "denied" || aud.recs[0].Tool != "mctl_list_tenants" {
		t.Errorf("denied records = %+v", aud.recs)
	}
}

func TestSupportAudit_RefusedWithoutAuditor(t *testing.T) {
	allow := AgentScopeDecisions.WithLabelValues("support", "enforce", "mcp", "allow")
	deny := AgentScopeDecisions.WithLabelValues("support", "enforce", "mcp", "deny")
	allow0, deny0 := testutil.ToFloat64(allow), testutil.ToFloat64(deny)
	defer func() {
		// Counted once, as a deny: never as both allow and deny.
		if a, d := testutil.ToFloat64(allow)-allow0, testutil.ToFloat64(deny)-deny0; a != 0 || d != 1 {
			t.Errorf("decisions: allow +%v deny +%v, want +0 / +1", a, d)
		}
	}()
	ran := false
	res, _ := callSupport(&Server{}, "mctl_get_service_status", map[string]any{"team": "labs", "service": "x"},
		func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			ran = true
			return mcplib.NewToolResultText("ok"), nil
		})
	if ran || !res.IsError {
		t.Fatal("a support call was served with no auditor")
	}
}
