package mcp

import (
	"context"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func runScope(t *testing.T, ctx context.Context, tool string) (*mcplib.CallToolResult, bool) {
	t.Helper()
	req := mcplib.CallToolRequest{}
	req.Params.Name = tool
	ran := false
	res, err := (&Server{}).agentScopeMiddleware(func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
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
	for _, tool := range []string{"mctl_resolve_incident", "mctl_deploy_service", "mctl_trigger_issue"} {
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
