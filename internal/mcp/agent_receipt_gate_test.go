package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

type fakeReceiptVerifier struct {
	code    string
	checks  []ReceiptCheck
	audited []ReceiptOutcome
}

func (f *fakeReceiptVerifier) VerifyAgentReceipt(_ context.Context, _ *auth.User, c ReceiptCheck) string {
	f.checks = append(f.checks, c)
	return f.code
}

func (f *fakeReceiptVerifier) AuditAgentReceipt(_ context.Context, _ *auth.User, o ReceiptOutcome) {
	f.audited = append(f.audited, o)
}

// runGate calls the middleware once and reports whether the wrapped handler
// ran, with the arguments it saw.
func runGate(t *testing.T, s *Server, user *auth.User, tool string, args map[string]any) (*mcplib.CallToolResult, bool, map[string]any) {
	t.Helper()
	ctx := context.Background()
	if user != nil {
		ctx = auth.WithUser(ctx, user)
	}
	req := mcplib.CallToolRequest{}
	req.Params.Name = tool
	req.Params.Arguments = args
	ran := false
	var seen map[string]any
	res, err := s.agentReceiptMiddleware(func(_ context.Context, r mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran = true
		seen = r.GetArguments()
		return mcplib.NewToolResultText("ok"), nil
	})(ctx, req)
	if err != nil {
		t.Fatalf("middleware error: %v", err)
	}
	return res, ran, seen
}

func receiptArgs() map[string]any {
	return map[string]any{
		"service":                     "web",
		ArgActionApprovalRef:          " aar_1 ",
		ArgActionApprovalArtifactHash: "sha256:abc",
	}
}

func gatedServer(mode AgentReceiptGateMode, code string) (*Server, *fakeReceiptVerifier) {
	v := &fakeReceiptVerifier{code: code}
	s := &Server{}
	s.SetAgentReceiptGate(v, mode)
	return s, v
}

func TestParseAgentReceiptGateMode(t *testing.T) {
	for raw, want := range map[string]AgentReceiptGateMode{
		"": AgentReceiptGateOff, "off": AgentReceiptGateOff, "observe": AgentReceiptGateObserve, "enforce": AgentReceiptGateEnforce,
	} {
		got, err := ParseAgentReceiptGateMode(raw)
		if err != nil || got != want {
			t.Errorf("ParseAgentReceiptGateMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if got, err := ParseAgentReceiptGateMode("\tobserve\n"); err != nil || got != AgentReceiptGateObserve {
		t.Errorf("surrounding whitespace: %q, %v", got, err)
	}
	for _, raw := range []string{"on", "Enforce", "true", "enforced"} {
		if _, err := ParseAgentReceiptGateMode(raw); err == nil {
			t.Errorf("ParseAgentReceiptGateMode(%q) accepted an unknown mode", raw)
		}
	}
}

func TestAgentReceiptGate_OffStripsArgsAndChecksNothing(t *testing.T) {
	s, v := gatedServer(AgentReceiptGateOff, ReceiptCodeNotFound)
	_, ran, seen := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", receiptArgs())
	if !ran {
		t.Fatal("off must not refuse")
	}
	if _, ok := seen[ArgActionApprovalRef]; ok {
		t.Fatal("reserved argument reached the handler")
	}
	if _, ok := seen[ArgActionApprovalArtifactHash]; ok {
		t.Fatal("reserved argument reached the handler")
	}
	if seen["service"] != "web" {
		t.Fatalf("ordinary argument lost: %v", seen)
	}
	if len(v.checks)+len(v.audited) != 0 {
		t.Fatalf("off consulted the verifier: %+v %+v", v.checks, v.audited)
	}
}

func TestAgentReceiptGate_StripsArgsForEveryone(t *testing.T) {
	s, _ := gatedServer(AgentReceiptGateEnforce, "")
	_, ran, seen := runGate(t, s, auth.NewGitHubUser("alice", nil), "mctl_get_service_status", receiptArgs())
	if !ran {
		t.Fatal("ungated call refused")
	}
	if _, ok := seen[ArgActionApprovalRef]; ok {
		t.Fatal("reserved argument reached the handler")
	}
}

func TestAgentReceiptGate_ObserveMissingRunsAndAudits(t *testing.T) {
	s, v := gatedServer(AgentReceiptGateObserve, "")
	_, ran, _ := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", map[string]any{"service": "web"})
	if !ran {
		t.Fatal("observe refused a call")
	}
	if len(v.checks) != 0 {
		t.Fatal("verified a receipt that was not presented")
	}
	if len(v.audited) != 1 || v.audited[0].Code != ReceiptCodeMissing || v.audited[0].Refused || v.audited[0].Mode != AgentReceiptGateObserve {
		t.Fatalf("audit = %+v", v.audited)
	}
}

func TestAgentReceiptGate_ObserveChecksWithoutSpending(t *testing.T) {
	s, v := gatedServer(AgentReceiptGateObserve, ReceiptCodeArtifactMismatch)
	_, ran, _ := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", receiptArgs())
	if !ran {
		t.Fatal("observe refused a call")
	}
	if len(v.checks) != 1 || v.checks[0].Redeem {
		t.Fatalf("observe must check read-only: %+v", v.checks)
	}
	if v.audited[0].Code != ReceiptCodeArtifactMismatch || v.audited[0].Refused {
		t.Fatalf("audit = %+v", v.audited)
	}
}

func TestAgentReceiptGate_EnforceRefusesMissing(t *testing.T) {
	s, v := gatedServer(AgentReceiptGateEnforce, "")
	res, ran, _ := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", map[string]any{"service": "web"})
	if ran {
		t.Fatal("enforce ran a governed call without a receipt")
	}
	if !res.IsError || !strings.Contains(resultText(t, res), ReceiptCodeMissing) {
		t.Fatalf("result = %+v", res)
	}
	if len(v.audited) != 1 || !v.audited[0].Refused {
		t.Fatalf("audit = %+v", v.audited)
	}
}

func TestAgentReceiptGate_EnforceRefusesEachVerifierCode(t *testing.T) {
	for _, code := range []string{
		ReceiptCodeNotFound, ReceiptCodeOperationMismatch, ReceiptCodeTargetMismatch, ReceiptCodeNotConsumed,
		ReceiptCodeAlreadyExecuted, ReceiptCodeArtifactMismatch, ReceiptCodeUnverifiable,
	} {
		s, _ := gatedServer(AgentReceiptGateEnforce, code)
		res, ran, _ := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", receiptArgs())
		if ran || !res.IsError || !strings.Contains(resultText(t, res), code) {
			t.Errorf("%s: ran=%v result=%+v", code, ran, res)
		}
	}
}

func TestAgentReceiptGate_EnforceRunsWithValidReceipt(t *testing.T) {
	s, v := gatedServer(AgentReceiptGateEnforce, "")
	_, ran, seen := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", receiptArgs())
	if !ran {
		t.Fatal("valid receipt refused")
	}
	if _, ok := seen[ArgActionApprovalRef]; ok {
		t.Fatal("reserved argument reached the handler")
	}
	want := ReceiptCheck{Tool: "mctl_deploy_service", Ref: "aar_1", ArtifactHash: "sha256:abc", Redeem: true}
	if len(v.checks) != 1 || v.checks[0] != want {
		t.Fatalf("checks = %+v, want %+v", v.checks, want)
	}
	if len(v.audited) != 1 || v.audited[0].Code != "" || v.audited[0].Refused {
		t.Fatalf("audit = %+v", v.audited)
	}
}

func TestAgentReceiptGate_OnlyDirectAgentPrincipalIsGated(t *testing.T) {
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"anonymous": nil,
		"human":     auth.NewGitHubUser("alice", []string{"admins"}),
		"lookalike": auth.NewGitHubUser(auth.ServiceUserID, []string{"admins"}),
		"surface":   surface,
		"relayed":   auth.NewRelayedUser("alice", nil, surface),
		"agent":     auth.NewAgentUser("investigator", auth.AgentRun{}),
	} {
		s, v := gatedServer(AgentReceiptGateEnforce, ReceiptCodeNotFound)
		_, ran, _ := runGate(t, s, u, "mctl_deploy_service", nil)
		if !ran || len(v.checks)+len(v.audited) != 0 {
			t.Errorf("%s: gated (ran=%v checks=%d audits=%d)", name, ran, len(v.checks), len(v.audited))
		}
	}
}

func TestAgentReceiptGate_UngovernedToolsPass(t *testing.T) {
	for _, tool := range []string{"mctl_get_service_status", "mctl_whoami", "mctl_resolve_incident", "mctl_list_services"} {
		s, v := gatedServer(AgentReceiptGateEnforce, ReceiptCodeNotFound)
		_, ran, _ := runGate(t, s, auth.NewServiceUser(), tool, nil)
		if !ran || len(v.audited) != 0 {
			t.Errorf("%s: gated", tool)
		}
	}
}

// Every registered tool is classified exactly once, so a new tool cannot
// silently escape the gate (or be gated by accident).
func TestAgentReceiptGate_ClassifiesEveryTool(t *testing.T) {
	srv := NewServer("http://localhost:8080", "").NewMCPServer()
	registered := map[string]bool{}
	for name := range srv.ListTools() {
		registered[name] = true
		_, governed := governedAgentTools[name]
		_, ungoverned := ungovernedAgentTools[name]
		read := isAgentReadTool(name)
		n := 0
		for _, b := range []bool{governed, ungoverned, read} {
			if b {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: governed=%v ungoverned=%v read=%v; want exactly one", name, governed, ungoverned, read)
		}
	}
	for name := range governedAgentTools {
		if !registered[name] {
			t.Errorf("governed tool %s is not registered", name)
		}
	}
	for name := range ungovernedAgentTools {
		if !registered[name] {
			t.Errorf("ungoverned tool %s is not registered", name)
		}
	}
}

// The gate is on the real tools/call path, ahead of the tool handler.
func TestAgentReceiptGate_RegisteredOnServer(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	v := &fakeReceiptVerifier{}
	s.SetAgentReceiptGate(v, AgentReceiptGateEnforce)
	srv := s.NewMCPServer()
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "mctl_scale_service", "arguments": map[string]any{"team": "t", "service": "web", "replicas": 2}},
	})
	b, _ := json.Marshal(srv.HandleMessage(auth.WithUser(context.Background(), auth.NewServiceUser()), req))
	if !strings.Contains(string(b), ReceiptCodeMissing) {
		t.Fatalf("response = %s", b)
	}
	if len(v.audited) != 1 || !v.audited[0].Refused {
		t.Fatalf("audit = %+v", v.audited)
	}
}

// A receipt of the wrong shape is refused before the store or the audit
// row sees it.
func TestAgentReceiptGate_MalformedReceiptNeverReachesTheStore(t *testing.T) {
	for name, args := range map[string]map[string]any{
		"no prefix":      {ArgActionApprovalRef: "wi_123", ArgActionApprovalArtifactHash: "sha256:x"},
		"prefix only":    {ArgActionApprovalRef: "aar_", ArgActionApprovalArtifactHash: "sha256:x"},
		"bad characters": {ArgActionApprovalRef: "aar_1' OR 1=1", ArgActionApprovalArtifactHash: "sha256:x"},
		"ref too long":   {ArgActionApprovalRef: "aar_" + strings.Repeat("a", maxReceiptRefBytes), ArgActionApprovalArtifactHash: "sha256:x"},
		"hash too long":  {ArgActionApprovalRef: "aar_1", ArgActionApprovalArtifactHash: strings.Repeat("a", maxReceiptHashBytes+1)},
		"hash control":   {ArgActionApprovalRef: "aar_1", ArgActionApprovalArtifactHash: "sha256:\x01x"},
	} {
		s, v := gatedServer(AgentReceiptGateEnforce, "")
		res, ran, _ := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", args)
		if ran || !res.IsError || !strings.Contains(resultText(t, res), ReceiptCodeMalformed) {
			t.Errorf("%s: ran=%v result=%+v", name, ran, res)
		}
		if len(v.checks) != 0 {
			t.Errorf("%s: malformed receipt reached the verifier: %+v", name, v.checks)
		}
		if len(v.audited) != 1 || v.audited[0].Ref != "" || v.audited[0].Code != ReceiptCodeMalformed ||
			v.audited[0].Malformed != DescribeMalformedReceipt(args[ArgActionApprovalRef].(string), args[ArgActionApprovalArtifactHash].(string)) {
			t.Errorf("%s: audit = %+v", name, v.audited)
		}
	}
	// The longest well-formed values still pass.
	s, v := gatedServer(AgentReceiptGateEnforce, "")
	_, ran, _ := runGate(t, s, auth.NewServiceUser(), "mctl_deploy_service", map[string]any{
		ArgActionApprovalRef:          "aar_" + strings.Repeat("a", maxReceiptRefBytes-len(receiptRefPrefix)),
		ArgActionApprovalArtifactHash: strings.Repeat("a", maxReceiptHashBytes),
	})
	if !ran || len(v.checks) != 1 {
		t.Fatalf("well-formed receipt at the limits refused (ran=%v checks=%d)", ran, len(v.checks))
	}
}

// The wire path: mcp-go decodes params.arguments itself, so this pins that
// the receipt is read from, and removed from, what a real tools/call
// carries, in both the decoded map and the raw bytes a handler could read.
func TestAgentReceiptGate_WireLevelStripping(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	v := &fakeReceiptVerifier{}
	s.SetAgentReceiptGate(v, AgentReceiptGateEnforce)
	srv := s.NewMCPServer()
	var seen mcplib.CallToolRequest
	ran := false
	// Replace a governed tool's handler with one that records its request.
	srv.AddTool(mcplib.NewTool("mctl_deploy_service"), func(_ context.Context, r mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran, seen = true, r
		return mcplib.NewToolResultText("ok"), nil
	})
	b := handleCall(t, srv, auth.NewServiceUser(), "mctl_deploy_service", map[string]any{
		"service": "web", ArgActionApprovalRef: "aar_abc", ArgActionApprovalArtifactHash: "sha256:abc",
	})
	if !ran {
		t.Fatalf("valid receipt refused: %s", b)
	}
	want := ReceiptCheck{Tool: "mctl_deploy_service", Ref: "aar_abc", ArtifactHash: "sha256:abc", Redeem: true}
	if len(v.checks) != 1 || v.checks[0] != want {
		t.Fatalf("checks = %+v, want %+v", v.checks, want)
	}
	args := seen.GetArguments()
	if _, ok := args[ArgActionApprovalRef]; ok || args["service"] != "web" {
		t.Fatalf("handler arguments = %v", args)
	}
	if raw, err := json.Marshal(seen.Params); err != nil || strings.Contains(string(raw), "aar_abc") || strings.Contains(string(raw), "sha256:abc") {
		t.Fatalf("receipt still reachable from the request params: %s (%v)", raw, err)
	}
}

func handleCall(t *testing.T, srv *server.MCPServer, u *auth.User, name string, args map[string]any) []byte {
	t.Helper()
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(srv.HandleMessage(auth.WithUser(context.Background(), u), req))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The gate's shape check refuses anything without the store's id prefix
// before the store is read, so the two must agree. This runs without a
// database, unlike the store-backed id test in internal/api.
func TestReceiptRefPrefixMatchesTheStore(t *testing.T) {
	if receiptRefPrefix != workitems.ActionApprovalIDPrefix {
		t.Fatalf("receiptRefPrefix %q != workitems.ActionApprovalIDPrefix %q", receiptRefPrefix, workitems.ActionApprovalIDPrefix)
	}
}

func TestDescribeMalformedReceipt(t *testing.T) {
	long := "aar_" + strings.Repeat("ab", 40)
	cases := []struct {
		name, ref, hash, want string
	}{
		{"no prefix", "xyz_123", "h", `prefix=false ref_len=7 head="xyz" hash_len=1`},
		{"too long", long, "", `prefix=true ref_len=84 head="abababab" hash_len=0`},
		{"bad char", "aar_ab-cd", "sha256:x", `prefix=true ref_len=9 head="ab" hash_len=8`},
		{"prefix only", "aar_", "", `prefix=true ref_len=4 head="" hash_len=0`},
		{"no alnum echoed", "<script>", "", `prefix=false ref_len=8 head="" hash_len=0`},
		{"bad hash", "aar_" + strings.Repeat("0", 32), "sha256:\x01", `prefix=true ref_len=36 head="00000000" hash_len=8`},
	}
	for _, c := range cases {
		if got := DescribeMalformedReceipt(c.ref, c.hash); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// The gate passes agent principals (run tokens) through because their
// scope refuses every governed tool first. A scope that admits one would
// reach the tool with no receipt at all, so no scope may.
func TestAgentScopesAdmitNoGovernedTool(t *testing.T) {
	// TestAgentReceiptGate_ClassifiesEveryTool holds every governed tool to
	// a registered one, so the governed set is the whole surface to check.
	if len(governedAgentTools) == 0 {
		t.Fatal("no governed tool is defined: the check proves nothing")
	}
	scopes := auth.AgentScopeNames()
	if len(scopes) == 0 {
		t.Fatal("no agent scope is defined: the check proves nothing")
	}
	for _, name := range scopes {
		scope, ok := auth.LookupAgentScope(name)
		if !ok {
			t.Fatalf("scope %q is listed but cannot be looked up", name)
		}
		for tool := range governedAgentTools {
			for _, spelling := range []string{tool, strings.TrimPrefix(tool, "mctl_")} {
				if scope.AllowsTool(spelling) {
					t.Errorf("scope %q admits governed tool %s: agent principals are not receipt-gated, so extend the gate before granting it", name, spelling)
				}
			}
		}
	}
}
