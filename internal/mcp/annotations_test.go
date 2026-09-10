package mcp

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// hints is one tool's declared side-effect profile.
type hints struct {
	readOnly    bool
	destructive bool
	idempotent  bool
}

// recordedHints is the record the portal allowlist is derived from
// (mctlhq/mctl-api#276): every tool the server registers, with the two hints
// it declares. It is data on purpose -- a change to any tool's classification
// is a visible diff here, never a side effect of editing a tool -- and the
// runtime set must equal it exactly: no tool missing, none unrecorded, none
// with a different profile.
var recordedHints = map[string]hints{
	"mctl_acknowledge_incident":               {readOnly: false, destructive: false, idempotent: true},
	"mctl_add_custom_domain":                  {readOnly: false, destructive: false, idempotent: true},
	"mctl_apply_openclaw_resource_profile":    {readOnly: false, destructive: false, idempotent: true},
	"mctl_approve_dev_loop":                   {readOnly: false, destructive: false, idempotent: false},
	"mctl_create_agent":                       {readOnly: false, destructive: false, idempotent: false},
	"mctl_create_preview":                     {readOnly: false, destructive: false, idempotent: false},
	"mctl_create_tenant":                      {readOnly: false, destructive: false, idempotent: false},
	"mctl_delete_openclaw_identity":           {readOnly: false, destructive: true, idempotent: true},
	"mctl_delete_openclaw_skill":              {readOnly: false, destructive: true, idempotent: true},
	"mctl_delete_preview":                     {readOnly: false, destructive: true, idempotent: false},
	"mctl_delete_tenant":                      {readOnly: false, destructive: true, idempotent: false},
	"mctl_deploy_openclaw":                    {readOnly: false, destructive: false, idempotent: false},
	"mctl_deploy_service":                     {readOnly: false, destructive: false, idempotent: false},
	"mctl_deprecate_platform_skill":           {readOnly: false, destructive: true, idempotent: false},
	"mctl_disable_tenant_skill":               {readOnly: false, destructive: true, idempotent: false},
	"mctl_enable_tenant_skill":                {readOnly: false, destructive: false, idempotent: true},
	"mctl_get_dev_loop":                       {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_incident":                       {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_openclaw_sizing_recommendation": {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_operation":                      {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_resource_usage":                 {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_service_config":                 {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_service_logs":                   {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_service_status":                 {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_tenant":                         {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_workflow_logs":                  {readOnly: true, destructive: false, idempotent: false},
	"mctl_get_workflow_status":                {readOnly: true, destructive: false, idempotent: false},
	"mctl_grant_repo_access":                  {readOnly: false, destructive: false, idempotent: true},
	"mctl_incident_summary":                   {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_agent_executions":              {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_agent_versions":                {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_domains":                       {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_incidents":                     {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_openclaw_identity":             {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_openclaw_skills":               {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_operations":                    {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_platform_skills":               {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_previews":                      {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_recent_agent_runs":             {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_recent_operations":             {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_repos":                         {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_services":                      {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_tenant_skill_bindings":         {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_tenants":                       {readOnly: true, destructive: false, idempotent: false},
	"mctl_list_workflows":                     {readOnly: true, destructive: false, idempotent: false},
	"mctl_promote_agent":                      {readOnly: false, destructive: true, idempotent: false},
	"mctl_provision_database":                 {readOnly: false, destructive: false, idempotent: false},
	"mctl_publish_agent_version":              {readOnly: false, destructive: false, idempotent: false},
	"mctl_publish_platform_skill":             {readOnly: false, destructive: false, idempotent: true},
	"mctl_read_openclaw_identity":             {readOnly: true, destructive: false, idempotent: false},
	"mctl_read_openclaw_skill":                {readOnly: true, destructive: false, idempotent: false},
	"mctl_read_platform_skill":                {readOnly: true, destructive: false, idempotent: false},
	"mctl_remove_custom_domain":               {readOnly: false, destructive: true, idempotent: false},
	"mctl_resolve_agent":                      {readOnly: true, destructive: false, idempotent: false},
	"mctl_resolve_incident":                   {readOnly: false, destructive: false, idempotent: true},
	"mctl_resume_openclaw_deploy":             {readOnly: false, destructive: false, idempotent: false},
	"mctl_retire_service":                     {readOnly: false, destructive: true, idempotent: false},
	"mctl_rollback_agent":                     {readOnly: false, destructive: true, idempotent: false},
	"mctl_rollback_service":                   {readOnly: false, destructive: true, idempotent: false},
	"mctl_save_openclaw_identity":             {readOnly: false, destructive: false, idempotent: true},
	"mctl_save_openclaw_skill":                {readOnly: false, destructive: false, idempotent: true},
	"mctl_scale_service":                      {readOnly: false, destructive: false, idempotent: true},
	"mctl_sync_repos":                         {readOnly: false, destructive: false, idempotent: true},
	"mctl_trigger_agents_run":                 {readOnly: false, destructive: false, idempotent: false},
	"mctl_trigger_approve":                    {readOnly: false, destructive: true, idempotent: true},
	"mctl_trigger_implementer":                {readOnly: false, destructive: true, idempotent: false},
	"mctl_trigger_incident_responder":         {readOnly: false, destructive: false, idempotent: false},
	"mctl_trigger_issue":                      {readOnly: false, destructive: false, idempotent: false},
	"mctl_trigger_mentor_only":                {readOnly: false, destructive: false, idempotent: false},
	"mctl_trigger_reconcile":                  {readOnly: false, destructive: true, idempotent: false},
	"mctl_trigger_shepherd":                   {readOnly: false, destructive: true, idempotent: false},
	"mctl_trigger_single_service":             {readOnly: false, destructive: false, idempotent: false},
	"mctl_verify_domain":                      {readOnly: false, destructive: false, idempotent: false},
	"mctl_whoami":                             {readOnly: true, destructive: false, idempotent: false},
}

// TestEveryToolMatchesTheRecordedHints holds the registered tools to the
// table above, and holds the table to a shape a portal can reason from: a
// tool is never both read-only and destructive.
func TestEveryToolMatchesTheRecordedHints(t *testing.T) {
	tools := NewServer("http://localhost:8080", "").NewMCPServer().ListTools()
	if len(tools) != len(recordedHints) {
		t.Errorf("server registers %d tools, the record has %d", len(tools), len(recordedHints))
	}
	var problems []string
	for name, st := range tools {
		a := st.Tool.Annotations
		got := hints{
			readOnly:    a.ReadOnlyHint != nil && *a.ReadOnlyHint,
			destructive: a.DestructiveHint != nil && *a.DestructiveHint,
			idempotent:  a.IdempotentHint != nil && *a.IdempotentHint,
		}
		want, ok := recordedHints[name]
		switch {
		case !ok:
			problems = append(problems, name+": registered but not recorded")
		case got != want:
			problems = append(problems, name+": declares "+describe(got)+", recorded "+describe(want))
		case got.readOnly && got.destructive:
			problems = append(problems, name+": read-only and destructive at once")
		}
	}
	for name := range recordedHints {
		if _, ok := tools[name]; !ok {
			problems = append(problems, name+": recorded but not registered")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("tool hints differ from the record:\n  %s", strings.Join(problems, "\n  "))
	}
}

func describe(h hints) string {
	return "readOnly=" + boolString(h.readOnly) + " destructive=" + boolString(h.destructive) + " idempotent=" + boolString(h.idempotent)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestEveryToolDeclaresBothHintsInSource is the half the runtime cannot see.
// Every tool names readOnly and destructive; every mutating tool also names
// idempotent.
// mcp-go fills an absent hint with a default (readOnly=false,
// destructive=true), so a tool that declares nothing still carries a
// well-formed profile at runtime and would satisfy the table above if that
// default happened to match. The declaration has to be checked where it is
// made: every mcplib.NewTool call in server.go names both hints.
func TestEveryToolDeclaresBothHintsInSource(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	nameRe := regexp.MustCompile(`NewTool\("([a-z0-9_]+)"`)
	parts := strings.Split(string(src), "mcplib.NewTool(")
	var missing []string
	seen := 0
	for _, part := range parts[1:] {
		end := strings.Index(part, "\n\t)")
		if end < 0 {
			end = len(part)
		}
		block := part[:end]
		m := nameRe.FindStringSubmatch("NewTool(" + block)
		if m == nil {
			t.Fatalf("a NewTool call without a literal name: %.60q", block)
		}
		seen++
		if !strings.Contains(block, "WithReadOnlyHintAnnotation(") {
			missing = append(missing, m[1]+": no readOnlyHint")
		}
		if !strings.Contains(block, "WithDestructiveHintAnnotation(") {
			missing = append(missing, m[1]+": no destructiveHint")
		}
		// A mutating tool says whether a repeat is a no-op; for a read-only
		// tool the question does not arise and the hint is left unstated.
		if strings.Contains(block, "WithReadOnlyHintAnnotation(false)") && !strings.Contains(block, "WithIdempotentHintAnnotation(") {
			missing = append(missing, m[1]+": mutating without idempotentHint")
		}
	}
	if seen != len(recordedHints) {
		t.Errorf("found %d NewTool calls in server.go, the record has %d", seen, len(recordedHints))
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("tools that rely on a library default instead of declaring a hint:\n  %s", strings.Join(missing, "\n  "))
	}
}

// TestReadOnlyToolsAreTheRecordedSet is the list the portal's allowlist for
// this server is pinned from: exactly the tools recorded above as read-only,
// spelled out so the allowlist can be copied rather than derived.
func TestReadOnlyToolsAreTheRecordedSet(t *testing.T) {
	want := []string{
		"mctl_get_dev_loop", "mctl_get_incident", "mctl_get_openclaw_sizing_recommendation", "mctl_get_operation",
		"mctl_get_resource_usage", "mctl_get_service_config", "mctl_get_service_logs", "mctl_get_service_status",
		"mctl_get_tenant", "mctl_get_workflow_logs", "mctl_get_workflow_status", "mctl_incident_summary",
		"mctl_list_agent_executions", "mctl_list_agent_versions", "mctl_list_domains", "mctl_list_incidents",
		"mctl_list_openclaw_identity", "mctl_list_openclaw_skills", "mctl_list_operations", "mctl_list_platform_skills",
		"mctl_list_previews", "mctl_list_recent_agent_runs", "mctl_list_recent_operations", "mctl_list_repos",
		"mctl_list_services", "mctl_list_tenant_skill_bindings", "mctl_list_tenants", "mctl_list_workflows",
		"mctl_read_openclaw_identity", "mctl_read_openclaw_skill", "mctl_read_platform_skill", "mctl_resolve_agent",
		"mctl_whoami",
	}
	var got []string
	for name, h := range recordedHints {
		if h.readOnly {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("read-only set differs:\n got  %v\n want %v", got, want)
	}
}
