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
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestParseStatsQuantities(t *testing.T) {
	if got := parseCPUCores("500m"); math.Abs(got-0.5) > 0.0001 {
		t.Fatalf("500m = %v", got)
	}
	if got := parseCPUCores("2"); got != 2 {
		t.Fatalf("2 cpu = %v", got)
	}
	if got := parseMemoryMiB("512Mi"); got != 512 {
		t.Fatalf("512Mi = %v", got)
	}
	if got := parseMemoryMiB("1Gi"); got != 1024 {
		t.Fatalf("1Gi = %v", got)
	}
	if got := parseMemoryMiB("128Ki"); math.Abs(got-0.125) > 0.0001 {
		t.Fatalf("128Ki = %v", got)
	}
	q := quotaFromMaps(
		map[string]string{"limits.cpu": "500m", "limits.memory": "512Mi", "pods": "3"},
		map[string]string{"limits.cpu": "2", "limits.memory": "1Gi", "pods": "10", "services": "5"},
	)
	if math.Abs(q.CPULimU-0.5) > 0.0001 || q.CPULimA != 2 || q.MemLimU != 512 || q.MemLimA != 1024 || q.PodsU != 3 || q.PodsA != 10 || q.SvcA != 5 {
		t.Fatalf("quota = %+v", q)
	}
}

func TestNormalizeStatsFilterAndNamespace(t *testing.T) {
	for _, in := range []string{"", "  ", "all", "ALL", "*"} {
		if got := normalizeStatsFilter(in); got != "" {
			t.Fatalf("%q -> %q", in, got)
		}
	}
	if got := normalizeStatsFilter(" labs "); got != "labs" {
		t.Fatalf("labs filter = %q", got)
	}
	tenant := apiTenant{Name: "labs", Teams: []apiTeam{{Name: "a"}}}
	if !tenantMatchesNamespace(tenant, "labs") || !tenantMatchesNamespace(tenant, "labs-a") {
		t.Fatal("expected namespace matches")
	}
	if tenantMatchesNamespace(tenant, "karabu") {
		t.Fatal("karabu must not match labs")
	}
}

func TestStatsViewHasNoNetworkAndSpeaksTheBridge(t *testing.T) {
	for _, banned := range []string{"fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "http://", "https://", "new Image"} {
		if strings.Contains(statsViewHTML, banned) {
			t.Errorf("embedded view contains %q", banned)
		}
	}
	for _, need := range []string{
		"ui/notifications/tool-result",
		"tools/call",
		"mctl_stats_dashboard",
		"connect-src 'none'",
		"text/html;profile=mcp-app",
		"ui://mctl-stats/view.html",
	} {
		if !strings.Contains(statsViewHTML, need) {
			t.Errorf("embedded view missing %q", need)
		}
	}
}

func TestStatsResourceAndToolRegistration(t *testing.T) {
	srv := NewServer("http://localhost:8080", "").NewMCPServer()

	list := mcpResult(t, srv, "resources/list", nil)
	resources, _ := list["resources"].([]any)
	var found bool
	for _, item := range resources {
		res, _ := item.(map[string]any)
		if res["uri"] != statsAppURI {
			continue
		}
		found = true
		if res["mimeType"] != statsAppMIME {
			t.Errorf("mimeType = %v", res["mimeType"])
		}
		meta := metaUI(t, res["_meta"])
		csp := mapField(t, meta, "csp")
		assertEmptyList(t, csp["connectDomains"])
		assertEmptyList(t, csp["resourceDomains"])
	}
	if !found {
		t.Fatal("ui://mctl-stats/view.html is not registered")
	}

	read := mcpResult(t, srv, "resources/read", map[string]any{"uri": statsAppURI})
	contents, _ := read["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("contents = %#v", read["contents"])
	}
	body, _ := contents[0].(map[string]any)
	if body["mimeType"] != statsAppMIME {
		t.Errorf("read mime = %v", body["mimeType"])
	}
	text, _ := body["text"].(string)
	if text != statsViewHTML {
		t.Fatal("resource text is not the embedded view")
	}
	meta := metaUI(t, body["_meta"])
	assertEmptyList(t, mapField(t, meta, "csp")["connectDomains"])

	tools := mcpResult(t, srv, "tools/list", nil)
	listed, _ := tools["tools"].([]any)
	var tool map[string]any
	for _, item := range listed {
		one, _ := item.(map[string]any)
		if one["name"] == "mctl_stats_dashboard" {
			tool = one
		}
	}
	if tool == nil {
		t.Fatal("mctl_stats_dashboard is not registered")
	}
	ui := metaUI(t, tool["_meta"])
	if ui["resourceUri"] != statsAppURI {
		t.Errorf("resourceUri = %v", ui["resourceUri"])
	}
	ann, _ := tool["annotations"].(map[string]any)
	if ann["readOnlyHint"] != true {
		t.Errorf("readOnlyHint = %v", ann["readOnlyHint"])
	}
	if ann["destructiveHint"] != false {
		t.Errorf("destructiveHint = %v", ann["destructiveHint"])
	}
}

func TestStatsDashboard_AdminAggregatesScopedData(t *testing.T) {
	fake := newStatsFake(t, statsFakeOpts{admin: true})
	srv := fake.server(t)
	defer srv.Close()

	res := callStats(t, srv.URL, nil)
	d := decodeDash(t, res)
	text := toolResultText(res)
	if d.Meta.APIBase != "" {
		t.Errorf("loopback api base leaked: %q", d.Meta.APIBase)
	}
	if strings.Contains(text, srv.URL) || strings.Contains(text, "127.0.0.1") {
		t.Errorf("summary leaks upstream: %s", text)
	}
	if !strings.Contains(text, "mashkovd") || !strings.Contains(text, "Read-only") {
		t.Errorf("summary = %s", text)
	}
	if !d.Meta.Admin || !d.Meta.Live {
		t.Fatalf("meta = %+v", d.Meta)
	}
	if len(d.Tenants) != 2 {
		t.Fatalf("tenants = %+v", namesOf(d))
	}
	labs := findTenant(d, "labs")
	if math.Abs(labs.Quota.CPULimU-0.5) > 0.001 || labs.Quota.CPULimA != 2 || labs.Quota.MemLimU != 512 || labs.Quota.MemLimA != 1024 {
		t.Fatalf("labs quota = %+v", labs.Quota)
	}
	if labs.Members != 1 || !strings.Contains(labs.Roles, "mashkovd") || !labs.Egress.Internet {
		t.Fatalf("labs identity = %+v", labs)
	}
	if labs.Previews == nil || *labs.Previews != 2 || labs.Repos == nil || *labs.Repos != 3 || labs.Domains == nil || *labs.Domains != 1 {
		t.Fatalf("labs counts previews=%v repos=%v domains=%v", labs.Previews, labs.Repos, labs.Domains)
	}
	if len(d.Services) != 2 {
		t.Fatalf("services = %+v", d.Services)
	}
	web := findService(d, "labs", "web")
	if web.SyncStatus != "Synced" || web.Health != "Healthy" || !web.Deployed || web.ArgoApp != "labs-web" || len(web.Hosts) != 1 || web.Hosts[0] != "web.example" {
		t.Fatalf("web = %+v", web)
	}
	draw := findService(d, "karabu", "draw")
	if draw.SyncStatus != "Unknown" || draw.Deployed {
		t.Fatalf("draw = %+v", draw)
	}
	if len(d.Incidents.Active) != 2 {
		t.Fatalf("active = %+v", d.Incidents.Active)
	}
	for _, inc := range d.Incidents.Active {
		if inc.Tenant == "other" || inc.Status == "resolved" {
			t.Fatalf("active incident leaked: %+v", inc)
		}
	}
	var noted bool
	for _, inc := range d.Incidents.Active {
		if inc.Tenant == "labs" && strings.Contains(inc.LiveArgoNote, "Healthy") && strings.Contains(inc.LiveArgoNote, "Synced") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("missing live argo note: %+v", d.Incidents.Active)
	}
	if d.Incidents.ResolvedSummary.Count != 3 || d.Incidents.ResolvedSummary.BySeverity["warning"] != 2 || d.Incidents.ResolvedSummary.BySeverity["critical"] != 1 {
		t.Fatalf("resolved = %+v", d.Incidents.ResolvedSummary)
	}
	if !d.Usage.Available || math.Abs(d.Usage.Totals.CalculatedCost-2) > 0.001 || d.Usage.Totals.Invocations != 3 || d.Usage.Totals.Success != 2 || d.Usage.Totals.Error != 1 {
		t.Fatalf("usage = %+v", d.Usage.Totals)
	}
	if d.Usage.Totals.ProviderReportedCost != nil || d.Usage.Totals.InvoiceReconciledCost != nil {
		t.Fatal("null cost columns were invented")
	}
	if !d.Agents.Available || len(d.Agents.Registry) != 1 || d.Agents.Registry[0].V1 != 3 || d.Agents.Registry[0].V1Alpha2 != 1 {
		t.Fatalf("registry = %+v", d.Agents.Registry)
	}
	if len(d.Agents.Profiles) != 1 || d.Agents.Profiles[0].BudgetUsd == nil || *d.Agents.Profiles[0].BudgetUsd != 20 || d.Agents.Profiles[0].TimeoutSeconds != 600 || d.Agents.Profiles[0].ToolsCount != 9 {
		t.Fatalf("profile = %+v", d.Agents.Profiles)
	}
	if len(d.Agents.Releases) != 1 || d.Agents.Releases[0].Environment != "shadow" || d.Agents.Releases[0].DefVersion != "3" {
		t.Fatalf("release = %+v", d.Agents.Releases)
	}
	if d.Agents.Executions.Count != 2 || len(d.Agents.Ownership.Stuck) != 1 || d.Agents.Ownership.Stuck[0].HoursSinceProgress != 10 {
		t.Fatalf("execs=%+v stuck=%+v", d.Agents.Executions, d.Agents.Ownership.Stuck)
	}
	if d.Agents.RecentRuns.Succeeded != 1 || d.Agents.RecentRuns.Failed != 1 || d.Agents.SkillsCount != 2 {
		t.Fatalf("runs=%+v skills=%d", d.Agents.RecentRuns, d.Agents.SkillsCount)
	}
	if d.Platform.Operations.Count != 2 || d.Platform.Operations.ByScope["admin"] != 1 || d.Platform.Operations.ByRisk["high"] != 1 {
		t.Fatalf("ops = %+v", d.Platform.Operations)
	}
	if len(d.Platform.Domains) != 1 || d.Platform.Domains[0].Domain != "example.com" {
		t.Fatalf("domains = %+v", d.Platform.Domains)
	}
	if len(d.Epics) != 0 || len(d.ReadyItems) != 0 || d.Platform.Commerce.Available || d.Platform.SyncWindows.Available {
		t.Fatal("unavailable sections were fabricated")
	}
	joined := strings.Join(d.Platform.DataGaps, "\n")
	if !strings.Contains(joined, "Дорожная карта") {
		t.Fatalf("gaps = %s", joined)
	}
	fake.assertGETOnly(t)

	filtered := decodeDash(t, callStats(t, srv.URL, map[string]any{"team": "all"}))
	if len(filtered.Tenants) != 2 {
		t.Fatalf(`team "all" narrowed to %v`, namesOf(filtered))
	}
	fake.reset()
	one := decodeDash(t, callStats(t, srv.URL, map[string]any{"namespace": "karabu"}))
	if len(one.Tenants) != 1 || one.Tenants[0].Name != "karabu" {
		t.Fatalf("namespace filter = %v", namesOf(one))
	}
	for _, path := range fake.snapshot() {
		if strings.Contains(path, "/api/v1/resources/labs") || strings.Contains(path, "/api/v1/status/labs/") {
			t.Errorf("namespace filter still read labs: %s", path)
		}
	}
	fake.assertGETOnly(t)
}

func TestStatsDashboard_NonAdminIsScopedAndSkipsAdminReads(t *testing.T) {
	fake := newStatsFake(t, statsFakeOpts{admin: false})
	srv := fake.server(t)
	defer srv.Close()

	d := decodeDash(t, callStats(t, srv.URL, nil))
	if d.Meta.Admin {
		t.Fatal("non-admin marked admin")
	}
	if len(d.Tenants) != 1 || d.Tenants[0].Name != "labs" {
		t.Fatalf("tenants = %v", namesOf(d))
	}
	if len(d.Services) != 1 || d.Services[0].Name != "web" {
		t.Fatalf("services = %+v", d.Services)
	}
	if len(d.Incidents.Active) != 1 || d.Incidents.Active[0].Tenant != "labs" {
		t.Fatalf("active = %+v", d.Incidents.Active)
	}
	if d.Incidents.ResolvedSummary.ByTenant["admins"] != 0 || d.Incidents.ResolvedSummary.Count != 2 {
		t.Fatalf("resolved = %+v", d.Incidents.ResolvedSummary)
	}
	if d.Usage.Available || d.Agents.Available {
		t.Fatal("non-admin received admin-only sections")
	}
	if d.Agents.SkillsCount != 2 {
		t.Fatalf("skills = %d", d.Agents.SkillsCount)
	}
	raw, _ := json.Marshal(d)
	blob := string(raw)
	if strings.Contains(blob, "karabu") || strings.Contains(blob, "secret-svc") || strings.Contains(blob, `"tenant":"admins"`) {
		t.Fatalf("foreign data leaked: %s", blob)
	}
	for _, path := range fake.snapshot() {
		switch {
		case path == "/api/v1/tenants":
			t.Error("non-admin listed every tenant")
		case strings.HasPrefix(path, "/api/v1/usage"):
			t.Error("non-admin read the usage ledger")
		case path == "/api/v1/agents" || strings.HasPrefix(path, "/api/v1/agents/"):
			t.Error("non-admin read the agent registry: " + path)
		case path == "/api/v1/agent-runs" || strings.HasPrefix(path, "/api/v1/lifecycle"):
			t.Error("non-admin read admin lifecycle data: " + path)
		case strings.Contains(path, "karabu"):
			t.Error("non-admin fetched karabu: " + path)
		}
	}
	fake.assertGETOnly(t)

	denied := callStats(t, srv.URL, map[string]any{"team": "karabu"})
	if !denied.IsError || !strings.Contains(toolResultText(denied), "access denied") {
		t.Fatalf("denied = error:%v text:%s", denied.IsError, toolResultText(denied))
	}
}

func TestStatsDashboard_FilterErrors(t *testing.T) {
	fake := newStatsFake(t, statsFakeOpts{admin: true})
	srv := fake.server(t)
	defer srv.Close()

	mismatch := callStats(t, srv.URL, map[string]any{"team": "labs", "namespace": "karabu"})
	if !mismatch.IsError || !strings.Contains(toolResultText(mismatch), "does not match") {
		t.Fatalf("mismatch = %s", toolResultText(mismatch))
	}
	missing := callStats(t, srv.URL, map[string]any{"team": "missing"})
	if !missing.IsError || !strings.Contains(toolResultText(missing), "tenant not found") {
		t.Fatalf("missing = %s", toolResultText(missing))
	}
}

func TestStatsDashboard_QuotaFailureStillReturnsServices(t *testing.T) {
	fake := newStatsFake(t, statsFakeOpts{admin: true, failLabsQuota: true})
	srv := fake.server(t)
	defer srv.Close()

	d := decodeDash(t, callStats(t, srv.URL, map[string]any{"team": "labs"}))
	if len(d.Services) != 1 || d.Services[0].Name != "web" {
		t.Fatalf("services = %+v", d.Services)
	}
	labs := findTenant(d, "labs")
	if labs.Quota.CPULimA != 2 || labs.Quota.CPULimU != 0 {
		t.Fatalf("quota fallback = %+v", labs.Quota)
	}
	if !strings.Contains(strings.Join(d.Platform.DataGaps, "\n"), "Квоты labs") {
		t.Fatalf("gaps = %v", d.Platform.DataGaps)
	}
}

type statsFakeOpts struct {
	admin         bool
	failLabsQuota bool
}

type statsFake struct {
	t    *testing.T
	opts statsFakeOpts
	mu   sync.Mutex
	hits []string
}

func newStatsFake(t *testing.T, opts statsFakeOpts) *statsFake {
	t.Helper()
	return &statsFake{t: t, opts: opts}
}

func (f *statsFake) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(f.serve))
}

func (f *statsFake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits = append(f.hits, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method"}`, http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		f.t.Errorf("auth = %q", got)
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/v1/whoami":
		if f.opts.admin {
			writeResp(w, map[string]any{"id": "mashkovd", "groups": []string{"admins", "labs"}, "isAdmin": true, "namespaces": []string{"admins", "labs"}})
			return
		}
		writeResp(w, map[string]any{"id": "dev", "groups": []string{"labs"}, "isAdmin": false, "namespaces": []string{"labs"}})
	case r.URL.Path == "/api/v1/tenants":
		writeResp(w, map[string]any{"items": []any{labsTenant(), karabuTenant()}, "count": 2})
	case strings.HasPrefix(r.URL.Path, "/api/v1/tenants/"):
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants/")
		switch name {
		case "labs":
			writeResp(w, map[string]any{"tenant": labsTenant()})
		case "karabu":
			writeResp(w, map[string]any{"tenant": karabuTenant()})
		default:
			http.Error(w, `{"error":"tenant not found"}`, http.StatusNotFound)
		}
	case r.URL.Path == "/api/v1/services":
		writeResp(w, map[string]any{"items": []any{
			map[string]any{"team": "labs", "name": "web", "imageTag": "1.2.3", "host": "web.example", "hasDatabase": true},
			map[string]any{"team": "karabu", "name": "draw", "imageTag": "0.1.0", "hasDatabase": false},
			map[string]any{"team": "other", "name": "secret-svc", "imageTag": "x", "hasDatabase": false},
		}})
	case r.URL.Path == "/api/v1/status/labs/web":
		writeResp(w, map[string]any{"argocd": map[string]any{"health": "Healthy", "syncStatus": "Synced"}, "service": map[string]any{}})
	case r.URL.Path == "/api/v1/status/karabu/draw":
		writeResp(w, map[string]any{"argocd": nil, "note": "not deployed"})
	case strings.HasPrefix(r.URL.Path, "/api/v1/resources/"):
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/resources/")
		if name == "labs" && f.opts.failLabsQuota {
			http.Error(w, `{"error":"quota backend down"}`, http.StatusInternalServerError)
			return
		}
		if name == "labs" {
			writeResp(w, map[string]any{
				"tenant": "labs",
				"used": map[string]string{
					"limits.cpu": "500m", "limits.memory": "512Mi", "requests.cpu": "100m",
					"requests.memory": "128Mi", "pods": "3", "services": "2", "persistentvolumeclaims": "0",
				},
				"allocated": map[string]string{
					"limits.cpu": "2", "limits.memory": "1Gi", "requests.cpu": "500m",
					"requests.memory": "256Mi", "pods": "10", "services": "5", "persistentvolumeclaims": "1",
				},
			})
			return
		}
		writeResp(w, map[string]any{
			"tenant":    name,
			"used":      map[string]string{"pods": "1", "limits.cpu": "200m"},
			"allocated": map[string]string{"pods": "4", "limits.cpu": "1"},
		})
	case r.URL.Path == "/api/v1/incidents":
		f.writeIncidents(w, r.URL.Query().Get("status"))
	case r.URL.Path == "/api/v1/previews":
		n := 0
		if r.URL.Query().Get("team") == "labs" {
			n = 2
		}
		writeResp(w, map[string]any{"items": make([]any, n), "count": n, "team": r.URL.Query().Get("team")})
	case r.URL.Path == "/api/v1/domains":
		if r.URL.Query().Get("team") == "labs" {
			writeResp(w, map[string]any{"domains": []any{map[string]any{
				"team": "labs", "service": "web", "domain": "example.com", "status": "active",
				"cname_target": "labs-web.mctl.ai", "verified_at": "2026-09-11T14:14:00Z",
			}}})
			return
		}
		writeResp(w, map[string]any{"domains": []any{}})
	case r.URL.Path == "/api/v1/repos":
		n := 1
		if r.URL.Query().Get("team") == "labs" {
			n = 3
		}
		writeResp(w, map[string]any{"items": make([]any, n), "count": n})
	case r.URL.Path == "/api/v1/operations":
		writeResp(w, map[string]any{"items": []any{
			map[string]any{"name": "deploy-service", "riskLevel": "medium", "adminOnly": false},
			map[string]any{"name": "delete-tenant", "riskLevel": "high", "adminOnly": true},
		}, "count": 2})
	case r.URL.Path == "/api/v1/platform-skills":
		writeResp(w, map[string]any{"items": []any{map[string]any{}, map[string]any{}}, "count": 2})
	case r.URL.Path == "/api/v1/usage/summary":
		f.writeUsage(w, r.URL.Query().Get("group_by"))
	case r.URL.Path == "/api/v1/agents":
		writeResp(w, map[string]any{"items": []any{map[string]any{
			"name": "implementer", "owner": "mctl-agents", "versionCount": 3, "definitionVersionCount": 1,
		}}, "count": 1})
	case r.URL.Path == "/api/v1/agents/executions":
		writeResp(w, map[string]any{"items": []any{
			map[string]any{"agent": "shepherd", "target_repo": "mctlhq/mctl-api", "phase": "Succeeded", "created_at": "2026-11-25T00:00:00Z"},
			map[string]any{"agent": "implementer", "target_repo": "", "phase": "Failed", "created_at": "2026-11-24T00:00:00Z"},
		}, "count": 2})
	case r.URL.Path == "/api/v1/agents/implementer":
		writeResp(w, map[string]any{
			"name": "implementer",
			"profileVersions": []any{map[string]any{
				"profile": "implementer-default", "version": "1.0.0",
				"spec": `{"timeoutSeconds":600,"maxToolCalls":9,"budgetUsd":20,"policyRef":"production-code-author","approvalGates":["code-authoring"]}`,
			}},
			"activeBindings": map[string]any{
				"shadow": map[string]any{
					"definitionVersion": "3", "profile": "implementer-default",
					"profileVersion": "1.0.0", "bindingSource": "registry",
				},
			},
		})
	case r.URL.Path == "/api/v1/lifecycle/ownership":
		writeResp(w, map[string]any{"ownership": []any{map[string]any{
			"entity":           map[string]any{"kind": "pull-request", "id": "mctlhq/mctl-api#9"},
			"phase":            "review-remediation",
			"owner":            map[string]any{"type": "devloop-workflow", "id": "dev-loop-1"},
			"proposal_ref":     "prop-1",
			"last_seen_at":     "2026-11-25T00:00:00Z",
			"last_progress_at": "2026-11-24T00:00:00Z",
			"derived":          map[string]any{"status": "stuck", "seconds_since_progress": 36000},
		}}, "count": 1})
	case r.URL.Path == "/api/v1/agent-runs":
		writeResp(w, map[string]any{"items": []any{
			map[string]any{"status": "Succeeded"},
			map[string]any{"status": "Failed"},
		}, "count": 2})
	default:
		http.NotFound(w, r)
	}
}

func (f *statsFake) writeIncidents(w http.ResponseWriter, status string) {
	active := []any{
		map[string]any{"id": "inc-labs", "tenant": "labs", "service": "web", "severity": "warning", "status": "open", "type": "generic", "source": "alertmanager", "summary": "labs web", "created_at": "2026-11-24T12:00:00Z"},
		map[string]any{"id": "inc-karabu", "tenant": "karabu", "service": "draw", "severity": "critical", "status": "fix_proposed", "type": "pod_crashloop", "source": "polling", "summary": "karabu draw", "created_at": "2026-11-24T11:00:00Z"},
		map[string]any{"id": "inc-other", "tenant": "other", "service": "secret-svc", "severity": "warning", "status": "open", "summary": "foreign", "created_at": "2026-11-24T10:00:00Z"},
		map[string]any{"id": "inc-resolved-in-active", "tenant": "labs", "service": "web", "severity": "warning", "status": "resolved", "summary": "should drop", "created_at": "2026-11-24T09:00:00Z"},
	}
	resolved := []any{
		map[string]any{"id": "r1", "tenant": "labs", "service": "web", "severity": "warning", "status": "resolved", "type": "generic", "source": "alertmanager", "summary": "one", "acknowledged_by": "service:mctl-agent", "created_at": "2026-11-24T12:00:00Z", "resolved_at": "2026-11-24T13:00:00Z"},
		map[string]any{"id": "r2", "tenant": "labs", "service": "web", "severity": "critical", "status": "resolved", "type": "pod_crashloop", "source": "polling", "summary": "two", "acknowledged_by": "github:mashkovd", "created_at": "2026-11-23T12:00:00Z", "resolved_at": "2026-11-23T13:00:00Z"},
		map[string]any{"id": "r3", "tenant": "karabu", "service": "draw", "severity": "warning", "status": "resolved", "type": "generic", "source": "alertmanager", "summary": "three", "created_at": "2026-11-22T12:00:00Z", "resolved_at": "2026-11-22T13:00:00Z"},
		map[string]any{"id": "r4", "tenant": "admins", "service": "secret-svc", "severity": "warning", "status": "resolved", "summary": "foreign", "created_at": "2026-11-22T12:00:00Z"},
	}
	items := active
	if status == "resolved" {
		items = resolved
	}
	writeResp(w, map[string]any{"items": items, "count": len(items)})
}

func (f *statsFake) writeUsage(w http.ResponseWriter, group string) {
	var buckets []any
	switch group {
	case "agent":
		buckets = []any{
			map[string]any{"key": "implementer", "count": 2, "calculated_cost": 1.5, "input_tokens": 10, "output_tokens": 4, "cache_read_tokens": 8},
			map[string]any{"key": "shepherd", "count": 1, "calculated_cost": 0.5, "input_tokens": 1, "output_tokens": 1, "cache_read_tokens": 1},
		}
	case "canonical_model":
		buckets = []any{map[string]any{"key": "claude", "count": 3, "calculated_cost": 2.0, "input_tokens": 11, "output_tokens": 5}}
	case "devloop_stage":
		buckets = []any{map[string]any{"key": "", "count": 3, "calculated_cost": 2.0}}
	case "provider":
		buckets = []any{map[string]any{"key": "firstParty", "count": 3, "calculated_cost": 2.0}}
	case "target_repo":
		buckets = []any{map[string]any{"key": "mctlhq/mctl-api", "count": 3, "calculated_cost": 2.0, "output_tokens": 5}}
	case "outcome":
		buckets = []any{
			map[string]any{"key": "success", "count": 2},
			map[string]any{"key": "error", "count": 1},
		}
	}
	writeResp(w, map[string]any{"group_by": group, "buckets": buckets, "truncated": false, "limit": 1000})
}

func (f *statsFake) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.hits))
	copy(out, f.hits)
	return out
}

func (f *statsFake) reset() {
	f.mu.Lock()
	f.hits = nil
	f.mu.Unlock()
}

func (f *statsFake) assertGETOnly(t *testing.T) {
	t.Helper()
	for _, hit := range f.snapshot() {
		if !strings.HasPrefix(hit, "GET ") {
			t.Errorf("non-GET call: %s", hit)
		}
	}
}

func labsTenant() map[string]any {
	return map[string]any{
		"name": "labs", "displayName": "Labs", "description": "lab tenant",
		"quotas": map[string]string{
			"limits.cpu": "2", "limits.memory": "1Gi", "requests.cpu": "500m",
			"requests.memory": "256Mi", "pods": "10", "services": "5", "persistentvolumeclaims": "1",
		},
		"networking": map[string]bool{"allowInternetEgress": true, "allowClusterEgress": true, "allowIntraNamespace": true},
		"members":    []any{map[string]any{"userId": "mashkovd", "role": "owner"}},
	}
}

func karabuTenant() map[string]any {
	return map[string]any{
		"name": "karabu", "displayName": "karabu", "description": "draw",
		"quotas":     map[string]string{"limits.cpu": "1", "pods": "4"},
		"networking": map[string]bool{},
		"members":    []any{map[string]any{"userId": "emilia", "role": "owner"}},
	}
}

func writeResp(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

func callStats(t *testing.T, apiURL string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	srv := NewServer(apiURL, "test-token")
	_, handler := srv.toolStatsDashboard()
	res, err := handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{Name: "mctl_stats_dashboard", Arguments: args},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return res
}

func decodeDash(t *testing.T, res *mcplib.CallToolResult) statsDashboard {
	t.Helper()
	if res == nil || res.IsError {
		t.Fatalf("error result: %s", toolResultText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var d statsDashboard
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func toolResultText(res *mcplib.CallToolResult) string {
	if res == nil {
		return ""
	}
	for _, c := range res.Content {
		if text, ok := c.(mcplib.TextContent); ok {
			return text.Text
		}
	}
	return ""
}

func findTenant(d statsDashboard, name string) statsTenant {
	for i := range d.Tenants {
		if d.Tenants[i].Name == name {
			return d.Tenants[i]
		}
	}
	return statsTenant{}
}

func findService(d statsDashboard, team, name string) statsService {
	for i := range d.Services {
		if d.Services[i].Team == team && d.Services[i].Name == name {
			return d.Services[i]
		}
	}
	return statsService{}
}

func namesOf(d statsDashboard) []string {
	out := make([]string, 0, len(d.Tenants))
	for i := range d.Tenants {
		out = append(out, d.Tenants[i].Name)
	}
	return out
}

func mcpResult(t *testing.T, srv interface {
	HandleMessage(context.Context, json.RawMessage) mcplib.JSONRPCMessage
}, method string, params any) map[string]any {
	t.Helper()
	payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		payload["params"] = params
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp := srv.HandleMessage(context.Background(), raw)
	buf, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Result map[string]any `json:"result"`
		Error  any            `json:"error"`
	}
	if err := json.Unmarshal(buf, &env); err != nil {
		t.Fatalf("unmarshal %s: %v body %s", method, err, buf)
	}
	if env.Error != nil {
		t.Fatalf("%s error: %v", method, env.Error)
	}
	if env.Result == nil {
		t.Fatalf("%s empty result: %s", method, buf)
	}
	return env.Result
}

func metaUI(t *testing.T, raw any) map[string]any {
	t.Helper()
	meta, _ := raw.(map[string]any)
	ui, _ := meta["ui"].(map[string]any)
	if ui == nil {
		t.Fatalf("missing _meta.ui in %#v", raw)
	}
	return ui
}

func mapField(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, _ := m[key].(map[string]any)
	if v == nil {
		t.Fatalf("missing %s in %#v", key, m)
	}
	return v
}

func assertEmptyList(t *testing.T, v any) {
	t.Helper()
	list, ok := v.([]any)
	if !ok || len(list) != 0 {
		t.Fatalf("want empty list, got %#v", v)
	}
}
