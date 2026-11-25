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
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// statsAppURI is the MCP App resource the statistics console is served from.
// The HTML is embedded and makes no network requests of its own; live numbers
// arrive as the structuredContent of mctl_stats_dashboard.
const (
	statsAppURI         = "ui://mctl-stats/view.html"
	statsAppMIME        = "text/html;profile=mcp-app"
	statsCollectBudget  = 20 * time.Second
	statsStatusCap      = 40
	statsStatusParallel = 6
	statsTenantParallel = 4
	statsIncidentLimit  = 100
	statsAgentDetailCap = 12
	statsExecutionLimit = 100
	statsOwnershipLimit = 100
)

//go:embed statsview/view.html
var statsViewHTML string

// registerStatsApp serves the embedded MCP App. CSP connectDomains is empty:
// the iframe is not allowed to open network connections. Live data is pushed
// in by the host as a tool result.
func (s *Server) registerStatsApp() {
	res := mcplib.NewResource(
		statsAppURI,
		"mctl-stats-view",
		mcplib.WithResourceTitle("MCTL Platform Statistics Console"),
		mcplib.WithResourceDescription("Interactive read-only platform statistics dashboard (MCP App). The iframe makes no network requests."),
		mcplib.WithMIMEType(statsAppMIME),
		mcplib.WithResourceSize(int64(len(statsViewHTML))),
	)
	res.Meta = statsAppMeta()
	s.mcpServer.AddResource(res, func(ctx context.Context, req mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		uri := req.Params.URI
		if uri == "" {
			uri = statsAppURI
		}
		return []mcplib.ResourceContents{
			mcplib.TextResourceContents{
				URI:      uri,
				MIMEType: statsAppMIME,
				Text:     statsViewHTML,
				Meta:     statsAppMetaMap(),
			},
		}, nil
	})
}

func statsAppMeta() *mcplib.Meta {
	return &mcplib.Meta{AdditionalFields: statsAppMetaMap()}
}

func statsAppMetaMap() map[string]any {
	return map[string]any{
		"ui": map[string]any{
			"csp": map[string]any{
				"connectDomains":  []string{},
				"resourceDomains": []string{},
			},
		},
	}
}

func (s *Server) toolStatsDashboard() (mcplib.Tool, server.ToolHandlerFunc) {
	tool := mcplib.NewTool("mctl_stats_dashboard",
		mcplib.WithTitleAnnotation("Platform Statistics"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithDescription(`Open the live MCTL platform statistics dashboard.

Read-only aggregate for the caller's own teams: tenants, services with ArgoCD sync and health, quota and pod/CPU/memory usage, incidents, and — for platform admins — already-recorded model-usage cost, agent executions and DevLoop ownership. It does not change any state and does not call a model or spend model budget.

Non-admins only receive their own teams. Pass team or namespace to narrow further; omit both (or pass "all") for every team the caller may see.

The interactive console is the MCP App at ui://mctl-stats/view.html. structuredContent matches that view; the text is a short summary for clients without a UI.`),
		mcplib.WithString("team",
			mcplib.Description("Optional team (tenant) filter. Omit or pass \"all\" for every team the caller may see."),
		),
		mcplib.WithString("namespace",
			mcplib.Description("Optional Kubernetes namespace filter. For a single-namespace tenant this is the tenant name; a multi-team tenant matches {tenant}-{team}. When both team and namespace are set, both must match."),
		),
	)
	tool.Meta = &mcplib.Meta{AdditionalFields: map[string]any{
		"ui": map[string]any{"resourceUri": statsAppURI},
	}}

	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		team := normalizeStatsFilter(stringArg(req, "team"))
		namespace := normalizeStatsFilter(stringArg(req, "namespace"))
		dash, err := s.buildStatsDashboard(ctx, team, namespace)
		if err != nil {
			slog.Warn("stats dashboard failed", "error", err)
			return mcplib.NewToolResultError("Failed to load platform statistics: " + s.redactUpstream(err)), nil
		}
		return mcplib.NewToolResultStructured(dash, summarizeStats(dash)), nil
	}
	return tool, handler
}

// normalizeStatsFilter treats blank, "all" and "*" as "no filter".
func normalizeStatsFilter(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "all") || v == "*" {
		return ""
	}
	return v
}

func (s *Server) buildStatsDashboard(ctx context.Context, teamFilter, nsFilter string) (*statsDashboard, error) {
	ctx, cancel := context.WithTimeout(ctx, statsCollectBudget)
	defer cancel()

	var id statsIdentity
	if _, err := s.getJSON(ctx, "/api/v1/whoami", &id); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	tenants, earlyGaps, err := s.loadScopedTenants(ctx, id, teamFilter, nsFilter)
	if err != nil {
		return nil, err
	}

	d := newStatsDashboard(id, time.Now())
	d.Meta.APIBase = s.displayURL()
	d.Meta.FilterTeam = teamFilter
	d.Meta.FilterNamespace = nsFilter
	d.Platform.DataGaps = append(d.Platform.DataGaps, earlyGaps...)
	d.Platform.DataGaps = append(d.Platform.DataGaps,
		"Дорожная карта (эпики и готовые work items) в API mctl не публикуется.",
		"Agent Commerce, окна синхронизации ArgoCD, заявки на регистрацию и события namespace в API mctl не публикуются.",
	)
	if len(tenants) == 0 {
		d.Platform.DataGaps = append(d.Platform.DataGaps, "Нет команд в области видимости этой учётной записи.")
	}

	loc := statsLocation()
	var (
		wg          sync.WaitGroup
		svcItems    []apiService
		svcErr      error
		active      []apiIncident
		activeErr   error
		resolved    []apiIncident
		resolvedErr error
		extras      []tenantExtra
		ops         statsOps
		opsErr      error
		skills      int
		skillErr    error
		usage       statsUsage
		usageGaps   []string
		agents      statsAgents
		agentGaps   []string
	)

	if len(tenants) > 0 {
		wg.Add(4)
		go func() {
			defer wg.Done()
			var wrap struct {
				Items []apiService `json:"items"`
			}
			_, svcErr = s.getJSON(ctx, servicesPath(tenants), &wrap)
			svcItems = wrap.Items
		}()
		go func() {
			defer wg.Done()
			active, activeErr = s.fetchIncidents(ctx, tenants, "active")
		}()
		go func() {
			defer wg.Done()
			resolved, resolvedErr = s.fetchIncidents(ctx, tenants, "resolved")
		}()
		go func() {
			defer wg.Done()
			extras = s.fillTenantExtras(ctx, tenants)
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		ops, opsErr = s.fetchOperations(ctx)
	}()
	go func() {
		defer wg.Done()
		skills, skillErr = s.fetchSkillCount(ctx)
	}()
	if id.admin() {
		wg.Add(2)
		go func() {
			defer wg.Done()
			usage, usageGaps = s.fetchUsage(ctx)
		}()
		go func() {
			defer wg.Done()
			agents, agentGaps = s.fetchAgents(ctx, loc)
		}()
	}
	wg.Wait()

	allow := tenantNameSet(tenants)
	d.Tenants = make([]statsTenant, 0, len(tenants))
	for i := range tenants {
		row, gaps := tenantRow(&tenants[i], extrasAt(extras, i), s.redactString)
		d.Tenants = append(d.Tenants, row)
		d.Platform.DataGaps = append(d.Platform.DataGaps, gaps...)
		d.Platform.Domains = append(d.Platform.Domains, extrasAt(extras, i).domains...)
	}
	sort.Slice(d.Platform.Domains, func(i, j int) bool { return d.Platform.Domains[i].Domain < d.Platform.Domains[j].Domain })

	if svcErr != nil {
		s.addGap(&d.Platform.DataGaps, svcErr, "Каталог сервисов недоступен")
	} else {
		d.Services = servicesInScope(svcItems, allow)
		failed, capped := s.attachArgoStatus(ctx, d.Services)
		if capped {
			d.Platform.DataGaps = append(d.Platform.DataGaps, fmt.Sprintf("Статус ArgoCD запрошен для первых %d сервисов из %d.", statsStatusCap, len(d.Services)))
		}
		if failed > 0 {
			d.Platform.DataGaps = append(d.Platform.DataGaps, fmt.Sprintf("Статус ArgoCD недоступен для %d сервисов.", failed))
		}
	}

	if activeErr != nil {
		d.Incidents.Available = false
		s.addGap(&d.Platform.DataGaps, activeErr, "Активные инциденты недоступны")
	} else {
		d.Incidents.Available = true
		d.Incidents.Active = activeIncidents(filterIncidents(active, allow), loc)
		if len(active) >= statsIncidentLimit {
			d.Platform.DataGaps = append(d.Platform.DataGaps, fmt.Sprintf("Выборка активных инцидентов ограничена %d записями.", statsIncidentLimit))
		}
	}
	if resolvedErr != nil {
		s.addGap(&d.Platform.DataGaps, resolvedErr, "История инцидентов недоступна")
	} else {
		d.Incidents.ResolvedSummary = summarizeResolved(filterIncidents(resolved, allow), loc)
		if len(resolved) >= statsIncidentLimit {
			d.Platform.DataGaps = append(d.Platform.DataGaps, fmt.Sprintf("Выборка закрытых инцидентов ограничена %d записями.", statsIncidentLimit))
		}
	}
	applyLiveNotes(d.Services, d.Incidents.Active, d.Meta.DataAsOf)

	if opsErr != nil {
		s.addGap(&d.Platform.DataGaps, opsErr, "Каталог операций недоступен")
	} else {
		d.Platform.Operations = ops
	}
	if skillErr != nil {
		s.addGap(&d.Platform.DataGaps, skillErr, "Каталог навыков платформы недоступен")
	}

	if id.admin() {
		d.Usage = usage
		d.Platform.DataGaps = append(d.Platform.DataGaps, usageGaps...)
		if usage.Available {
			d.Platform.DataGaps = append(d.Platform.DataGaps, "Стоимость моделей — calculated_cost по уже записанному журналу; вызов модели не выполняется. provider_reported_cost и invoice_reconciled_cost суммируются только по строкам, где журнал их содержит.")
		}
		agents.SkillsCount = skills
		d.Agents = agents
		d.Platform.DataGaps = append(d.Platform.DataGaps, agentGaps...)
		if (teamFilter != "" || nsFilter != "") && (usage.Available || agents.Available) {
			d.Platform.DataGaps = append(d.Platform.DataGaps, "Фильтр команды сужает тенанты, сервисы, квоты, инциденты, домены и превью. Журнал моделей и агенты остаются платформенными.")
		}
	} else {
		d.Usage.Available = false
		d.Agents.Available = false
		d.Agents.SkillsCount = skills
		d.Platform.DataGaps = append(d.Platform.DataGaps,
			"Журнал расходов на модели доступен только администраторам платформы; запрос не отправлялся.",
			"Реестр агентов, исполнения, недавние запуски и DevLoop ownership доступны только администраторам; запросы не отправлялись.",
		)
	}
	if ctx.Err() != nil {
		d.Platform.DataGaps = append(d.Platform.DataGaps, "Сбор статистики остановлен по таймауту; часть секций может быть неполной.")
	}
	d.Platform.DataGaps = dedupeStrings(d.Platform.DataGaps)
	return d, nil
}

func extrasAt(extras []tenantExtra, i int) tenantExtra {
	if i < 0 || i >= len(extras) {
		return tenantExtra{}
	}
	return extras[i]
}

func (s *Server) addGap(dst *[]string, err error, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if err != nil {
		msg += ": " + s.redactUpstream(err)
	}
	*dst = append(*dst, msg)
}

func summarizeStats(d *statsDashboard) string {
	synced, degraded := 0, 0
	for i := range d.Services {
		if d.Services[i].SyncStatus == "Synced" {
			synced++
		}
		if d.Services[i].Health == "Degraded" {
			degraded++
		}
	}
	scope := "all accessible teams"
	switch {
	case d.Meta.FilterTeam != "" && d.Meta.FilterNamespace != "":
		scope = "team " + d.Meta.FilterTeam + ", namespace " + d.Meta.FilterNamespace
	case d.Meta.FilterTeam != "":
		scope = "team " + d.Meta.FilterTeam
	case d.Meta.FilterNamespace != "":
		scope = "namespace " + d.Meta.FilterNamespace
	}
	role := "member"
	if d.Meta.Admin {
		role = "admin"
	}
	cost := "not available to this caller"
	if d.Usage.Available {
		cost = fmt.Sprintf("$%.2f calculated", d.Usage.Totals.CalculatedCost)
		if d.Meta.FilterTeam != "" || d.Meta.FilterNamespace != "" {
			cost += " (platform ledger, not team-scoped)"
		}
	}
	agents := "not available to this caller"
	if d.Agents.Available {
		agents = fmt.Sprintf("%d executions, %d stuck ownership", d.Agents.Executions.Count, len(d.Agents.Ownership.Stuck))
	}
	return fmt.Sprintf(
		"MCTL statistics for %s (%s), scope %s, as of %s. Tenants: %d. Services: %d (%d Synced, %d Degraded). Active incidents: %d, resolved in view: %d. Model cost: %s. Agents: %s. Read-only; no model calls.",
		d.Meta.User, role, scope, d.Meta.DataAsOf,
		len(d.Tenants), len(d.Services), synced, degraded,
		len(d.Incidents.Active), d.Incidents.ResolvedSummary.Count,
		cost, agents,
	)
}

// --- identity and tenant scope ---

type statsIdentity struct {
	ID         string   `json:"id"`
	Groups     []string `json:"groups"`
	IsAdmin    bool     `json:"isAdmin"`
	Namespaces []string `json:"namespaces"`
}

func (id statsIdentity) admin() bool {
	if id.IsAdmin {
		return true
	}
	for _, g := range id.Groups {
		if g == "admins" {
			return true
		}
	}
	return false
}

type apiTenant struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"displayName"`
	Description string            `json:"description"`
	Quotas      map[string]string `json:"quotas"`
	Networking  map[string]bool   `json:"networking"`
	Members     []apiMember       `json:"members"`
	Teams       []apiTeam         `json:"teams"`
}

type apiMember struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

type apiTeam struct {
	Name string `json:"name"`
}

func tenantMatchesNamespace(t apiTenant, ns string) bool {
	if ns == "" || t.Name == ns {
		return ns == "" || t.Name == ns
	}
	for _, team := range t.Teams {
		if t.Name+"-"+team.Name == ns {
			return true
		}
	}
	return false
}

func (s *Server) loadScopedTenants(ctx context.Context, id statsIdentity, teamFilter, nsFilter string) ([]apiTenant, []string, error) {
	admin := id.admin()
	groups := uniqueStrings(id.Groups)
	if teamFilter != "" && !admin && !containsString(groups, teamFilter) {
		return nil, nil, fmt.Errorf("access denied to team %q", teamFilter)
	}

	var (
		raws []apiTenant
		gaps []string
		err  error
	)
	switch {
	case teamFilter != "":
		raws, err = s.fetchOneTenant(ctx, teamFilter)
	case admin:
		raws, err = s.fetchAllTenants(ctx)
	default:
		raws, gaps, err = s.fetchNamedTenants(ctx, groups)
	}
	if err != nil {
		return nil, nil, err
	}
	if nsFilter != "" {
		matched := make([]apiTenant, 0, len(raws))
		for i := range raws {
			if tenantMatchesNamespace(raws[i], nsFilter) {
				matched = append(matched, raws[i])
			}
		}
		if len(matched) == 0 {
			if teamFilter != "" {
				return nil, nil, fmt.Errorf("team %q does not match namespace %q", teamFilter, nsFilter)
			}
			if !admin {
				return nil, nil, fmt.Errorf("access denied to namespace %q", nsFilter)
			}
			return nil, nil, fmt.Errorf("no tenant matches namespace %q", nsFilter)
		}
		raws = matched
	}
	sort.Slice(raws, func(i, j int) bool { return raws[i].Name < raws[j].Name })
	return raws, gaps, nil
}

func (s *Server) fetchOneTenant(ctx context.Context, name string) ([]apiTenant, error) {
	var wrap struct {
		Tenant apiTenant `json:"tenant"`
	}
	status, err := s.getJSON(ctx, "/api/v1/tenants/"+url.PathEscape(name), &wrap)
	if err != nil {
		if status == http.StatusNotFound {
			return nil, fmt.Errorf("tenant not found: %s", name)
		}
		if status == http.StatusForbidden {
			return nil, fmt.Errorf("access denied to team %q", name)
		}
		return nil, err
	}
	if wrap.Tenant.Name == "" {
		wrap.Tenant.Name = name
	}
	return []apiTenant{wrap.Tenant}, nil
}

func (s *Server) fetchAllTenants(ctx context.Context) ([]apiTenant, error) {
	var wrap struct {
		Items []apiTenant `json:"items"`
	}
	if _, err := s.getJSON(ctx, "/api/v1/tenants", &wrap); err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	if wrap.Items == nil {
		wrap.Items = []apiTenant{}
	}
	return wrap.Items, nil
}

func (s *Server) fetchNamedTenants(ctx context.Context, names []string) ([]apiTenant, []string, error) {
	var (
		out  []apiTenant
		gaps []string
	)
	var hard error
	for _, name := range names {
		one, err := s.fetchOneTenant(ctx, name)
		if err != nil {
			if strings.HasPrefix(err.Error(), "tenant not found:") {
				gaps = append(gaps, "Команда "+name+" не найдена.")
				continue
			}
			hard = err
			gaps = append(gaps, "Команда "+name+" не прочитана: "+s.redactUpstream(err))
			continue
		}
		out = append(out, one...)
	}
	if len(out) == 0 && hard != nil {
		return nil, gaps, hard
	}
	if out == nil {
		out = []apiTenant{}
	}
	return out, gaps, nil
}

// --- section fetches (GET only) ---

type apiService struct {
	Team        string `json:"team"`
	Name        string `json:"name"`
	ImageTag    string `json:"imageTag"`
	Host        string `json:"host"`
	HasDatabase bool   `json:"hasDatabase"`
}

type apiIncident struct {
	ID             string     `json:"id"`
	Source         string     `json:"source"`
	Type           string     `json:"type"`
	Tenant         string     `json:"tenant"`
	Service        string     `json:"service"`
	Summary        string     `json:"summary"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Analysis       string     `json:"analysis"`
	Confidence     string     `json:"confidence"`
	CreatedAt      time.Time  `json:"created_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AcknowledgedBy string     `json:"acknowledged_by"`
}

type apiResources struct {
	Allocated map[string]string `json:"allocated"`
	Used      map[string]string `json:"used"`
	Note      string            `json:"note"`
}

type apiDomain struct {
	Team       string     `json:"team"`
	Service    string     `json:"service"`
	Domain     string     `json:"domain"`
	Status     string     `json:"status"`
	CNAME      string     `json:"cname_target"`
	VerifiedAt *time.Time `json:"verified_at"`
}

type tenantExtra struct {
	quota      statsQuota
	quotaNote  string
	quotaErr   error
	previews   *int
	previewErr error
	domains    []statsDomain
	domainErr  error
	repos      *int
	repoErr    error
}

func servicesPath(tenants []apiTenant) string {
	if len(tenants) == 1 {
		return "/api/v1/services?team=" + url.QueryEscape(tenants[0].Name)
	}
	return "/api/v1/services"
}

func (s *Server) fetchIncidents(ctx context.Context, tenants []apiTenant, status string) ([]apiIncident, error) {
	q := url.Values{}
	q.Set("status", status)
	q.Set("limit", strconv.Itoa(statsIncidentLimit))
	if len(tenants) == 1 {
		q.Set("tenant", tenants[0].Name)
	}
	var wrap struct {
		Items []apiIncident `json:"items"`
	}
	_, err := s.getJSON(ctx, "/api/v1/incidents?"+q.Encode(), &wrap)
	if err != nil {
		return nil, err
	}
	if wrap.Items == nil {
		wrap.Items = []apiIncident{}
	}
	return wrap.Items, nil
}

func (s *Server) fillTenantExtras(ctx context.Context, tenants []apiTenant) []tenantExtra {
	out := make([]tenantExtra, len(tenants))
	sem := make(chan struct{}, statsTenantParallel)
	var wg sync.WaitGroup
	for i := range tenants {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i].quotaErr = ctx.Err()
				out[i].previewErr = ctx.Err()
				out[i].domainErr = ctx.Err()
				out[i].repoErr = ctx.Err()
				out[i].quota = quotaFromMaps(nil, tenants[i].Quotas)
				return
			}
			name := tenants[i].Name
			var res apiResources
			if _, err := s.getJSON(ctx, "/api/v1/resources/"+url.PathEscape(name), &res); err != nil {
				out[i].quotaErr = err
				out[i].quota = quotaFromMaps(nil, tenants[i].Quotas)
			} else {
				alloc := res.Allocated
				if len(alloc) == 0 {
					alloc = tenants[i].Quotas
				}
				out[i].quota = quotaFromMaps(res.Used, alloc)
				out[i].quotaNote = strings.TrimSpace(res.Note)
			}
			if n, err := s.getCount(ctx, "/api/v1/previews?team="+url.QueryEscape(name)); err != nil {
				out[i].previewErr = err
			} else {
				out[i].previews = intPtr(n)
			}
			var doms struct {
				Domains []apiDomain `json:"domains"`
			}
			if _, err := s.getJSON(ctx, "/api/v1/domains?team="+url.QueryEscape(name), &doms); err != nil {
				out[i].domainErr = err
			} else {
				out[i].domains = make([]statsDomain, 0, len(doms.Domains))
				for _, d := range doms.Domains {
					out[i].domains = append(out[i].domains, statsDomain{
						Team:        d.Team,
						Service:     d.Service,
						Domain:      d.Domain,
						CNAMETarget: d.CNAME,
						Status:      d.Status,
						VerifiedCET: formatStatsTime(derefTime(d.VerifiedAt), statsLocation()),
					})
				}
			}
			if n, err := s.getCount(ctx, "/api/v1/repos?team="+url.QueryEscape(name)); err != nil {
				out[i].repoErr = err
			} else {
				out[i].repos = intPtr(n)
			}
		}(i)
	}
	wg.Wait()
	return out
}

func (s *Server) fetchOperations(ctx context.Context) (statsOps, error) {
	var wrap struct {
		Items []struct {
			RiskLevel string `json:"riskLevel"`
			AdminOnly bool   `json:"adminOnly"`
		} `json:"items"`
	}
	ops := statsOps{ByRisk: map[string]int{}, ByScope: map[string]int{}}
	if _, err := s.getJSON(ctx, "/api/v1/operations", &wrap); err != nil {
		return ops, err
	}
	for _, item := range wrap.Items {
		risk := item.RiskLevel
		if risk == "" {
			risk = "unknown"
		}
		ops.ByRisk[risk]++
		if item.AdminOnly {
			ops.ByScope["admin"]++
		} else {
			ops.ByScope["tenant"]++
		}
	}
	ops.Count = len(wrap.Items)
	return ops, nil
}

func (s *Server) fetchSkillCount(ctx context.Context) (int, error) {
	var wrap struct {
		Items []struct{} `json:"items"`
		Count int        `json:"count"`
	}
	if _, err := s.getJSON(ctx, "/api/v1/platform-skills", &wrap); err != nil {
		return 0, err
	}
	n := wrap.Count
	if len(wrap.Items) > n {
		n = len(wrap.Items)
	}
	return n, nil
}

type apiBucket struct {
	Key                   string   `json:"key"`
	Count                 int64    `json:"count"`
	InputTokens           *int64   `json:"input_tokens"`
	OutputTokens          *int64   `json:"output_tokens"`
	CacheReadTokens       *int64   `json:"cache_read_tokens"`
	CacheWriteTokens      *int64   `json:"cache_write_tokens"`
	WebSearchRequests     *int64   `json:"web_search_requests"`
	ProviderReportedCost  *float64 `json:"provider_reported_cost"`
	CalculatedCost        *float64 `json:"calculated_cost"`
	InvoiceReconciledCost *float64 `json:"invoice_reconciled_cost"`
}

type apiUsageSummary struct {
	Buckets   []apiBucket `json:"buckets"`
	Truncated bool        `json:"truncated"`
}

func (s *Server) fetchUsage(ctx context.Context) (statsUsage, []string) {
	u := emptyUsage()
	groups := []string{"agent", "devloop_stage", "canonical_model", "provider", "target_repo", "outcome"}
	type part struct {
		rows      []statsUsageRow
		buckets   []apiBucket
		truncated bool
		err       error
	}
	parts := make([]part, len(groups))
	var wg sync.WaitGroup
	for i, group := range groups {
		wg.Add(1)
		go func(i int, group string) {
			defer wg.Done()
			path := "/api/v1/usage/summary?group_by=" + url.QueryEscape(group) + "&limit=1000"
			var resp apiUsageSummary
			_, err := s.getJSON(ctx, path, &resp)
			if err != nil {
				parts[i].err = err
				return
			}
			parts[i].buckets = resp.Buckets
			parts[i].truncated = resp.Truncated
			parts[i].rows = usageRows(group, resp.Buckets)
		}(i, group)
	}
	wg.Wait()

	var gaps []string
	ok := 0
	for i, group := range groups {
		if parts[i].err != nil {
			gaps = append(gaps, "Сводка расходов ("+group+"): "+s.redactUpstream(parts[i].err))
			continue
		}
		ok++
		if parts[i].truncated {
			gaps = append(gaps, "Сводка расходов ("+group+") обрезана по числу записей; сумма ниже полной.")
		}
	}
	if ok == 0 {
		return u, gaps
	}
	u.Available = true
	u.ByAgent = orRows(parts[0].rows)
	u.ByStage = orRows(parts[1].rows)
	u.ByModel = orRows(parts[2].rows)
	u.ByProvider = orRows(parts[3].rows)
	u.ByRepo = orRows(parts[4].rows)
	if parts[0].err == nil {
		u.Totals = totalsFromBuckets(parts[0].buckets)
	}
	if parts[5].err == nil {
		for _, b := range parts[5].buckets {
			switch strings.ToLower(strings.TrimSpace(b.Key)) {
			case "success":
				u.Totals.Success += b.Count
			case "error":
				u.Totals.Error += b.Count
			case "interrupted":
				u.Totals.Interrupted += b.Count
			}
		}
	}
	return u, gaps
}

func orRows(rows []statsUsageRow) []statsUsageRow {
	if rows == nil {
		return []statsUsageRow{}
	}
	return rows
}

func usageRows(group string, buckets []apiBucket) []statsUsageRow {
	rows := make([]statsUsageRow, 0, len(buckets))
	label := emptyUsageLabel(group)
	for _, b := range buckets {
		rows = append(rows, rowFromBucket(b, label))
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Cost != rows[j].Cost {
			return rows[i].Cost > rows[j].Cost
		}
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Key < rows[j].Key
	})
	return rows
}

func emptyUsageLabel(group string) string {
	switch group {
	case "devloop_stage":
		return "(без стадии / прочее)"
	case "target_repo":
		return "(без репозитория)"
	default:
		return "(не указано)"
	}
}

func rowFromBucket(b apiBucket, empty string) statsUsageRow {
	key := strings.TrimSpace(b.Key)
	if key == "" {
		key = empty
	}
	return statsUsageRow{
		Key:        key,
		Count:      b.Count,
		Cost:       floatOr0(b.CalculatedCost),
		Input:      n64(b.InputTokens),
		Output:     n64(b.OutputTokens),
		CacheRead:  n64(b.CacheReadTokens),
		CacheWrite: n64(b.CacheWriteTokens),
	}
}

func totalsFromBuckets(buckets []apiBucket) statsTotals {
	var t statsTotals
	for _, b := range buckets {
		t.Invocations += b.Count
		t.CalculatedCost += floatOr0(b.CalculatedCost)
		t.InputTokens += n64(b.InputTokens)
		t.OutputTokens += n64(b.OutputTokens)
		t.CacheReadTokens += n64(b.CacheReadTokens)
		t.CacheWriteTokens += n64(b.CacheWriteTokens)
		t.WebSearchRequests += n64(b.WebSearchRequests)
		addOpt(&t.ProviderReportedCost, b.ProviderReportedCost)
		addOpt(&t.InvoiceReconciledCost, b.InvoiceReconciledCost)
	}
	return t
}

type apiAgentSummary struct {
	Name                   string `json:"name"`
	Owner                  string `json:"owner"`
	VersionCount           int    `json:"versionCount"`
	DefinitionVersionCount int    `json:"definitionVersionCount"`
}

type apiExecution struct {
	Agent      string    `json:"agent"`
	TargetRepo string    `json:"target_repo"`
	Phase      string    `json:"phase"`
	CreatedAt  time.Time `json:"created_at"`
}

type apiOwnership struct {
	Entity struct {
		ID string `json:"id"`
	} `json:"entity"`
	Phase string `json:"phase"`
	Owner struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"owner"`
	ProposalRef    string    `json:"proposal_ref"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	LastProgressAt time.Time `json:"last_progress_at"`
	Derived        struct {
		Status               string `json:"status"`
		SecondsSinceProgress int64  `json:"seconds_since_progress"`
	} `json:"derived"`
}

func (s *Server) fetchAgents(ctx context.Context, loc *time.Location) (statsAgents, []string) {
	a := emptyAgents()
	var gaps []string
	anyOK := false

	var list struct {
		Items []apiAgentSummary `json:"items"`
	}
	if _, err := s.getJSON(ctx, "/api/v1/agents", &list); err != nil {
		gaps = append(gaps, "Реестр агентов недоступен: "+s.redactUpstream(err))
	} else {
		anyOK = true
		a.Registry = make([]statsAgentReg, 0, len(list.Items))
		for _, item := range list.Items {
			a.Registry = append(a.Registry, statsAgentReg{
				Name:     item.Name,
				Owner:    item.Owner,
				V1:       item.VersionCount,
				V1Alpha2: item.DefinitionVersionCount,
			})
		}
		sort.Slice(a.Registry, func(i, j int) bool { return a.Registry[i].Name < a.Registry[j].Name })
		profGaps := s.fillAgentDetails(ctx, &a)
		gaps = append(gaps, profGaps...)
	}

	var execs struct {
		Items []apiExecution `json:"items"`
	}
	if _, err := s.getJSON(ctx, "/api/v1/agents/executions?limit="+strconv.Itoa(statsExecutionLimit), &execs); err != nil {
		gaps = append(gaps, "Исполнения агентов недоступны: "+s.redactUpstream(err))
	} else {
		anyOK = true
		a.Executions = summarizeExecutions(execs.Items, loc)
		if len(execs.Items) >= statsExecutionLimit {
			gaps = append(gaps, fmt.Sprintf("Выборка исполнений агентов ограничена %d записями.", statsExecutionLimit))
		}
	}

	var own struct {
		Ownership []apiOwnership `json:"ownership"`
	}
	if _, err := s.getJSON(ctx, "/api/v1/lifecycle/ownership?limit="+strconv.Itoa(statsOwnershipLimit), &own); err != nil {
		gaps = append(gaps, "Lifecycle ownership недоступен: "+s.redactUpstream(err))
	} else {
		anyOK = true
		a.Ownership = summarizeOwnership(own.Ownership, loc)
		if len(own.Ownership) >= statsOwnershipLimit {
			a.Ownership.Truncated = true
			gaps = append(gaps, fmt.Sprintf("Выборка lifecycle ownership ограничена %d записями.", statsOwnershipLimit))
		}
	}

	var runs struct {
		Items []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if _, err := s.getJSON(ctx, "/api/v1/agent-runs", &runs); err != nil {
		gaps = append(gaps, "Недавние запуски агентов недоступны: "+s.redactUpstream(err))
	} else {
		anyOK = true
		a.RecentRuns.Total = len(runs.Items)
		for _, item := range runs.Items {
			switch strings.ToLower(item.Status) {
			case "succeeded", "success", "completed":
				a.RecentRuns.Succeeded++
			case "failed", "error", "failure":
				a.RecentRuns.Failed++
			}
		}
	}
	a.Available = anyOK
	return a, gaps
}

func (s *Server) fillAgentDetails(ctx context.Context, a *statsAgents) []string {
	n := len(a.Registry)
	if n > statsAgentDetailCap {
		n = statsAgentDetailCap
	}
	type detail struct {
		profiles []statsProfile
		releases []statsRelease
		err      error
	}
	got := make([]detail, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := a.Registry[i].Name
			var entry struct {
				ProfileVersions []struct {
					Profile string `json:"profile"`
					Version string `json:"version"`
					Spec    string `json:"spec"`
				} `json:"profileVersions"`
				ActiveBindings map[string]*struct {
					DefinitionVersion string `json:"definitionVersion"`
					Profile           string `json:"profile"`
					ProfileVersion    string `json:"profileVersion"`
					BindingSource     string `json:"bindingSource"`
				} `json:"activeBindings"`
			}
			if _, err := s.getJSON(ctx, "/api/v1/agents/"+url.PathEscape(name), &entry); err != nil {
				got[i].err = err
				return
			}
			for _, p := range entry.ProfileVersions {
				budget, timeout, policy, gates, tools := parseProfileSpec(p.Spec)
				if gates == nil {
					gates = []string{}
				}
				got[i].profiles = append(got[i].profiles, statsProfile{
					Name:           p.Profile,
					Version:        p.Version,
					BudgetUsd:      budget,
					TimeoutSeconds: timeout,
					PolicyRef:      policy,
					ApprovalGates:  gates,
					ToolsCount:     tools,
				})
			}
			for env, b := range entry.ActiveBindings {
				if b == nil {
					continue
				}
				got[i].releases = append(got[i].releases, statsRelease{
					Agent:          name,
					Environment:    env,
					DefVersion:     b.DefinitionVersion,
					ProfileName:    b.Profile,
					ProfileVersion: b.ProfileVersion,
					BindingSource:  b.BindingSource,
					Promotable:     false,
				})
			}
		}(i)
	}
	wg.Wait()

	seen := map[string]struct{}{}
	failed := 0
	for i := range got {
		if got[i].err != nil {
			failed++
			continue
		}
		for _, p := range got[i].profiles {
			key := p.Name + "@" + p.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			a.Profiles = append(a.Profiles, p)
		}
		a.Releases = append(a.Releases, got[i].releases...)
	}
	sort.Slice(a.Profiles, func(i, j int) bool {
		if a.Profiles[i].Name != a.Profiles[j].Name {
			return a.Profiles[i].Name < a.Profiles[j].Name
		}
		return a.Profiles[i].Version < a.Profiles[j].Version
	})
	sort.Slice(a.Releases, func(i, j int) bool {
		if a.Releases[i].Agent != a.Releases[j].Agent {
			return a.Releases[i].Agent < a.Releases[j].Agent
		}
		return a.Releases[i].Environment < a.Releases[j].Environment
	})
	var gaps []string
	if failed > 0 {
		gaps = append(gaps, fmt.Sprintf("Профили %d агентов не прочитаны.", failed))
	}
	if len(a.Registry) > statsAgentDetailCap {
		gaps = append(gaps, fmt.Sprintf("Профили и релизы прочитаны для первых %d агентов из %d.", statsAgentDetailCap, len(a.Registry)))
	}
	return gaps
}

func parseProfileSpec(spec string) (budget *float64, timeout int, policy string, gates []string, tools int) {
	var m map[string]any
	if json.Unmarshal([]byte(spec), &m) != nil || m == nil {
		return nil, 0, "", []string{}, 0
	}
	if f, ok := firstFloat(m, "budgetUsd", "budget_usd", "maxBudgetUsd"); ok {
		budget = &f
	}
	if n, ok := firstInt(m, "timeoutSeconds", "timeout_seconds"); ok {
		timeout = n
	}
	if s, ok := m["policyRef"].(string); ok {
		policy = s
	}
	if policy == "" {
		if s, ok := m["policy_ref"].(string); ok {
			policy = s
		}
	}
	gates = stringSlice(m["approvalGates"])
	if arr, ok := m["tools"].([]any); ok {
		tools = len(arr)
	}
	if tools == 0 {
		if n, ok := firstInt(m, "maxToolCalls", "toolsCount"); ok {
			tools = n
		}
	}
	if gates == nil {
		gates = []string{}
	}
	return budget, timeout, policy, gates, tools
}

func summarizeExecutions(items []apiExecution, loc *time.Location) statsExecutions {
	ex := statsExecutions{
		Count:   len(items),
		ByAgent: map[string]int{},
		ByRepo:  map[string]int{},
		ByPhase: map[string]int{},
	}
	var oldest, newest time.Time
	for _, item := range items {
		agent := item.Agent
		if agent == "" {
			agent = "(не указан)"
		}
		repo := item.TargetRepo
		if repo == "" {
			repo = "(без репозитория)"
		}
		phase := item.Phase
		if phase == "" {
			phase = "(не указана)"
		}
		ex.ByAgent[agent]++
		ex.ByRepo[repo]++
		ex.ByPhase[phase]++
		if !item.CreatedAt.IsZero() {
			if oldest.IsZero() || item.CreatedAt.Before(oldest) {
				oldest = item.CreatedAt
			}
			if newest.IsZero() || item.CreatedAt.After(newest) {
				newest = item.CreatedAt
			}
		}
	}
	ex.OldestCET = formatStatsTime(oldest, loc)
	ex.NewestCET = formatStatsTime(newest, loc)
	return ex
}

func summarizeOwnership(items []apiOwnership, loc *time.Location) statsOwnership {
	own := statsOwnership{
		Count:    len(items),
		AsOfCET:  formatStatsTime(time.Now(), loc),
		ByStatus: map[string]int{"terminal": 0, "released": 0, "stuck": 0},
		Stuck:    []statsStuck{},
	}
	for i := range items {
		item := &items[i]
		status := item.Derived.Status
		if status == "" {
			status = "unknown"
		}
		own.ByStatus[status]++
		if status != "stuck" && status != "dead" && status != "handoff-stalled" {
			continue
		}
		if len(own.Stuck) >= 20 {
			continue
		}
		sec := item.Derived.SecondsSinceProgress
		if sec == 0 && !item.LastProgressAt.IsZero() {
			delta := time.Since(item.LastProgressAt).Seconds()
			if delta > 0 {
				sec = int64(delta)
			}
		}
		workflow := item.Owner.ID
		if item.Owner.Type != "" && item.Owner.Type != "devloop-workflow" {
			workflow = item.Owner.Type + ":" + item.Owner.ID
		}
		own.Stuck = append(own.Stuck, statsStuck{
			EntityID:           item.Entity.ID,
			Phase:              item.Phase,
			WorkflowID:         workflow,
			ProposalRef:        item.ProposalRef,
			LastSeenCET:        formatStatsTime(item.LastSeenAt, loc),
			LastProgressCET:    formatStatsTime(item.LastProgressAt, loc),
			HoursSinceProgress: round1(float64(sec) / 3600),
			Status:             status,
		})
	}
	return own
}

func (s *Server) attachArgoStatus(ctx context.Context, svcs []statsService) (failed int, capped bool) {
	n := len(svcs)
	if n == 0 {
		return 0, false
	}
	if n > statsStatusCap {
		capped = true
		n = statsStatusCap
	}
	sem := make(chan struct{}, statsStatusParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			mu.Lock()
			failed += n - i
			mu.Unlock()
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				failed++
				mu.Unlock()
				return
			}
			path := "/api/v1/status/" + url.PathEscape(svcs[i].Team) + "/" + url.PathEscape(svcs[i].Name)
			var resp struct {
				Argo *struct {
					Health     string `json:"health"`
					SyncStatus string `json:"syncStatus"`
				} `json:"argocd"`
			}
			_, err := s.getJSON(ctx, path, &resp)
			if err != nil || resp.Argo == nil {
				if err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
				}
				return
			}
			svcs[i].SyncStatus = resp.Argo.SyncStatus
			if svcs[i].SyncStatus == "" {
				svcs[i].SyncStatus = "Unknown"
			}
			svcs[i].Health = resp.Argo.Health
			svcs[i].Deployed = true
		}(i)
	}
	wg.Wait()
	return failed, capped
}

// --- assembly ---

func tenantNameSet(tenants []apiTenant) map[string]struct{} {
	m := make(map[string]struct{}, len(tenants))
	for i := range tenants {
		m[tenants[i].Name] = struct{}{}
	}
	return m
}

func servicesInScope(items []apiService, allow map[string]struct{}) []statsService {
	out := make([]statsService, 0, len(items))
	for _, item := range items {
		if _, ok := allow[item.Team]; !ok {
			continue
		}
		hosts := []string{}
		if strings.TrimSpace(item.Host) != "" {
			hosts = []string{item.Host}
		}
		out = append(out, statsService{
			Team:        item.Team,
			Name:        item.Name,
			ImageTag:    item.ImageTag,
			HasDatabase: item.HasDatabase,
			SyncStatus:  "Unknown",
			Hosts:       hosts,
			ArgoApp:     item.Team + "-" + item.Name,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Team != out[j].Team {
			return out[i].Team < out[j].Team
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func filterIncidents(items []apiIncident, allow map[string]struct{}) []apiIncident {
	out := make([]apiIncident, 0, len(items))
	for i := range items {
		if _, ok := allow[items[i].Tenant]; !ok {
			continue
		}
		out = append(out, items[i])
	}
	return out
}

func activeIncidents(items []apiIncident, loc *time.Location) []statsIncident {
	out := make([]statsIncident, 0, len(items))
	for i := range items {
		item := &items[i]
		switch strings.ToLower(item.Status) {
		case "resolved", "suppressed":
			continue
		}
		out = append(out, statsIncident{
			ID:         item.ID,
			Tenant:     item.Tenant,
			Service:    item.Service,
			Severity:   item.Severity,
			Status:     item.Status,
			Type:       item.Type,
			Source:     item.Source,
			Confidence: item.Confidence,
			Summary:    item.Summary,
			Analysis:   item.Analysis,
			CreatedCET: formatStatsTime(item.CreatedAt, loc),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedCET > out[j].CreatedCET })
	return out
}

func summarizeResolved(items []apiIncident, loc *time.Location) statsResolved {
	rs := emptyResolved()
	daily := map[string]int{}
	sorted := append([]apiIncident(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CreatedAt.After(sorted[j].CreatedAt) })
	for i := range sorted {
		item := &sorted[i]
		if !strings.EqualFold(item.Status, "resolved") {
			continue
		}
		rs.Count++
		incMap(rs.BySeverity, item.Severity)
		incMap(rs.ByType, item.Type)
		incMap(rs.BySource, item.Source)
		incMap(rs.ByTenant, item.Tenant)
		resolver := item.AcknowledgedBy
		if resolver == "" {
			resolver = "—"
		}
		incMap(rs.ByResolver, resolver)
		if !item.CreatedAt.IsZero() {
			daily[item.CreatedAt.In(loc).Format("2006-01-02")]++
		}
		if len(rs.Recent) < 15 {
			rs.Recent = append(rs.Recent, statsRecent{
				ID:          item.ID,
				Tenant:      item.Tenant,
				Service:     item.Service,
				Severity:    item.Severity,
				Status:      item.Status,
				Type:        item.Type,
				Source:      item.Source,
				Summary:     item.Summary,
				CreatedCET:  formatStatsTime(item.CreatedAt, loc),
				ResolvedCET: formatStatsTime(derefTime(item.ResolvedAt), loc),
				ResolvedBy:  resolver,
			})
		}
	}
	days := make([]string, 0, len(daily))
	for day := range daily {
		days = append(days, day)
	}
	sort.Strings(days)
	for _, day := range days {
		rs.Daily = append(rs.Daily, []any{day, daily[day]})
	}
	return rs
}

func applyLiveNotes(svcs []statsService, active []statsIncident, asOf string) {
	idx := map[string]statsService{}
	for i := range svcs {
		idx[svcs[i].Team+"/"+svcs[i].Name] = svcs[i]
	}
	for i := range active {
		svc, ok := idx[active[i].Tenant+"/"+active[i].Service]
		if !ok {
			continue
		}
		if svc.Health == "" && svc.SyncStatus == "Unknown" {
			continue
		}
		health := svc.Health
		if health == "" {
			health = "—"
		}
		active[i].LiveArgoNote = fmt.Sprintf("По live-запросу статуса на %s: Health = %s, Sync = %s.", asOf, health, svc.SyncStatus)
	}
}

func tenantRow(t *apiTenant, extra tenantExtra, redact func(string) string) (statsTenant, []string) {
	var gaps []string
	members, roles := formatRoles(t.Members)
	name := t.Name
	display := t.DisplayName
	if display == "" {
		display = name
	}
	networking := t.Networking
	if networking == nil {
		networking = map[string]bool{}
	}
	row := statsTenant{
		Name:        name,
		DisplayName: display,
		Description: t.Description,
		Members:     members,
		Roles:       roles,
		Egress: statsEgress{
			Cluster:  networking["allowClusterEgress"],
			Internet: networking["allowInternetEgress"],
			Intra:    networking["allowIntraNamespace"],
		},
		Quota:    extra.quota,
		Repos:    extra.repos,
		Previews: extra.previews,
	}
	if extra.quotaErr != nil {
		gaps = append(gaps, "Квоты "+name+" недоступны: "+redact(extra.quotaErr.Error()))
	} else if extra.quotaNote != "" {
		gaps = append(gaps, "Квоты "+name+": "+redact(extra.quotaNote))
	}
	if extra.previewErr != nil {
		gaps = append(gaps, "Превью "+name+" недоступны: "+redact(extra.previewErr.Error()))
	}
	if extra.domainErr != nil {
		gaps = append(gaps, "Домены "+name+" недоступны: "+redact(extra.domainErr.Error()))
	} else {
		n := len(extra.domains)
		row.Domains = &n
	}
	if extra.repoErr != nil {
		gaps = append(gaps, "Репозитории "+name+" недоступны: "+redact(extra.repoErr.Error()))
	}
	return row, gaps
}

func (s *Server) redactString(msg string) string {
	return s.redactUpstream(errors.New(msg))
}

func formatRoles(members []apiMember) (int, string) {
	parts := make([]string, 0, len(members))
	for _, m := range members {
		if m.UserID == "" {
			continue
		}
		if m.Role != "" {
			parts = append(parts, m.UserID+" ("+m.Role+")")
		} else {
			parts = append(parts, m.UserID)
		}
	}
	return len(members), strings.Join(parts, ", ")
}

// --- quantities ---

func quotaFromMaps(used, allocated map[string]string) statsQuota {
	if used == nil {
		used = map[string]string{}
	}
	if allocated == nil {
		allocated = map[string]string{}
	}
	return statsQuota{
		CPULimU: parseCPUCores(firstQty(used, "limits.cpu", "cpu")),
		CPULimA: parseCPUCores(firstQty(allocated, "limits.cpu", "cpu")),
		CPUReqU: parseCPUCores(firstQty(used, "requests.cpu")),
		CPUReqA: parseCPUCores(firstQty(allocated, "requests.cpu")),
		MemLimU: parseMemoryMiB(firstQty(used, "limits.memory", "memory")),
		MemLimA: parseMemoryMiB(firstQty(allocated, "limits.memory", "memory")),
		MemReqU: parseMemoryMiB(firstQty(used, "requests.memory")),
		MemReqA: parseMemoryMiB(firstQty(allocated, "requests.memory")),
		PodsU:   parsePlain(firstQty(used, "pods")),
		PodsA:   parsePlain(firstQty(allocated, "pods")),
		SvcU:    parsePlain(firstQty(used, "services")),
		SvcA:    parsePlain(firstQty(allocated, "services")),
		PVCU:    parsePlain(firstQty(used, "persistentvolumeclaims")),
		PVCA:    parsePlain(firstQty(allocated, "persistentvolumeclaims")),
	}
}

func firstQty(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

func parseCPUCores(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if strings.HasSuffix(raw, "m") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(raw, "m"), 64)
		if err != nil {
			return 0
		}
		return n / 1000
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return n
}

func parseMemoryMiB(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	units := []struct {
		suffix string
		mult   float64
	}{
		{"Ki", 1.0 / 1024},
		{"Mi", 1},
		{"Gi", 1024},
		{"Ti", 1024 * 1024},
		{"k", 1000.0 / 1024 / 1024},
		{"K", 1000.0 / 1024 / 1024},
		{"M", 1000 * 1000 / 1024 / 1024},
		{"G", 1000 * 1000 * 1000 / 1024 / 1024},
		{"T", 1000.0 * 1000 * 1000 * 1000 / 1024 / 1024},
	}
	for _, u := range units {
		if strings.HasSuffix(raw, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(raw, u.suffix), 64)
			if err != nil {
				return 0
			}
			return n * u.mult
		}
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	// A bare Kubernetes memory quantity is bytes.
	return n / 1024 / 1024
}

func parsePlain(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return n
}

// --- dashboard shape (the view's DATA contract) ---

type statsDashboard struct {
	Meta       statsMeta        `json:"meta"`
	Tenants    []statsTenant    `json:"tenants"`
	Services   []statsService   `json:"services"`
	Incidents  statsIncidents   `json:"incidents"`
	Usage      statsUsage       `json:"usage"`
	Agents     statsAgents      `json:"agents"`
	Epics      []statsEpic      `json:"epics"`
	ReadyItems []statsReadyItem `json:"readyItems"`
	Platform   statsPlatform    `json:"platform"`
}

type statsMeta struct {
	URI             string   `json:"uri"`
	MIMEType        string   `json:"mimeType"`
	APIBase         string   `json:"apiBase"`
	User            string   `json:"user"`
	Admin           bool     `json:"admin"`
	Teams           []string `json:"teams"`
	Namespaces      []string `json:"namespaces"`
	DataAsOf        string   `json:"dataAsOf"`
	DataAsOfIso     string   `json:"dataAsOfIso"`
	Live            bool     `json:"live"`
	FilterTeam      string   `json:"filterTeam,omitempty"`
	FilterNamespace string   `json:"filterNamespace,omitempty"`
}

type statsTenant struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"displayName"`
	Description string      `json:"description"`
	Members     int         `json:"members"`
	Roles       string      `json:"roles"`
	Egress      statsEgress `json:"egress"`
	Quota       statsQuota  `json:"quota"`
	Repos       *int        `json:"repos"`
	Previews    *int        `json:"previews"`
	Domains     *int        `json:"domains"`
	Events1h    *int        `json:"events_1h"`
}

type statsEgress struct {
	Cluster  bool `json:"cluster"`
	Internet bool `json:"internet"`
	Intra    bool `json:"intra"`
}

type statsQuota struct {
	CPULimU float64 `json:"cpu_lim_u"`
	CPULimA float64 `json:"cpu_lim_a"`
	CPUReqU float64 `json:"cpu_req_u"`
	CPUReqA float64 `json:"cpu_req_a"`
	MemLimU float64 `json:"mem_lim_u"`
	MemLimA float64 `json:"mem_lim_a"`
	MemReqU float64 `json:"mem_req_u"`
	MemReqA float64 `json:"mem_req_a"`
	PodsU   float64 `json:"pods_u"`
	PodsA   float64 `json:"pods_a"`
	SvcU    float64 `json:"svc_u"`
	SvcA    float64 `json:"svc_a"`
	PVCU    float64 `json:"pvc_u"`
	PVCA    float64 `json:"pvc_a"`
}

type statsService struct {
	Team        string   `json:"team"`
	Name        string   `json:"name"`
	ImageTag    string   `json:"imageTag"`
	HasDatabase bool     `json:"hasDatabase"`
	SyncStatus  string   `json:"syncStatus"`
	Health      string   `json:"health"`
	Deployed    bool     `json:"deployed"`
	Hosts       []string `json:"hosts"`
	ArgoApp     string   `json:"argoApp"`
}

type statsIncidents struct {
	Available       bool            `json:"available"`
	Active          []statsIncident `json:"active"`
	ResolvedSummary statsResolved   `json:"resolvedSummary"`
}

type statsIncident struct {
	ID           string `json:"id"`
	Tenant       string `json:"tenant"`
	Service      string `json:"service"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	Type         string `json:"type"`
	Source       string `json:"source"`
	Confidence   string `json:"confidence"`
	Summary      string `json:"summary"`
	Analysis     string `json:"analysis"`
	CreatedCET   string `json:"created_cet"`
	LiveArgoNote string `json:"liveArgoNote"`
}

type statsResolved struct {
	Count      int            `json:"count"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
	BySource   map[string]int `json:"by_source"`
	ByTenant   map[string]int `json:"by_tenant"`
	ByResolver map[string]int `json:"by_resolver"`
	Daily      [][]any        `json:"daily"`
	Recent     []statsRecent  `json:"recent"`
}

type statsRecent struct {
	ID          string `json:"id"`
	Tenant      string `json:"tenant"`
	Service     string `json:"service"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Type        string `json:"type"`
	Source      string `json:"source"`
	Summary     string `json:"summary"`
	CreatedCET  string `json:"created_cet"`
	ResolvedCET string `json:"resolved_cet"`
	ResolvedBy  string `json:"resolved_by"`
}

type statsUsage struct {
	Available  bool            `json:"available"`
	Totals     statsTotals     `json:"totals"`
	ByAgent    []statsUsageRow `json:"byAgent"`
	ByModel    []statsUsageRow `json:"byModel"`
	ByStage    []statsUsageRow `json:"byStage"`
	ByProvider []statsUsageRow `json:"byProvider"`
	ByRepo     []statsUsageRow `json:"byRepo"`
}

type statsTotals struct {
	Invocations           int64    `json:"invocations"`
	Success               int64    `json:"success"`
	Error                 int64    `json:"error"`
	Interrupted           int64    `json:"interrupted"`
	CalculatedCost        float64  `json:"calculated_cost"`
	ProviderReportedCost  *float64 `json:"provider_reported_cost"`
	InvoiceReconciledCost *float64 `json:"invoice_reconciled_cost"`
	InputTokens           int64    `json:"input_tokens"`
	OutputTokens          int64    `json:"output_tokens"`
	CacheReadTokens       int64    `json:"cache_read_tokens"`
	CacheWriteTokens      int64    `json:"cache_write_tokens"`
	WebSearchRequests     int64    `json:"web_search_requests"`
}

type statsUsageRow struct {
	Key        string  `json:"key"`
	Count      int64   `json:"count"`
	Cost       float64 `json:"cost"`
	Input      int64   `json:"input"`
	Output     int64   `json:"output"`
	CacheRead  int64   `json:"cache_read"`
	CacheWrite int64   `json:"cache_write"`
}

type statsAgents struct {
	Available   bool            `json:"available"`
	Registry    []statsAgentReg `json:"registry"`
	Profiles    []statsProfile  `json:"profiles"`
	Releases    []statsRelease  `json:"releases"`
	Executions  statsExecutions `json:"executions"`
	Ownership   statsOwnership  `json:"ownership"`
	SkillsCount int             `json:"skillsCount"`
	RecentRuns  statsRecentRuns `json:"recentRuns"`
}

type statsAgentReg struct {
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	V1       int    `json:"v1"`
	V1Alpha2 int    `json:"v1alpha2"`
}

type statsProfile struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	BudgetUsd      *float64 `json:"budgetUsd"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
	PolicyRef      string   `json:"policyRef"`
	ApprovalGates  []string `json:"approvalGates"`
	ToolsCount     int      `json:"toolsCount"`
}

type statsRelease struct {
	Agent          string `json:"agent"`
	Environment    string `json:"environment"`
	DefVersion     string `json:"defVersion"`
	ProfileName    string `json:"profileName"`
	ProfileVersion string `json:"profileVersion"`
	BindingSource  string `json:"bindingSource"`
	Promotable     bool   `json:"promotable"`
}

type statsExecutions struct {
	Count     int            `json:"count"`
	ByAgent   map[string]int `json:"by_agent"`
	ByRepo    map[string]int `json:"by_repo"`
	ByPhase   map[string]int `json:"by_phase"`
	OldestCET string         `json:"oldest_cet"`
	NewestCET string         `json:"newest_cet"`
}

type statsOwnership struct {
	Count     int            `json:"count"`
	Truncated bool           `json:"truncated"`
	AsOfCET   string         `json:"as_of_cet"`
	ByStatus  map[string]int `json:"by_status"`
	Stuck     []statsStuck   `json:"stuck"`
}

type statsStuck struct {
	EntityID           string  `json:"entity_id"`
	Phase              string  `json:"phase"`
	WorkflowID         string  `json:"workflow_id"`
	ProposalRef        string  `json:"proposal_ref"`
	LastSeenCET        string  `json:"last_seen_cet"`
	LastProgressCET    string  `json:"last_progress_cet"`
	HoursSinceProgress float64 `json:"hours_since_progress"`
	Status             string  `json:"status"`
}

type statsRecentRuns struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type statsEpic struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Complete int    `json:"complete"`
	Ready    int    `json:"ready"`
	Blocked  int    `json:"blocked"`
	Unknown  int    `json:"unknown"`
	Total    int    `json:"total"`
	Drift    int    `json:"drift"`
}

type statsReadyItem struct {
	Epic     string `json:"epic"`
	ID       string `json:"id"`
	Repo     string `json:"repo"`
	Phase    string `json:"phase"`
	Required bool   `json:"required"`
}

type statsPlatform struct {
	Operations  statsOps         `json:"operations"`
	Commerce    statsCommerce    `json:"commerce"`
	Domains     []statsDomain    `json:"domains"`
	SyncWindows statsSyncWindows `json:"syncWindows"`
	Signups     []any            `json:"signups"`
	Events      map[string]any   `json:"events"`
	DataGaps    []string         `json:"dataGaps"`
}

type statsOps struct {
	Count   int            `json:"count"`
	ByRisk  map[string]int `json:"by_risk"`
	ByScope map[string]int `json:"by_scope"`
}

type statsCommerce struct {
	Available bool `json:"available"`
}

type statsDomain struct {
	Team        string `json:"team"`
	Service     string `json:"service"`
	Domain      string `json:"domain"`
	CNAMETarget string `json:"cnameTarget"`
	Status      string `json:"status"`
	VerifiedCET string `json:"verifiedCet"`
}

type statsSyncWindows struct {
	Available bool `json:"available"`
	Apps      *int `json:"apps"`
	Platform  *int `json:"platform"`
	Default   *int `json:"default"`
}

func newStatsDashboard(id statsIdentity, now time.Time) *statsDashboard {
	loc := statsLocation()
	local := now.In(loc)
	teams := uniqueStrings(id.Groups)
	namespaces := uniqueStrings(id.Namespaces)
	if len(namespaces) == 0 {
		namespaces = append([]string{}, teams...)
	}
	return &statsDashboard{
		Meta: statsMeta{
			URI:         statsAppURI,
			MIMEType:    statsAppMIME,
			User:        id.ID,
			Admin:       id.admin(),
			Teams:       teams,
			Namespaces:  namespaces,
			DataAsOf:    local.Format("2006-01-02 15:04 MST") + " (Europe/Podgorica)",
			DataAsOfIso: local.Format(time.RFC3339),
			Live:        true,
		},
		Tenants:    []statsTenant{},
		Services:   []statsService{},
		Incidents:  statsIncidents{Active: []statsIncident{}, ResolvedSummary: emptyResolved()},
		Usage:      emptyUsage(),
		Agents:     emptyAgents(),
		Epics:      []statsEpic{},
		ReadyItems: []statsReadyItem{},
		Platform: statsPlatform{
			Operations:  statsOps{ByRisk: map[string]int{}, ByScope: map[string]int{}},
			Commerce:    statsCommerce{Available: false},
			Domains:     []statsDomain{},
			SyncWindows: statsSyncWindows{Available: false},
			Signups:     []any{},
			Events:      map[string]any{},
			DataGaps:    []string{},
		},
	}
}

func emptyResolved() statsResolved {
	return statsResolved{
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
		BySource:   map[string]int{},
		ByTenant:   map[string]int{},
		ByResolver: map[string]int{},
		Daily:      [][]any{},
		Recent:     []statsRecent{},
	}
}

func emptyUsage() statsUsage {
	return statsUsage{
		ByAgent:    []statsUsageRow{},
		ByModel:    []statsUsageRow{},
		ByStage:    []statsUsageRow{},
		ByProvider: []statsUsageRow{},
		ByRepo:     []statsUsageRow{},
	}
}

func emptyAgents() statsAgents {
	return statsAgents{
		Registry: []statsAgentReg{},
		Profiles: []statsProfile{},
		Releases: []statsRelease{},
		Executions: statsExecutions{
			ByAgent: map[string]int{},
			ByRepo:  map[string]int{},
			ByPhase: map[string]int{},
		},
		Ownership: statsOwnership{
			ByStatus: map[string]int{"terminal": 0, "released": 0, "stuck": 0},
			Stuck:    []statsStuck{},
		},
	}
}

// --- HTTP and small helpers ---

func (s *Server) getJSON(ctx context.Context, path string, dest any) (int, error) {
	body, status, err := s.apiGetStatus(ctx, path)
	if err != nil {
		return status, err
	}
	if status >= 400 {
		return status, fmt.Errorf("API status %d: %s", status, clipAPIBody(body))
	}
	if dest != nil && len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, dest); err != nil {
			return status, fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return status, nil
}

func (s *Server) getCount(ctx context.Context, path string) (int, error) {
	body, status, err := s.apiGetStatus(ctx, path)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("API status %d: %s", status, clipAPIBody(body))
	}
	n, ok := countJSONItems(body)
	if !ok {
		return 0, fmt.Errorf("unexpected payload from %s", path)
	}
	return n, nil
}

func countJSONItems(body []byte) (int, bool) {
	var env struct {
		Count *int              `json:"count"`
		Items []json.RawMessage `json:"items"`
		Repos []json.RawMessage `json:"repos"`
	}
	if err := json.Unmarshal(body, &env); err == nil && (env.Count != nil || env.Items != nil || env.Repos != nil) {
		if env.Count != nil {
			return *env.Count, true
		}
		if env.Items != nil {
			return len(env.Items), true
		}
		return len(env.Repos), true
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err == nil {
		return len(arr), true
	}
	return 0, false
}

func clipAPIBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "empty body"
	}
	const maxClip = 160
	if len(s) <= maxClip {
		return s
	}
	// Cut on a rune boundary so a multi-byte character at the edge is dropped
	// whole instead of leaving an invalid UTF-8 tail in the gap text.
	cut := maxClip
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func statsLocation() *time.Location {
	loc, err := time.LoadLocation("Europe/Podgorica")
	if err != nil {
		return time.FixedZone("CET", 3600)
	}
	return loc
}

func formatStatsTime(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format("2006-01-02 15:04 MST")
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func intPtr(n int) *int { return &n }

func n64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func floatOr0(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

func addOpt(dst **float64, v *float64) {
	if v == nil {
		return
	}
	if *dst == nil {
		z := 0.0
		*dst = &z
	}
	**dst += *v
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func incMap(m map[string]int, key string) {
	if key == "" {
		key = "—"
	}
	m[key]++
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func dedupeStrings(in []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func firstFloat(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return v, true
		case json.Number:
			f, err := v.Float64()
			if err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

func firstInt(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int(v), true
		case json.Number:
			n, err := v.Int64()
			if err == nil {
				return int(n), true
			}
		}
	}
	return 0, false
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
