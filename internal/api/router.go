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

package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/mctlhq/mctl-api/internal/agentregistry"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/openapi"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Options holds all dependencies for the API router.
type Options struct {
	Registry       *operations.Registry
	GitReader      GitReader
	ArgoCD         ArgoStatusClient
	AuditLog       AuditLog
	Executor       WorkflowExecutor
	AuthMiddleware func(http.Handler) http.Handler
	// MCPServer exposes platform tools over MCP Streamable HTTP at /mcp.
	MCPServer *mctlmcp.Server
	// QuotaReader fetches live K8s resource usage (optional — nil in local/test).
	QuotaReader QuotaReader
	// LogQuerier queries Loki for service logs (optional — nil outside cluster).
	LogQuerier LogQuerier
	// WorkflowLogArchive reads archived Argo step logs from object storage
	// (optional — nil when the archive env vars are unset).
	WorkflowLogArchive WorkflowLogArchive
	// VaultReader checks persisted secrets for onboarding preflight (optional — nil outside cluster).
	VaultReader VaultReader
	// MetricsQuerier fetches historical runtime usage for right-sizing decisions (optional).
	MetricsQuerier MetricsQuerier
	// Optional Backstage integration for immediate catalog sync.
	BackstageURL   string
	BackstageToken string
	// BackstageInternalURL is the cluster-internal URL for Backstage (e.g. http://backstage.backstage.svc:7007).
	// Used for proxying repo operations to the github-app-connect plugin.
	BackstageInternalURL string
	// AllowedOrigins is the list of origins permitted by CORS.
	// If empty, no Access-Control-Allow-Origin header is set (deny all cross-origin).
	AllowedOrigins []string
	// OAuthServer handles OAuth 2.0 Authorization Code + PKCE flow for Claude.ai connectors.
	// If nil, all /oauth/* endpoints return 404.
	OAuthServer *auth.OAuthServer
	// AlertStore persists incident alerts to PostgreSQL (optional — nil disables incident endpoints).
	AlertStore *alerts.Store
	// AgentRegistry persists mctl-agents AgentManifest versions/releases to
	// PostgreSQL (optional — nil disables the agent registry endpoints).
	AgentRegistry *agentregistry.Store
	// TemporalClient starts/signals DevLoopWorkflow runs on the dev-workflow
	// control plane's Temporal deployment (optional — nil disables
	// mctl_trigger_issue's use_temporal path; callers fall back to the
	// direct Argo submission they already use today). Typed as the
	// DevLoopClient interface, not the concrete *temporalclient.Client, so
	// tests can inject a fake — see interfaces.go.
	TemporalClient DevLoopClient
	// OpenClaw controls quota and rate limits on the skill/identity save handlers.
	// Zero values fall back to defaults (see OpenClawQuotaDefaults).
	OpenClaw OpenClawQuotaConfig
	// GitopsReady / PostgresReady / DexReady / VaultReady are optional
	// dependency probes for GET /readyz. A nil check is reported as
	// not_configured and does not fail readiness (tests, local without Vault).
	GitopsReady   ReadyCheck
	PostgresReady ReadyCheck
	DexReady      ReadyCheck
	VaultReady    ReadyCheck
	// ArgoWebhookSecret authenticates POST /api/v1/workflows/events/argo-complete.
	// Fail-closed: an empty secret rejects every callback.
	ArgoWebhookSecret string
	// OAuthRegistrationToken, when non-empty, requires Authorization: Bearer
	// <token> on POST /oauth/register (RFC 7591 initial access token).
	OAuthRegistrationToken string
	// TrustedProxyCIDRs are Traefik (or other ingress) source ranges. X-Forwarded-For
	// is used for audit client IP only when RemoteAddr is in this list.
	TrustedProxyCIDRs []*net.IPNet
}

// Handlers holds all API handler dependencies.
type Handlers struct {
	opts Options
	// openClawQuota is the effective quota config after default fill-in.
	// Pre-computed at router init so each save call is a plain map lookup.
	openClawQuota       OpenClawQuotaConfig
	openClawRateLimiter *saveRateLimiter
}

// NewRouter creates the HTTP router with all API routes.
func NewRouter(opts Options) http.Handler {
	quota := opts.OpenClaw.withDefaults()
	h := &Handlers{
		opts:                opts,
		openClawQuota:       quota,
		openClawRateLimiter: newSaveRateLimiter(quota.SaveRatePerHour),
	}

	r := chi.NewRouter()

	// Infrastructure middleware (no auth). clientMetaMiddleware resolves the
	// client IP once, honouring X-Forwarded-For only from TrustedProxyCIDRs;
	// audit entries and rate-limit keys both read it back from the context.
	// chi's middleware.RealIP is deliberately absent — it rewrites RemoteAddr
	// from an attacker-supplied header and now has no consumer here.
	r.Use(middleware.RequestID)
	r.Use(clientMetaMiddleware(opts.TrustedProxyCIDRs))
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders())
	r.Use(corsMiddleware(opts.AllowedOrigins))
	r.Use(metricsMiddleware())

	// Health checks and metrics (no auth). /metrics is cluster-only: ingress
	// sets X-Forwarded-* and is 404'd; kube probes and vmagent scrape the
	// Service directly.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", h.handleReadyz)
	r.Handle("/metrics", clusterOnly(promhttp.Handler()))

	// OpenAPI spec — public, no auth required.
	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(openapi.Spec)
	})
	// Swagger UI redirect — opens editor.swagger.io pre-loaded with our spec.
	r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
		scheme := "https"
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
			scheme = "http"
		}
		specURL := scheme + "://" + r.Host + "/openapi.yaml"
		target := "https://petstore.swagger.io/?url=" + specURL
		http.Redirect(w, r, target, http.StatusFound)
	})

	// OAuth 2.0 endpoints — public (no user auth middleware), required for
	// Claude.ai connector. Rate-limited per IP because they sit outside the
	// authenticated group. Registration is tighter: it mints client_ids.
	r.Group(func(r chi.Router) {
		r.Use(httprate.Limit(60, 1*time.Minute, httprate.WithKeyFuncs(keyByTrustedIP)))
		r.Get("/.well-known/oauth-authorization-server", h.handleOAuthMeta)
		// RFC 9728 Protected Resource Metadata — registered at both the root path
		// and the /mcp-suffixed alias since clients probe either form.
		r.Get("/.well-known/oauth-protected-resource", h.handleProtectedResourceMeta)
		r.Get("/.well-known/oauth-protected-resource/mcp", h.handleProtectedResourceMeta)
		r.Get("/oauth/authorize", h.handleOAuthAuthorize)
		r.Get("/oauth/github/callback", h.handleOAuthGitHubCallback)
		r.Post("/oauth/token", h.handleOAuthToken)
		r.Post("/oauth/revoke", h.handleOAuthRevoke)
	})
	r.Group(func(r chi.Router) {
		// Keyed by IP, so every process of one desktop MCP client shares the
		// budget. That broke the Antigravity CLI at the previous limit of 5:
		// it fans out across ~8 processes that each run their own dynamic
		// registration on start, and the whole cold start therefore 429'd
		// every time, with no path to a token at all.
		//
		// The low limit was carrying the memory bound as well, since the
		// registration map was unbounded. That is now capped and evicting
		// (OAuthServer.MaxRegisteredClients), so this can be sized for real
		// client behaviour and still stay far below what abuse would need.
		r.Use(httprate.Limit(30, 1*time.Minute, httprate.WithKeyFuncs(keyByTrustedIP)))
		r.Post("/oauth/register", h.handleOAuthRegister)
	})

	// Webhook callbacks (unauthenticated/token-validated)
	r.Post("/api/v1/workflows/events/argo-complete", h.HandleArgoWorkflowComplete)

	// Authenticated API routes.
	r.Group(func(r chi.Router) {
		if opts.AuthMiddleware != nil {
			r.Use(opts.AuthMiddleware)
		}
		r.Use(middleware.Timeout(30 * 1000000000)) // 30s

		// Global rate limit: 100 requests/minute per user (fallback to per-IP).
		r.Use(httprate.Limit(100, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			if user := auth.UserFromContext(r.Context()); user != nil {
				return "user:" + user.ID, nil
			}
			return keyByTrustedIP(r)
		})))

		r.Route("/api/v1", func(r chi.Router) {
			// Auth endpoints.
			r.Get("/whoami", h.Whoami)
			r.Post("/auth/logout", h.Logout)

			// Read endpoints (safe, no side effects).
			r.Get("/tenants", h.ListTenants)
			r.Get("/tenants/{name}", h.GetTenant)
			r.Get("/services", h.ListServices)
			r.Get("/services/{team}/{app}", h.GetService)
			r.Get("/status/{team}/{app}", h.GetServiceStatus)
			r.Get("/workflows", h.ListWorkflows)
			r.Get("/workflows/{name}", h.GetWorkflow)
			r.Get("/workflows/{name}/logs", h.GetWorkflowLogs)
			r.Get("/previews", h.ListPreviews)
			r.Get("/resources/{tenant}", h.GetResourceUsage)
			r.Get("/logs/{team}/{app}", h.GetServiceLogs)
			r.Get("/audit", h.ListAudit)
			r.Get("/agent-runs", h.ListAgentRuns)

			// Platform-wide skill registry.
			r.Get("/platform-skills", h.ListPlatformSkills)
			r.Get("/platform-skills/bindings/tenants", h.ListTenantSkillBindings)
			r.Post("/platform-skills/bindings/tenants/enable", h.EnableTenantSkill)
			r.Post("/platform-skills/bindings/tenants/disable", h.DisableTenantSkill)
			r.Post("/platform-skills", h.PublishPlatformSkill)
			r.Get("/platform-skills/{name}", h.ReadPlatformSkill)
			r.Post("/platform-skills/{name}/deprecate", h.DeprecatePlatformSkill)

			// Repository discovery (proxied to Backstage github-app-connect plugin).
			r.Get("/repos", h.ListRepos)
			r.Get("/repos/install-url", h.GetRepoInstallURL)
			r.Post("/repos/sync", h.SyncRepos)

			// OpenClaw self-service onboarding and right-sizing.
			r.Post("/openclaw/deploy/start", h.StartOpenClawDeploy)
			r.Post("/openclaw/deploy/resume", h.ResumeOpenClawDeploy)
			r.Get("/openclaw/{team}/{app}/sizing", h.GetOpenClawSizingRecommendation)
			r.Post("/openclaw/{team}/{app}/resource-profile", h.ApplyOpenClawResourceProfile)
			r.Get("/openclaw/{team}/skills", h.ListOpenClawSkills)
			r.Get("/openclaw/{team}/skills/{name}", h.GetOpenClawSkill)
			r.Post("/openclaw/{team}/skills", h.SaveOpenClawSkill)
			r.Delete("/openclaw/{team}/skills/{name}", h.DeleteOpenClawSkill)
			r.Get("/openclaw/{team}/identity", h.ListOpenClawIdentity)
			r.Get("/openclaw/{team}/identity/{name}", h.GetOpenClawIdentity)
			r.Post("/openclaw/{team}/identity", h.SaveOpenClawIdentity)
			r.Delete("/openclaw/{team}/identity/{name}", h.DeleteOpenClawIdentity)

			// Custom domains (proxied to Backstage custom-domains plugin).
			r.Get("/domains", h.ListDomains)
			r.Post("/domains", h.AddDomain)
			r.Post("/domains/{id}/verify", h.VerifyDomain)
			r.Delete("/domains/{id}", h.DeleteDomain)

			// Incident endpoints (alert store).
			r.Get("/incidents/summary", h.IncidentSummary)
			r.Get("/incidents", h.ListIncidents)
			r.Get("/incidents/{id}", h.GetIncident)
			r.Post("/incidents", h.CreateIncident)
			r.Post("/incidents/resolve-by-fingerprint", h.ResolveIncidentByFingerprint)
			r.Patch("/incidents/{id}", h.UpdateIncident)
			r.Post("/incidents/{id}/ack", h.AcknowledgeIncident)
			r.Post("/incidents/{id}/resolve", h.ResolveIncident)

			// Agent registry (mctl-agents AgentManifest versions/releases). Admin-only.
			r.Post("/agents", h.CreateAgentDefinition)
			r.Post("/agents/{name}/versions", h.PublishAgentVersion)
			r.Get("/agents/{name}/versions", h.ListAgentVersions)
			r.Post("/agents/{name}/releases", h.UpdateAgentRelease)
			r.Get("/agents/{name}/resolve", h.ResolveAgentRelease)
			// No collision with the /agents/{name}/... routes above today —
			// those are all 3 segments, this is 2. If a 2-segment
			// GET /agents/{name} is ever added, chi's radix tree still
			// prefers this static "executions" match over it; keep them
			// adjacent so that stays easy to notice.
			r.Post("/agents/executions", h.RecordAgentExecution)
			r.Get("/agents/executions", h.ListAgentExecutions)

			// Write endpoints with real side effects (trigger Argo Workflows,
			// start/signal a Temporal workflow) — tighter rate limit, shared
			// so every route in this group inherits it instead of each one
			// needing its own With(...) (a route added here without it would
			// silently bypass the limit, same write-cost profile as
			// /operations/{name}/execute below).
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(20, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "write:" + user.ID, nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/operations/{name}/execute", h.ExecuteOperation)
				r.Post("/agents/dev-loop/start", h.StartDevLoopWorkflow)
				r.Post("/agents/dev-loop/{workflow_id}/approve", h.ApproveDevLoopWorkflow)
			})

			// Liveness read for one DevLoopWorkflow. Deliberately OUTSIDE the
			// write group above: it has no side effects, and the shepherd
			// sweeper calls it once per actionable proposal per tick (#213),
			// which would eat the 20/min write budget shared with
			// /operations/{name}/execute and starve real writes.
			r.Get("/agents/dev-loop/{workflow_id}", h.GetDevLoopWorkflow)

			// Operation registry (metadata only).
			r.Get("/operations", h.ListOperations)
			r.Get("/operations/{name}", h.GetOperation)
		})

		// MCP Streamable HTTP transport — single endpoint for Claude Desktop, Cursor, etc.
		// POST /mcp  → send request (can return streaming SSE response)
		// GET  /mcp  → open persistent listen stream (optional, for server-initiated messages)
		// Auth: Authorization: Bearer <token> on every request.
		if opts.MCPServer != nil {
			mcpH := opts.MCPServer.NewStreamableHTTPHandler()
			r.Post("/mcp", mcpH.ServeHTTP)
			r.Get("/mcp", mcpH.ServeHTTP)
			r.Delete("/mcp", mcpH.ServeHTTP)
		}
	})

	return r
}

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "path", "code"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

// metricsMiddleware returns middleware that records Prometheus metrics for each
// request. It skips infrastructure paths (/healthz, /readyz, /metrics) to avoid
// noise. The chi route pattern is used for the path label to prevent high cardinality.
func metricsMiddleware() func(http.Handler) http.Handler {
	skip := map[string]bool{
		"/healthz": true,
		"/readyz":  true,
		"/metrics": true,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()

			next.ServeHTTP(ww, r)

			duration := time.Since(start).Seconds()

			path := r.URL.Path
			if rctx := chi.RouteContext(r.Context()); rctx != nil {
				if pattern := rctx.RoutePattern(); pattern != "" {
					path = pattern
				}
			}

			httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(ww.Status())).Inc()
			httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
		})
	}
}

// corsMiddleware returns middleware that validates the request Origin against
// a list of allowed origins. If the origin matches, it sets the appropriate
// CORS headers. If no origins are configured, all cross-origin requests are denied.
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimSpace(o)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
