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
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/openapi"
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
	MCPServer      *mctlmcp.Server
	// QuotaReader fetches live K8s resource usage (optional — nil in local/test).
	QuotaReader    QuotaReader
	// LogQuerier queries Loki for service logs (optional — nil outside cluster).
	LogQuerier     LogQuerier
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
	OAuthServer    *auth.OAuthServer
	// AlertStore persists incident alerts to PostgreSQL (optional — nil disables incident endpoints).
	AlertStore     *alerts.Store
}

// Handlers holds all API handler dependencies.
type Handlers struct {
	opts Options
}

// NewRouter creates the HTTP router with all API routes.
func NewRouter(opts Options) http.Handler {
	h := &Handlers{opts: opts}

	r := chi.NewRouter()

	// Infrastructure middleware (no auth).
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware(opts.AllowedOrigins))

	// Health checks (no auth).
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	// OpenAPI spec — public, no auth required.
	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Cache-Control", "public, max-age=300")
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

	// OAuth 2.0 endpoints — public (no auth middleware), required for Claude.ai connector.
	r.Get("/.well-known/oauth-authorization-server", h.handleOAuthMeta)
	r.Get("/oauth/authorize", h.handleOAuthAuthorize)
	r.Get("/oauth/github/callback", h.handleOAuthGitHubCallback)
	r.Post("/oauth/token", h.handleOAuthToken)
	r.Post("/oauth/revoke", h.handleOAuthRevoke)
	r.Post("/oauth/register", h.handleOAuthRegister)

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
			return httprate.KeyByRealIP(r)
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
			r.Get("/previews", h.ListPreviews)
			r.Get("/resources/{tenant}", h.GetResourceUsage)
			r.Get("/logs/{team}/{app}", h.GetServiceLogs)
			r.Get("/audit", h.ListAudit)

			// Repository discovery (proxied to Backstage github-app-connect plugin).
			r.Get("/repos", h.ListRepos)
			r.Get("/repos/install-url", h.GetRepoInstallURL)
			r.Post("/repos/sync", h.SyncRepos)

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
			r.Patch("/incidents/{id}", h.UpdateIncident)
			r.Post("/incidents/{id}/ack", h.AcknowledgeIncident)
			r.Post("/incidents/{id}/resolve", h.ResolveIncident)

			// Operation registry (metadata only).
			r.Get("/operations", h.ListOperations)
			r.Get("/operations/{name}", h.GetOperation)

			// Write endpoints (trigger Argo Workflows) — tighter rate limit.
			r.With(httprate.Limit(20, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
				if user := auth.UserFromContext(r.Context()); user != nil {
					return "write:" + user.ID, nil
				}
				return httprate.KeyByRealIP(r)
			}))).Post("/operations/{name}/execute", h.ExecuteOperation)
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
