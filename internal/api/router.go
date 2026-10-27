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
	"context"
	"log/slog"
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
	"github.com/mctlhq/mctl-api/internal/commerce"
	"github.com/mctlhq/mctl-api/internal/decisions"
	"github.com/mctlhq/mctl-api/internal/delegation"
	"github.com/mctlhq/mctl-api/internal/deployanalyze"
	"github.com/mctlhq/mctl-api/internal/domains"
	"github.com/mctlhq/mctl-api/internal/evidence"
	"github.com/mctlhq/mctl-api/internal/governance"
	"github.com/mctlhq/mctl-api/internal/humaninput"
	"github.com/mctlhq/mctl-api/internal/lifecycle"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
	"github.com/mctlhq/mctl-api/internal/openapi"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/roadmap"
	"github.com/mctlhq/mctl-api/internal/securityfindings"
	"github.com/mctlhq/mctl-api/internal/surfaceid"
	"github.com/mctlhq/mctl-api/internal/usage"
	"github.com/mctlhq/mctl-api/internal/workitems"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Options holds all dependencies for the API router.
type Options struct {
	Signup                        *SignupOptions
	CustomerDeletion              *CustomerDeletionOptions
	CustomerTenantDeletionPending func(context.Context, string) (bool, error)

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
	// PreviewLister lists preview Helm releases (optional — nil means listing is unavailable).
	PreviewLister PreviewLister
	// WorkloadReader reads pod state and events (optional — nil means 503).
	WorkloadReader WorkloadReader
	// LogQuerier queries Loki for service logs (optional — nil outside cluster).
	LogQuerier LogQuerier
	// ComponentSourceRepos answers which repository is registered for a
	// component, for CI deploys (mctl-api#530). Nil refuses every CI deploy
	// with 503.
	ComponentSourceRepos ComponentSourceRepoReader
	// SourceRepoBindings answers which services are built from a repository
	// (the reverse of ComponentSourceRepos), for the deploy reads. Nil
	// answers 503 deploy_binding_unavailable.
	SourceRepoBindings SourceRepoBindingReader
	// DeployContentReader reads repository content at a pinned commit for
	// deploy analysis. Nil answers 502 deploy_github_unavailable.
	DeployContentReader deployanalyze.ContentReader
	// WorkflowLogArchive reads archived Argo step logs from object storage
	// (optional — nil when the archive env vars are unset).
	WorkflowLogArchive WorkflowLogArchive
	// BackstageInternalURL is the cluster-internal URL for Backstage (e.g. http://backstage.backstage.svc:7007).
	// Used for proxying repo operations to the github-app-connect plugin.
	BackstageInternalURL string
	// GitHubAPIBaseURL overrides https://api.github.com for the build
	// repository gate's public-repository check (tests only).
	GitHubAPIBaseURL string
	// BackstageGithubAppConnectToken authorizes calls to Backstage's
	// github-app-connect plugin (repos list/sync/install-url). When empty,
	// the repos routes answer 503 without
	// calling Backstage.
	BackstageGithubAppConnectToken string
	// AllowedOrigins is the list of origins permitted by CORS.
	// If empty, no Access-Control-Allow-Origin header is set (deny all cross-origin).
	AllowedOrigins []string
	// OAuthServer handles OAuth 2.0 Authorization Code + PKCE flow for Claude.ai connectors.
	// If nil, all /oauth/* endpoints return 404.
	OAuthServer *auth.OAuthServer
	// IdentityLink configures explicit identity linking (mctl-api#435,
	// handlers_identity_link.go). Nil disables it (503).
	IdentityLink *IdentityLinkOptions
	// OAuthUpstream is where /oauth/authorize signs people in
	// (OAUTH_UPSTREAM, mctl-api#467); the zero value is GitHub.
	OAuthUpstream OAuthUpstreamMode
	// OAuthZitadel configures the ZITADEL upstream; nil keeps it off.
	OAuthZitadel *OAuthZitadelOptions
	// SurfaceZitadel configures POST /api/v1/surface-principals/zitadel;
	// nil leaves it answering 503.
	SurfaceZitadel *SurfaceZitadelOptions
	// AlertStore persists incident alerts to PostgreSQL (optional — nil disables incident endpoints).
	AlertStore *alerts.Store
	// DomainStore persists custom domain registrations to PostgreSQL
	// (optional — nil makes every /api/v1/domains* route return 503).
	// mctl-api is the system of record here; it no longer proxies to the
	// Backstage custom-domains plugin (that write route requires a Backstage
	// user principal none of mctl-api's callers can produce).
	DomainStore *domains.Store
	// DomainVerifier resolves TXT/CNAME records to prove custom domain
	// ownership (optional — nil makes /domains/*verify return 503).
	DomainVerifier *domains.Verifier
	// PlatformDomain is the platform's own domain (e.g. "mctl.ai"). Hostnames
	// equal to or ending in "."+PlatformDomain are rejected by AddDomain —
	// those stay GitOps-only via ingress.hosts. Defaults to "mctl.ai" when empty.
	PlatformDomain string
	// ErpactDeployer is the ERPact site-deployer client (mctl-api#486). A
	// temporary, tenant-`erpact`-only stopgap: nil makes every
	// /api/v1/tenants/erpact/sites* route 503, which is also how the feature
	// is switched off entirely (no deployer token configured).
	ErpactDeployer ErpactDeployer
	// AgentRegistry persists mctl-agents AgentManifest versions/releases to
	// PostgreSQL (optional — nil disables the agent registry endpoints).
	AgentRegistry *agentregistry.Store
	// Lifecycle records which actor owns advancing an entity through a
	// lifecycle phase (optional — nil makes the lifecycle endpoints 503,
	// which callers treat as "unknown", never as "unowned").
	Lifecycle *lifecycle.Store

	// SurfaceIdentities stores SurfaceIdentityLinks (mctl-api#350).
	// Optional: nil makes the surface-identity endpoints 503.
	SurfaceIdentities *surfaceid.Store
	// TenantResolver gives a relayed subject its tenant memberships, the
	// same lookup authentication uses. Nil relays with no tenant access.
	TenantResolver auth.TenantResolver
	// Principals resolves a relayed human to their canonical principal
	// (mctl-api#373 phase 1), as authentication does for a direct caller.
	// Nil relays without a principal id.
	Principals auth.PrincipalResolver
	// LegacyApproverDisabled is MCTL_AGENTS_APPROVE_LEGACY_APPROVER=false
	// (mctl-api#571). The zero value keeps the service principal's
	// free-text approver relay on mctl-agents-approve, audited per use as
	// approver.legacy_relay; true refuses it.
	LegacyApproverDisabled bool
	// TenantAuthzMode is TENANT_AUTHZ_MODE (mctl-api#377). The zero value
	// behaves as legacy; shadow also compares the principal-keyed decision
	// (tenantAuthzShadow) without acting on it.
	TenantAuthzMode TenantAuthzMode
	// AgentReceiptGateMode is MCTL_AGENT_RECEIPT_GATE (mctl-api#723): off,
	// observe or enforce for the MCP agent receipt gate. The zero value is
	// off.
	AgentReceiptGateMode mctlmcp.AgentReceiptGateMode
	// AgentReceiptMaxAge is MCTL_AGENT_RECEIPT_MAX_AGE (mctl-api#773): how
	// long after its consume a receipt still authorizes a call. Zero is
	// mctlmcp.DefaultAgentReceiptMaxAge.
	AgentReceiptMaxAge time.Duration
	// PrincipalMembership is the principal-keyed membership shadow mode
	// reads. Nil makes every shadow comparison unresolved.
	PrincipalMembership PrincipalMembershipReader
	// AdminPrincipals is ADMIN_PRINCIPALS. In principal mode it is the only
	// source of platform admin (auth.PrincipalAuthz); in shadow mode, when
	// set, each request's legacy admin decision is compared with it.
	AdminPrincipals map[string]bool
	// Policies is the registered policy set action approvals are revalidated
	// against (mctl-api#700). Nil means governance.Policies; tests inject
	// another to exercise policy drift.
	Policies governance.PolicySet
	// RequireRegisteredPolicy is ACTION_APPROVAL_REQUIRE_REGISTERED_POLICY:
	// an approval under a policy rule that is not in Policies cannot be spent.
	RequireRegisteredPolicy bool
	// ApprovalMaxDecisionAge is ACTION_APPROVAL_MAX_DECISION_AGE: how long an
	// approval stays spendable after it was decided. Zero means
	// governance.DefaultMaxDecisionAge.
	ApprovalMaxDecisionAge time.Duration
	// Clock replaces time.Now for approval freshness; nil is time.Now.
	Clock func() time.Time
	// PrincipalAuthz decides, in principal mode, a relayed or delegated
	// subject's tenants by its principal, exactly as the middleware decides
	// a direct caller's (mctl-api#377 B5). Nil in principal mode makes every
	// relay and delegation 503, never a login-keyed fallback.
	PrincipalAuthz *auth.PrincipalAuthz
	// MemberKeyPlan backs the read-only principal-key plan for GitOps
	// member entries (mctl-api#377 A5). Nil makes it 503.
	MemberKeyPlan *MemberKeyPlanOptions
	// Delegation resolves an X-MCTL-On-Behalf-Of grant ref to the stored
	// subject it names (mctl-api#376 slice B). Optional: nil makes every
	// delegated request 503, never an undelegated one.
	Delegation delegation.Resolver

	// Roadmap serves the RoadmapPublication read model (mctl-api#333).
	// Optional: nil makes the roadmap endpoints 503.
	Roadmap *roadmap.Reader
	// RoadmapWaveMaxAge bounds how old the latest publication's observation
	// may be when a wave executes (mctl-api#334). Zero means
	// DefaultRoadmapWaveMaxAge; negative means the configuration was
	// invalid, and execution is refused.
	RoadmapWaveMaxAge time.Duration
	// RoadmapWaveDisabledReason names the setting that disabled wave
	// execution; reported in responses. Empty falls back to
	// ROADMAP_WAVE_MAX_AGE.
	RoadmapWaveDisabledReason string

	// Usage is the durable model-usage and cost ledger (mctl-api#266,
	// ADR-012). Optional — nil makes the usage endpoints 503, which a caller
	// must read as "the ledger is unavailable" and never as "nothing was
	// spent".
	Usage *usage.Store
	// Commerce is the durable commerce ledger of ADR 020 (mctl-api#547):
	// terms, quotes, invocations and their history. Optional — nil makes the
	// commerce endpoints 503, which is "the ledger is unavailable", never
	// "this tenant was not charged".
	Commerce *commerce.Store
	// CommerceAcceptDisabled is COMMERCE_ACCEPT_DISABLED (mctl-api#570). It
	// refuses only MintCommerceQuote and AcceptCommerceInvocation, with 422
	// unsupported-execution; every other commerce route stays live so
	// outstanding liability can drain. Commerce == nil takes precedence: the
	// routes are 503 whatever this says.
	CommerceAcceptDisabled bool
	// TemporalClient starts/signals DevLoopWorkflow runs on the dev-workflow
	// control plane's Temporal deployment (optional — nil disables
	// mctl_trigger_issue's use_temporal path; callers fall back to the
	// direct Argo submission they already use today). Typed as the
	// DevLoopClient interface, not the concrete *temporalclient.Client, so
	// tests can inject a fake — see interfaces.go.
	TemporalClient DevLoopClient
	// WorkItems is the workitem/v1 store (mctl-api#349). Optional — nil makes
	// every /api/v1/work-items route answer 503.
	WorkItems *workitems.Store
	// AgentRunBinder verifies an agent pod's projected ServiceAccount token
	// for POST /api/v1/agent-run-tokens/exchange (mctlhq/mctl-agents#737).
	// Optional: nil makes that route 503.
	AgentRunBinder AgentRunBinder
	// Evidence is the durable execution-evidence store (mctl-api#409, Tier B
	// of evidence.mctl.ai/v1alpha1). Optional — nil makes every
	// /api/v1/evidence* route (and GET /api/v1/work-items/{id}/evidence)
	// answer 503, never an empty list (requirements.md "Availability, gaps
	// and retention").
	Evidence *evidence.Store
	// SecurityFindings is the durable SecurityFinding v1 store
	// (mctl-api#774). Optional: nil makes every /api/v1/security* route
	// answer 503 security_findings_store_unavailable, never an empty list.
	SecurityFindings *securityfindings.Store
	// SecurityProviders is the server-side configuration of the security
	// providers (SECURITY_PROVIDERS), keyed by ref: their tenants and
	// strongest allowed verification. A provider's authority comes from
	// here and from its token, never from a request body.
	SecurityProviders map[string]auth.SecurityProviderConfig
	// CodeScanningWebhookSecret is the dedicated HMAC secret of
	// POST /api/v1/security/webhooks/github-code-scanning (mctl-api#802). It
	// must be at least CodeScanningMinSecretLen long and differ from
	// GitHubWebhookSecret, or the receiver answers 503.
	CodeScanningWebhookSecret string
	// CodeScanningConfig is the validated SECURITY_GITHUB_CODE_SCANNING; nil
	// disables the receiver.
	CodeScanningConfig *CodeScanningConfig
	// CodeScanningIngester is the #774 store the receiver writes to; nil
	// answers 503.
	CodeScanningIngester SecurityIngester
	// Decisions is the durable decision record (mctl-api#701). Optional —
	// nil makes every /api/v1/decisions* route answer 503.
	Decisions *decisions.Store
	// HumanInputLedger is the idempotency/delivery record for human-input
	// responses (mctl-api#261). Optional — nil makes the response endpoint
	// 503: without it a response could be neither deduplicated nor
	// redelivered after a Temporal outage.
	HumanInputLedger humaninput.Ledger
	// WorkflowDispatcher starts GitHub Actions workflow_dispatch runs
	// (optional — nil makes POST /api/v1/cloudflare/portal/server-auth/apply
	// return 503). Deliberately a dispatcher and not a Cloudflare client: the
	// credential that writes to Cloudflare lives in a mctl-gitops environment
	// secret behind a required reviewer, so this process can ask for that
	// apply without ever being able to perform it.
	WorkflowDispatcher WorkflowDispatcher
	// GitopsReady / PostgresReady / DexReady / VaultReady are optional
	// dependency probes for GET /readyz. Results are reported in the body and
	// in mctl_api_dependency_up but never fail readiness (a shared dependency
	// outage must not drain every replica). A nil check is reported as
	// not_configured (tests, local without Vault).
	GitopsReady   ReadyCheck
	PostgresReady ReadyCheck
	DexReady      ReadyCheck
	VaultReady    ReadyCheck
	// StoreInitFailures lists the configured stores whose startup init failed
	// (mctl-api#387). Such a store stays nil for the life of the pod, so any
	// entry keeps GET /readyz at 503 and names the store; liveness (/healthz)
	// is unaffected. Nil means not wired (tests) and is not_configured.
	StoreInitFailures func() []string
	// TemporalState reports "not_configured", "connecting" or "ok" for
	// /readyz as information only; it never affects readiness (mctl-api#764).
	TemporalState func() string
	// GitopsSynced reports whether this pod's own gitops checkout has synced
	// at least once. Unlike the shared dependencies above it is pod-local: a
	// fresh pod that has not cloned yet would serve an empty catalogue, so
	// GET /readyz answers 503 with checks.gitops_sync=never_synced until the
	// first sync lands. Nil means not wired (tests) and is not reported.
	GitopsSynced func() bool
	// Draining reports that graceful shutdown has begun; GET /readyz then
	// answers 503 with checks.shutdown=draining. Nil means never draining.
	Draining func() bool
	// ArgoWebhookSecret authenticates POST /api/v1/workflows/events/argo-complete.
	// Fail-closed: an empty secret rejects every callback.
	ArgoWebhookSecret string
	// GitHubWebhookSecret authenticates POST /api/v1/webhooks/github
	// (X-Hub-Signature-256). Fail-closed: empty rejects every delivery.
	GitHubWebhookSecret string
	// GitHubWebhookOwners lists repository owners whose pull request events
	// are published; anything else is acknowledged and ignored.
	GitHubWebhookOwners []string
	// GitHubEventOutbox durably accepts envelopes (nil answers 503).
	GitHubEventOutbox GitHubEventOutbox
	// GitHubEventNotify wakes the outbox relay after an insert (optional).
	GitHubEventNotify func()
	// ZitadelHook wires the ZITADEL Actions v2 identity hook for the
	// customers org (handlers_zitadel_hook.go). Nil answers 503 on its
	// three routes; each route also rejects calls without a valid
	// ZITADEL-Signature under that target's own key.
	ZitadelHook *ZitadelHookOptions
	// OAuthRegistrationToken, when non-empty, requires Authorization: Bearer
	// <token> on POST /oauth/register (RFC 7591 initial access token).
	OAuthRegistrationToken string
	// TrustedProxyCIDRs are Traefik (or other ingress) source ranges. X-Forwarded-For
	// is used for audit client IP only when RemoteAddr is in this list.
	TrustedProxyCIDRs []*net.IPNet
}

// Handlers holds all API handler dependencies.
type Handlers struct {
	opts           Options
	identityLink   *identityLinker
	oauthZitadel   *oauthZitadel
	surfaceZitadel *surfaceZitadel
	// principalSets memoizes shadow mode's principal-keyed tenant sets;
	// nil reads the checkout on every comparison.
	principalSets *principalSetCache
}

// NewRouter creates the HTTP router with all API routes.
func NewRouter(opts Options) http.Handler {
	h := &Handlers{opts: opts}
	if opts.TenantAuthzMode == TenantAuthzShadow {
		h.principalSets = newPrincipalSetCache(principalSetCacheTTL)
	}
	if opts.IdentityLink != nil {
		h.identityLink = newIdentityLinker(opts.IdentityLink)
	}
	if opts.OAuthZitadel != nil {
		h.oauthZitadel = &oauthZitadel{opts: opts.OAuthZitadel, lazyOIDCProvider: lazyOIDCProvider{issuer: opts.OAuthZitadel.Issuer}}
	}
	if opts.SurfaceZitadel != nil {
		h.surfaceZitadel = &surfaceZitadel{opts: opts.SurfaceZitadel, lazyOIDCProvider: lazyOIDCProvider{issuer: opts.SurfaceZitadel.Issuer}}
	}

	if opts.BackstageGithubAppConnectToken == "" {
		slog.Warn("BACKSTAGE_GITHUB_APP_CONNECT_TOKEN is unset; repos list/sync/install-url answer 503 (no credential configured)",
			"routes", "GET /api/v1/repos, GET /api/v1/repos/install-url, POST /api/v1/repos/sync")
	}

	if opts.DomainStore == nil {
		slog.Warn("domains registry not configured (set DOMAINS_DB_URL or AUDIT_DB_URL); /api/v1/domains* will return 503",
			"routes", "GET/POST /api/v1/domains, POST /api/v1/domains/verify, POST /api/v1/domains/{id}/verify, DELETE/PATCH /api/v1/domains/{id}")
	}

	r := chi.NewRouter()

	// Infrastructure middleware (no auth). clientMetaMiddleware resolves the
	// client IP once, honouring X-Forwarded-For only from TrustedProxyCIDRs;
	// audit entries and rate-limit keys both read it back from the context.
	// chi's middleware.RealIP is deliberately absent — it rewrites RemoteAddr
	// from an attacker-supplied header and now has no consumer here.
	r.Use(middleware.RequestID)
	r.Use(tracingMiddleware())
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
		r.Get("/.well-known/jwks.json", h.handleJWKS)
		// RFC 9728 Protected Resource Metadata — registered at both the root path
		// and the /mcp-suffixed alias since clients probe either form.
		r.Get("/.well-known/oauth-protected-resource", h.handleProtectedResourceMeta)
		r.Get("/.well-known/oauth-protected-resource/mcp", h.handleProtectedResourceMeta)
		r.Get("/oauth/authorize", h.handleOAuthAuthorize)
		r.Get("/oauth/github/callback", h.handleOAuthGitHubCallback)
		r.Get(oauthZitadelCallbackPath, h.handleOAuthZitadelCallback)
		r.Post("/oauth/consent", h.handleOAuthConsent)
		r.Post("/oauth/token", h.handleOAuthToken)
		r.Post("/oauth/revoke", h.handleOAuthRevoke)
		// Explicit identity linking, browser side (mctl-api#435). Public:
		// the person proves both identities inside the flow itself.
		r.Get(linkStartPath, h.handleIdentityLinkStart)
		r.Get(linkCallbackPath, h.handleIdentityLinkCallback)
		r.Post(linkConfirmPath, h.handleIdentityLinkConfirm)
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
	r.Post("/api/v1/webhooks/github", h.HandleGitHubWebhook)
	r.Post("/api/v1/security/webhooks/github-code-scanning", h.HandleGitHubCodeScanningWebhook)
	r.Post(zitadelHookIntentPath, h.HandleZitadelIntent)
	r.Post(zitadelHookCreatePath, h.HandleZitadelCreateUser)
	r.Post(zitadelHookTokenPath, h.HandleZitadelTokenClaims)

	// Agent pods exchange their projected ServiceAccount token for a scoped
	// run token (mctlhq/mctl-agents#737). Outside the authenticated group:
	// the bearer is a Kubernetes token, judged by TokenReview, never by
	// AuthMiddleware. Its own budget, keyed by caller IP, so a pod that
	// retries cannot starve anything else; every attempt costs a TokenReview.
	r.Group(func(r chi.Router) {
		r.Use(httprate.Limit(60, 1*time.Minute, httprate.WithKeyFuncs(keyByTrustedIP)))
		r.Post("/api/v1/agent-run-tokens/exchange", h.ExchangeAgentRunToken)
	})

	// Authenticated API routes.
	r.Group(func(r chi.Router) {
		if opts.AuthMiddleware != nil {
			r.Use(opts.AuthMiddleware)
		}
		// A surface principal's ceiling counts every call it makes, so it
		// runs before the gate: the gate turns a relay call into the linked
		// human, and a refused relay still costs a link lookup.
		r.Use(surfaceAggregateLimit(httprate.Limit(surfaceAggregateLimitPerMinute, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return "surface-total:" + auth.UserFromContext(r.Context()).ID, nil
		}))))
		// Above the gate: relay resolves a link in Postgres there.
		r.Use(middleware.Timeout(30 * 1000000000)) // 30s
		// Surface principals reach only their allowlisted routes; relay
		// routes continue as the linked human.
		r.Use(h.surfacePrincipalGate)
		// An agent principal's ceiling counts every call it makes, the same
		// reasoning as surfaceAggregateLimit above: it must run before
		// agentPrincipalGate substitutes the delegated human, otherwise the
		// global limiter's per-subject split below (keyed on
		// rateLimitSubject -> the delegated human's user.ID) becomes the
		// agent's only ceiling, with no aggregate cap across every human it
		// delegates to -- unlike the surface relay, which pairs its own
		// per-subject split with exactly this aggregate ceiling.
		r.Use(agentAggregateLimit(httprate.Limit(agentAggregateLimitPerMinute, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return "agent-total:" + auth.UserFromContext(r.Context()).ID, nil
		}))))
		// Delegation (mctl-api#376 slice B): an agent principal's
		// X-MCTL-On-Behalf-Of resolves to the grant's subject here, right
		// after the surface gate and on the same footing -- it too resolves
		// a grant in Postgres, so it belongs under the timeout above and
		// before the rate limiter below, whose budget must key on the
		// delegated subject once this gate has run.
		// A scoped agent run reaches only its scope's routes
		// (mctlhq/mctl-agents#737). Ahead of agentPrincipalGate, so the
		// scope is judged on the agent itself, never on a delegated human.
		r.Use(h.agentScopeGate)
		r.Use(h.agentPrincipalGate)
		// The usage writer reaches one route and nothing else.
		r.Use(usageWriterGate)
		// The evidence writer reaches its append routes and nothing else
		// (mctl-api#409, #701), the same shape as the usage writer above.
		r.Use(evidenceWriterGate)
		// A security provider reaches the observation ingest route and
		// nothing else (mctl-api#774).
		r.Use(securityProviderGate)
		// The registry publisher reaches the registry publication routes and
		// nothing else (mctlhq/mctl-agents#470).
		r.Use(registryPublisherGate)
		// A GitHub Actions principal reaches the deploy route and nothing
		// else (mctl-api#530).
		r.Use(ciPrincipalGate)

		// Global rate limit: 300 requests/minute per user (fallback to per-IP).
		// Loopback is skipped so MCP's in-process REST to localhost:8080 does
		// not double-count against the same bucket as POST /mcp. Chi RealIP is
		// not used on this group; Traefik cannot spoof RemoteAddr as loopback.
		// The write 20/min group below does NOT skip loopback — MCP deploys
		// must still be throttled.
		r.Use(skipLoopbackRateLimit(httprate.Limit(300, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			if user := auth.UserFromContext(r.Context()); user != nil {
				return "user:" + rateLimitSubject(r, user), nil
			}
			return keyByTrustedIP(r)
		}))))
		// Shadow comparison of tenant authorization (mctl-api#377). After
		// every gate that substitutes a relayed or delegated human, so the
		// caller compared is the one the handlers authorize, and after the
		// global limiter, so a request it refuses costs no checkout read. A
		// no-op unless TENANT_AUTHZ_MODE=shadow.
		r.Use(h.tenantAuthzShadow)

		r.Route("/api/v1", func(r chi.Router) {
			// Auth endpoints.
			r.Get("/whoami", h.Whoami)
			r.Get("/admin/signup/requests", h.ListSignupRequests)
			r.Post("/admin/signup/requests/{id}/decision", h.DecideSignupRequest)
			r.Get("/admin/signup/capacity", h.GetSignupCapacity)
			r.Post("/admin/signup/capacity", h.SetSignupCapacity)
			r.Post("/surface-principals/signup-claim", h.ClaimSignup)
			r.Post("/internal/customer-deletions/{tenant}/{principal}/cancel", h.CancelCustomerDeletion)
			r.Post("/internal/customer-deletions/{tenant}/{principal}/{stage}", h.AdvanceCustomerDeletion)
			r.Get("/surface-principals/workspace-access/{tenant}", h.ObserveWorkspaceAccess)
			// The caller's linked identities (mctl-api#435).
			r.Get("/identity/links", h.ListIdentityLinks)
			r.Delete("/identity/links/{id}", h.UnlinkIdentity)
			r.Post("/admin/principals/{from}/merge-into/{into}", h.MergePrincipals)
			r.Post("/admin/principals/{id}/disable", h.DisablePrincipal)
			// Read-only: proposes a principalId per GitOps member entry.
			r.Get("/admin/tenant-members/principal-plan", h.TenantMemberPrincipalPlan)
			r.Post("/auth/logout", h.Logout)

			// Read endpoints (safe, no side effects).
			r.Get("/tenants", h.ListTenants)
			r.Get("/tenants/{name}", h.GetTenant)
			r.Get("/services", h.ListServices)
			r.Get("/services/{team}/{app}", h.GetService)
			r.Get("/deploy/analyze", h.DeployAnalyze)
			r.Get("/deploy/bindings", h.DeployBindings)
			r.Get("/status/{team}/{app}", h.GetServiceStatus)
			r.Get("/workflows", h.ListWorkflows)
			r.Get("/workflows/{name}", h.GetWorkflow)
			r.Get("/workflows/{name}/logs", h.GetWorkflowLogs)
			r.Get("/previews", h.ListPreviews)
			r.Get("/resources/{tenant}", h.GetResourceUsage)
			r.Get("/logs/{team}/{app}", h.GetServiceLogs)
			r.Get("/pods/{team}/{app}", h.GetServicePods)
			r.Get("/events/{team}", h.ListNamespaceEvents)
			r.Get("/audit", h.ListAudit)
			r.Get("/audit/support", h.ListSupportAudit)
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

			// Custom domains (mctl-api's own PostgreSQL-backed registry —
			// see internal/domains). No chi conflict between the two verify
			// routes: /domains/verify is two segments, /domains/{id}/verify
			// is three.
			r.Get("/domains", h.ListDomains)
			r.Post("/domains", h.AddDomain)
			r.Post("/domains/verify", h.VerifyDomainByName)
			r.Post("/domains/{id}/verify", h.VerifyDomain)
			r.Delete("/domains/{id}", h.DeleteDomain)
			r.Patch("/domains/{id}", h.UpdateDomainStatus)

			// ERPact site tools (mctl-api#486): a temporary, tenant-`erpact`-only
			// stopgap in front of the tenant's own site-deployer. See
			// internal/erpactsites's package comment and handlers_erpact_sites.go.
			r.Get("/tenants/erpact/sites", h.ListErpactSites)
			r.Post("/tenants/erpact/sites", h.CreateErpactSite)
			r.Get("/tenants/erpact/sites/{name}/status", h.GetErpactSiteStatus)

			// Incident endpoints (alert store).
			r.Get("/incidents/summary", h.IncidentSummary)
			r.Get("/incidents", h.ListIncidents)
			r.Get("/incidents/{id}", h.GetIncident)
			r.Post("/incidents", h.CreateIncident)
			r.Post("/incidents/resolve-by-fingerprint", h.ResolveIncidentByFingerprint)
			r.Patch("/incidents/{id}", h.UpdateIncident)
			r.Post("/incidents/{id}/ack", h.AcknowledgeIncident)
			r.Post("/incidents/{id}/resolve", h.ResolveIncident)

			// Agent registry (mctl-agents AgentManifest versions/releases).
			// Admin-only, except that the three publication routes (create,
			// publish, promote) also admit the registry publisher: see
			// handlers_agent_registry_publisher.go.
			r.Post("/agents", h.CreateAgentDefinition)
			r.Post("/agents/{name}/versions", h.PublishAgentVersion)
			r.Get("/agents/{name}/versions", h.ListAgentVersions)
			r.Post("/agents/{name}/releases", h.UpdateAgentRelease)
			r.Get("/agents/{name}/resolve", h.ResolveAgentRelease)
			// GET /agents/executions is 2 segments, same as the v1alpha2
			// GET /agents/{name} registered below — chi's radix tree prefers
			// this static "executions" match over the dynamic one; keep them
			// adjacent so that stays easy to notice. internal/api/router_test.go
			// pins it.
			r.Post("/agents/executions", h.RecordAgentExecution)
			r.Get("/agents/executions", h.ListAgentExecutions)

			// v1alpha2 agent-platform layer (ADR 007): immutable
			// AgentDefinition/ExecutionProfile versions plus append-only
			// ReleaseBinding revisions per (agent, environment). Extends the
			// same *agentregistry.Store as the v1 routes above — see
			// internal/api/handlers_agent_platform.go and
			// docs/agent-platform-registry.md. Admin-only, same as v1.
			r.Get("/agents", h.ListAgents)
			r.Get("/agents/{name}", h.GetAgent)
			r.Post("/agents/{name}/definition-versions", h.PublishDefinitionVersion)
			r.Get("/agents/{name}/definition-versions", h.ListDefinitionVersions)
			r.Post("/agents/{name}/definition-versions/{version}/lifecycle", h.SetDefinitionVersionLifecycle)
			r.Post("/agent-profiles/{profile}/versions", h.PublishProfileVersion)
			r.Get("/agent-profiles/{profile}/versions", h.ListProfileVersions)
			r.Post("/agent-profiles/{profile}/versions/{version}/lifecycle", h.SetProfileVersionLifecycle)
			r.Post("/agents/{name}/bindings", h.CreateBinding)
			r.Get("/agents/{name}/bindings", h.ListBindings)
			// "resolve" and "rollback" are static 4th-segment matches that
			// win over the dynamic GET .../bindings/{revision} below, same
			// static-beats-dynamic precedence as /agents/executions above.
			r.Get("/agents/{name}/bindings/resolve", h.ResolveBinding)
			// Read-only asset index and CI-equivalent preflight (mctl-api#748).
			// Static segments win over {name}; no eligibility semantics.
			r.Get("/agent-assets", h.ListAgentAssets)
			r.Get("/agents/{name}/preflight", h.PreflightAgent)
			r.Post("/agents/{name}/bindings/rollback", h.RollbackBinding)
			r.Get("/agents/{name}/bindings/{revision}", h.GetBinding)

			// Write endpoints with real side effects (trigger Argo Workflows,
			// start/signal a Temporal workflow) — tighter rate limit, shared
			// so every route in this group inherits it instead of each one
			// needing its own With(...) (a route added here without it would
			// silently bypass the limit, same write-cost profile as
			// /operations/{name}/execute below).
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(20, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "write:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/operations/{name}/execute", h.ExecuteOperation)
				r.Post("/agents/dev-loop/start", h.StartDevLoopWorkflow)
				// Starts one DevLoop per item of a publication-bound plan
				// (mctl-api#334), on this budget like the single start.
				r.Post("/roadmap/waves/execute", h.ExecuteRoadmapWave)
				r.Post("/agents/dev-loop/{workflow_id}/approve", h.ApproveDevLoopWorkflow)
				// Ends a DevLoop gracefully (mctl-api#392).
				r.Post("/agents/dev-loop/{workflow_id}/abandon", h.AbandonDevLoopWorkflow)
				// Signals the owning DevLoopWorkflow (mctl-api#261).
				r.Post("/human-input/{request_id}/response", h.RespondHumanInput)
				// Starts a mctl-gitops workflow, not a platform workflow, and
				// belongs in this group for the same reason the two above do:
				// it costs a write on the far side and shares the 20/min
				// budget rather than getting an exemption.
				r.Post("/cloudflare/portal/server-auth/apply", h.DispatchPortalServerAuthApply)
				// Work-item mutations (mctl-api#349): the contract puts them
				// on this shared write budget.
				r.Post("/work-items", h.CreateWorkItem)
				// Surface identity links (mctl-api#350).
				r.Post("/surface-identities/challenges", h.CreateSurfaceChallenge)
				r.Post("/surface-identities/redeem", h.RedeemSurfaceChallenge)
				// The portal resolves a tenant creator's GitHub login to a
				// principal before it submits create-tenant (mctl-api#377).
				r.Post("/surface-principals/github", h.ResolveGitHubPrincipal)
				// ... and a self-service customer by its ZITADEL ID token.
				r.Post("/surface-principals/zitadel", h.ResolveZitadelPrincipal)
				r.Post("/surface-identities/{id}/revoke", h.RevokeSurfaceIdentity)
				r.Patch("/work-items/{id}", h.TransitionWorkItem)
				r.Post("/work-items/{id}/intents", h.AppendWorkItemIntent)
				r.Post("/work-items/{id}/executions", h.AttachWorkItemExecution)
				r.Post("/work-items/{id}/resume", h.ResumeWorkItem)
				r.Post("/work-items/{id}/surface-refs", h.LinkWorkItemSurface)
				// Sealed ContextSnapshots (mctl-agents#431): insert-only.
				r.Post("/work-items/{id}/executions/{execution_id}/snapshot", h.SealWorkItemSnapshot)
				// Action approval requests (mctl-api#366): single-use
				// approvals of one hashed runtime side effect.
				r.Post("/action-approvals", h.CreateActionApproval)
				r.Post("/action-approvals/{id}/decision", h.DecideActionApproval)
				r.Post("/action-approvals/{id}/consume", h.ConsumeActionApproval)
				r.Post("/action-approvals/{id}/execute", h.MarkActionApprovalExecuted)
				// Execution requests (mctl-api#368): a person or a relaying
				// surface asks for a run; the platform supplies its identity.
				r.Post("/work-items/{id}/execution-requests", h.CreateExecutionRequest)
			})

			// The execution platform's side of execution requests
			// (mctl-api#368): claim, fulfil, reject. Service principal only.
			// Its own group and budget: the dispatcher polls claim, and on
			// the 20/min write budget shared with dev-loop starts it would
			// starve the very workflow triggers it feeds, the lifecycle
			// writes' reasoning below.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(120, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "execution-requests:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/execution-requests/claim", h.ClaimExecutionRequest)
				r.Post("/execution-requests/{request_id}/fulfil", h.FulfilExecutionRequest)
				r.Post("/execution-requests/{request_id}/reject", h.RejectExecutionRequest)
			})

			// Execution-evidence ingest (mctl-api#409). Its own group, the
			// same reasoning as the execution-requests group above: a
			// single short Postgres transaction a producer makes once per
			// governed run must not compete with the 20/min budget
			// reserved for calls that trigger Argo and Temporal, and a
			// retry burst (the producer's own non-fatality contract) must
			// not be throttled into a false gap.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(evidenceIngestPerMinute, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "evidence:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/evidence/records", h.IngestEvidence)
			})

			// Security observation ingest (mctl-api#774). Its own bucket for
			// the same reason as evidence ingest: a provider's retry burst
			// must not be throttled into a gap.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(securityIngestPerMinute, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "security-ingest:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/security/observations", h.IngestSecurityObservations)
			})

			// SecurityFinding v1 reads and lifecycle writes (mctl-api#774).
			r.Get("/security/findings", h.ListSecurityFindings)
			r.Get("/security/findings/{id}", h.GetSecurityFinding)
			r.Get("/security/occurrences", h.ListSecurityOccurrences)
			r.Get("/security/occurrences/{id}", h.GetSecurityOccurrence)
			r.Post("/security/occurrences/{id}/triage", h.TriageSecurityOccurrence)
			r.Post("/security/occurrences/{id}/remediation-attempts", h.StartSecurityRemediation)
			r.Post("/security/occurrences/{id}/dismiss", h.DismissSecurityOccurrence)
			r.Post("/security/remediation-attempts/{id}/fix", h.RecordSecurityFix)
			r.Post("/security/remediation-attempts/{id}/verifications", h.RecordSecurityVerification)

			// Decision records (mctl-api#701). Same producer and the same
			// no-false-gap reasoning as evidence ingest, but their own
			// bucket: a run makes one decision per policy checkpoint and up
			// to two attempt events each, keyed on one fleet-wide service
			// principal, so sharing evidence's budget would let decisions
			// throttle evidence ingest. Sized against the global limit
			// above: see decisionWritesPerMinute.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(decisionWritesPerMinute, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "decisions:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/decisions", h.RecordDecision)
				r.Post("/decisions/{id}/attempts", h.AppendDecisionAttempt)
			})

			// Agent run tokens (mctl-api#376): minting is isDirectService
			// only, so every mint shares the exact same principal key as
			// every other route on the 20/min write budget above. An agent
			// run needing a fresh credential would then compete with
			// dev-loop starts, work-item mutations, and everything else on
			// that budget and could be starved under load. Its own group
			// and budget, the same reasoning as the execution-requests
			// group above.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(120, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "agent-run-tokens:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/agent-run-tokens", h.MintAgentRunToken)
				r.Post(agentRunTokenSelfRevokeRoute, h.RevokeOwnAgentRunToken)
			})

			// Work-item reads: side-effect free, outside the write budget.
			r.Get("/work-items", h.ListWorkItems)
			r.Get("/surface-identities", h.ListSurfaceIdentities)
			r.Get("/work-items/{id}", h.GetWorkItem)
			r.Get("/work-items/{id}/executions", h.ListWorkItemExecutions)
			r.Get("/work-items/{id}/events", h.ListWorkItemEvents)
			r.Get("/work-items/{id}/intents", h.ListWorkItemIntents)
			r.Get("/work-items/{id}/intents/{intent_id}", h.GetWorkItemIntent)
			r.Get("/work-items/{id}/executions/{execution_id}/snapshot", h.GetWorkItemExecutionSnapshot)
			r.Get("/work-items/{id}/snapshots", h.ListWorkItemSnapshots)
			r.Get("/work-items/{id}/snapshots/{snapshot_id}", h.GetWorkItemSnapshot)
			r.Get("/work-items/{id}/execution-requests", h.ListExecutionRequests)
			r.Get("/work-items/{id}/execution-requests/{request_id}", h.GetExecutionRequest)
			r.Get("/action-approvals", h.ListActionApprovals)
			r.Get("/action-approvals/{id}", h.GetActionApproval)

			// Execution-evidence reads (mctl-api#409): side-effect free,
			// admin-only except the work-item-scoped one, which reuses
			// visibleWorkItem so evidence never leaks past what the caller
			// could already see on the work item. Outside the write
			// budget above like every other read in this block.
			// /evidence/current (ADR 018 Amendment 2) is a static segment, so
			// chi matches it before the /evidence/{id} pattern.
			r.Get("/evidence/current", h.CurrentEvidence)
			r.Get("/evidence/{id}", h.GetEvidence)
			r.Get("/evidence", h.ListEvidence)
			r.Get("/work-items/{id}/evidence", h.ListWorkItemEvidence)
			r.Get("/work-items/{id}/evidence/current", h.CurrentWorkItemEvidence)
			// Decision record reads (mctl-api#701): admin-only.
			r.Get("/decisions/{id}", h.GetDecision)
			r.Get("/decisions", h.ListDecisions)

			// Liveness read for one DevLoopWorkflow. Deliberately OUTSIDE the
			// write group above: it has no side effects, and the shepherd
			// sweeper calls it once per actionable proposal per tick (#213),
			// which would eat the 20/min write budget shared with
			// /operations/{name}/execute and starve real writes.
			r.Get("/agents/dev-loop/{workflow_id}", h.GetDevLoopWorkflow)

			// Who the API resolved the caller to (mctl-api#376 D3):
			// side-effect-free, outside the write group like the dev-loop
			// liveness read.
			r.Get("/identity/self", h.GetIdentitySelf)

			// Human-input read model (mctl-api#261): side-effect-free reads,
			// outside the write group like the dev-loop liveness read.
			r.Get("/human-input", h.ListHumanInputs)
			r.Get("/human-input/{request_id}", h.GetHumanInput)

			// Roadmap read model (mctl-api#333): read-only, selected from the
			// published RoadmapPublication, never evaluated here.
			r.Get("/roadmap/epics", h.ListRoadmapEpics)
			r.Get("/roadmap/epic-status", h.GetRoadmapEpicStatus)
			r.Get("/roadmap/ready", h.GetRoadmapReadyWorkItems)
			// A wave plan is a dry run: POST only to carry an exact item
			// list, no side effects (mctl-api#334).
			r.Post("/roadmap/waves/plan", h.PlanRoadmapWave)

			// Lifecycle ownership READS. Deliberately OUTSIDE the write
			// group above, for the same reason the dev-loop liveness read
			// is: the shepherd calls these once per sweep and an operator
			// calls them while diagnosing, so putting them on the 20/min
			// write budget shared with /operations/{name}/execute would
			// starve real writes.
			r.Get("/lifecycle/ownership", h.GetLifecycleOwnership)
			// One entity phase, as a bare record. Separate path, not a
			// query parameter on the line above: the shape of the answer
			// must not depend on whether an argument was supplied (#302).
			r.Get("/lifecycle/ownership/record", h.GetLifecycleOwnershipRecord)
			r.Get("/lifecycle/ownership/batch", h.BatchGetLifecycleOwnership)
			r.Get("/lifecycle/events", h.ListLifecycleEvents)
			// Recovery evidence read: what a follow-up recovery call below
			// needs (stored row, derived view, legacy DevLoopWorkflow
			// answer, divergence class, recent transitions, and the exact
			// precondition values to send). A read like the four above it,
			// so it sits outside the write budgets too.
			r.Get("/lifecycle/ownership/conflict", h.GetLifecycleConflict)

			// Lifecycle ownership WRITES — their own group and their own
			// budget.
			//
			// These are not the same cost profile as the 20/min group: those
			// trigger Argo workflows and Temporal executions, while these are
			// a single short Postgres transaction. But they are far more
			// frequent — every DevLoop acquires, records progress per
			// effective tick, and releases — so sharing the 20/min bucket
			// would mean ownership bookkeeping starving the workflow triggers
			// it exists to coordinate. 120/min is roughly the ceiling implied
			// by the reconciler cadence with headroom for a bootstrap sweep.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(120, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "lifecycle:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/lifecycle/ownership/acquire", h.AcquireLifecycleOwnership)
				r.Post("/lifecycle/ownership/progress", h.RecordLifecycleProgress)
				r.Post("/lifecycle/ownership/handoff/start", h.StartLifecycleHandoff)
				r.Post("/lifecycle/ownership/handoff/complete", h.CompleteLifecycleHandoff)
				r.Post("/lifecycle/ownership/release", h.ReleaseLifecycleOwnership)
				r.Post("/lifecycle/ownership/terminal", h.TerminateLifecycleOwnership)
				// Recovery is a WRITE like the rest and sits in the same
				// admin group: it moves ownership off a live record, which
				// no other endpoint here can do.
				r.Post("/lifecycle/ownership/recover", h.RecoverLifecycleOwnership)
			})

			// Model usage ledger (mctl-api#266). Ingestion is a write but is
			// not on the 20/min group: that budget exists for calls that
			// trigger Argo workflows and Temporal executions, while this is a
			// single short Postgres transaction that a producer makes once per
			// completed model invocation. Throttling it would drop cost
			// records for work that has already been paid for, which is the
			// one failure this ledger cannot absorb — the money is spent
			// whether or not the row lands.
			//
			// The reads share the group because they are operator-driven and
			// infrequent.
			r.Post("/usage/records", h.IngestUsageRecords)
			r.Get("/usage/records", h.ListUsageRecords)
			r.Get("/usage/summary", h.GetUsageSummary)

			// Commerce ledger (mctl-api#547, ADR 020). Like usage, the writes
			// are single short Postgres transactions, one per quote or
			// accepted invocation, and they stay off the 20/min group for
			// the same reason. Terms and transitions are platform
			// operations; quotes, invocations and receipts are tenant-scoped
			// under /commerce/tenants/{tenant}.
			r.Route("/commerce", func(r chi.Router) {
				r.Post("/terms", h.PublishCommerceTerms)
				r.Get("/terms", h.ListCommerceTerms)
				r.Get("/terms/{terms_id}/versions/{version}", h.GetCommerceTerms)
				r.Post("/terms/{terms_id}/versions/{version}/retire", h.RetireCommerceTerms)
				r.Get("/invocations/overdue", h.ListOverdueCommerceInvocations)
				// Budgets and the money edges (mctl-api#548). Setting a
				// budget, reserve, finalize, release and the reconciler
				// are platform operations; the balance, its history and
				// the non-binding precheck are tenant reads.
				r.Post("/reconcile/expired", h.ReconcileCommerceExpired)
				// The public halves of the dispatch signing key (C4).
				r.Get("/dispatch-keys", h.ListCommerceDispatchKeys)
				r.Route("/tenants/{tenant}", func(r chi.Router) {
					r.Put("/budget", h.SetCommerceBudget)
					r.Get("/budget", h.GetCommerceBudget)
					r.Get("/budget/changes", h.ListCommerceBudgetChanges)
					r.Post("/budget/precheck", h.PrecheckCommerceBudget)
					r.Post("/entitlements", h.GrantCommerceEntitlement)
					r.Get("/entitlements", h.ListCommerceEntitlements)
					r.Get("/entitlements/{entitlement_id}", h.GetCommerceEntitlement)
					r.Post("/entitlements/{entitlement_id}/retire", h.RetireCommerceEntitlement)
					r.Delete("/entitlements/{entitlement_id}", h.RetireCommerceEntitlement)
					r.Post("/quotes", h.MintCommerceQuote)
					r.Get("/quotes/{quote_id}", h.GetCommerceQuote)
					r.Post("/invocations", h.AcceptCommerceInvocation)
					r.Get("/invocations", h.ListCommerceInvocations)
					r.Get("/invocations/{invocation_id}", h.GetCommerceInvocation)
					r.Get("/invocations/{invocation_id}/receipt", h.GetCommerceReceipt)
					r.Get("/invocations/{invocation_id}/transitions", h.ListCommerceInvocationTransitions)
					r.Post("/invocations/{invocation_id}/transitions", h.TransitionCommerceInvocation)
					r.Post("/invocations/{invocation_id}/reserve", h.ReserveCommerceInvocation)
					r.Post("/invocations/{invocation_id}/dispatch", h.DispatchCommerceInvocation)
					r.Post("/invocations/{invocation_id}/finalize", h.FinalizeCommerceInvocation)
					r.Post("/invocations/{invocation_id}/release", h.ReleaseCommerceInvocation)
				})
			})

			// Human-operator lifecycle RECOVERY -- fence a dead claim,
			// escalate a stuck owner into a handoff, retry a stalled
			// handoff, or request reconciliation. A SEPARATE group and a
			// tighter budget than the 120/min actor-write group above: these
			// are rare, human-initiated interventions, not per-tick
			// bookkeeping, and a caller hammering this endpoint is far more
			// likely to be a bug than a legitimate burst.
			//
			// "recovery/handoff/*" is deliberately a distinct static prefix
			// from the actor-driven "handoff/start"/"handoff/complete"
			// above, so chi's radix tree cannot confuse an operator's
			// escalation with an actor's own declared handoff.
			r.Group(func(r chi.Router) {
				r.Use(httprate.Limit(10, 1*time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
					if user := auth.UserFromContext(r.Context()); user != nil {
						return "lifecycle-recovery:" + rateLimitSubject(r, user), nil
					}
					return keyByTrustedIP(r)
				})))
				r.Post("/lifecycle/ownership/recovery/reconcile", h.RequestLifecycleReconcile)
				r.Post("/lifecycle/ownership/recovery/fence", h.FenceLifecycleClaim)
				r.Post("/lifecycle/ownership/recovery/handoff/request", h.RequestLifecycleHandoffRecovery)
				r.Post("/lifecycle/ownership/recovery/handoff/retry", h.RetryLifecycleHandoff)
			})

			// Operation registry (metadata only).
			r.Get("/operations", h.ListOperations)
			r.Get("/operations/{name}", h.GetOperation)
			// The build workflow's binding check; ciPrincipalGate lets a CI
			// principal reach it and the handler pins the workflow.
			r.Get("/ci/build-repo-binding", h.CIBuildRepoBinding)
		})

		// MCP Streamable HTTP transport — single endpoint for Claude Desktop, Cursor, etc.
		// The transport is stateless (mctlhq/mctl-api#276): no Mcp-Session-Id is
		// minted or required. GET and DELETE stay routed and are answered by the
		// transport itself -- a listen stream bound to no session, and a DELETE
		// that has nothing to terminate -- so method semantics live in one place.
		// POST /mcp  → send request (can return a streaming SSE response)
		// GET  /mcp  → listen stream (no session binding under stateless mode)
		// Auth: Authorization: Bearer <token> on every request.
		if opts.MCPServer != nil {
			opts.MCPServer.SetTenantOwnerChecker(h)
			opts.MCPServer.SetAgentReceiptGate(h, opts.AgentReceiptGateMode)
			opts.MCPServer.SetScopedCallAuditor(h)
			mcpH := opts.MCPServer.NewStreamableHTTPHandler()
			r.Post("/mcp", mcpH.ServeHTTP)
			r.Get("/mcp", mcpH.ServeHTTP)
			r.Delete("/mcp", mcpH.ServeHTTP)
		}
	})

	return r
}

// isLoopbackRemote reports whether the transport peer is IPv4 or IPv6
// localhost. The skip is keyed on RemoteAddr (via SplitHostPort), not
// X-Forwarded-For: an attacker in front of Traefik cannot make RemoteAddr
// look like 127.0.0.1 or ::1.
func isLoopbackRemote(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host == "127.0.0.1" || host == "::1"
}

// skipLoopbackRateLimit wraps a rate-limit middleware so loopback peers are
// not counted. Use only on the global authenticated limiter.
func skipLoopbackRateLimit(limitMW func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limitMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isLoopbackRemote(r) {
				next.ServeHTTP(w, r)
				return
			}
			limited.ServeHTTP(w, r)
		})
	}
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

// rateLimitSubject is who a per-user rate limit counts against. A surface
// principal calls for many end users, so its budget is split by the one it
// names in SurfaceActorHeader, otherwise one Telegram user could exhaust
// every other's. surfacePrincipalGate runs first and refuses a value that is
// not one of the surface's own ids, which bounds the key space;
// surfaceAggregateLimit still caps the surface as a whole.
func rateLimitSubject(r *http.Request, user *auth.User) string {
	if _, isSurface := user.Surface(); isSurface {
		return user.ID + "|" + r.Header.Get(SurfaceActorHeader)
	}
	return user.ID
}

// surfaceAggregateLimitPerMinute caps one surface principal across all the
// end users it calls for, the ceiling rateLimitSubject's per-user split
// would otherwise remove. Roughly Telegram's own bot send rate.
const surfaceAggregateLimitPerMinute = 1200

// surfaceAggregateLimit applies limit to surface principals only, keyed on
// the principal alone.
func surfaceAggregateLimit(limit func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limit(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, isSurface := auth.UserFromContext(r.Context()).Surface(); isSurface {
				limited.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// agentAggregateLimitPerMinute caps one agent principal across all the
// delegated subjects it acts for, the same ceiling surfaceAggregateLimit
// pairs with the surface relay's per-subject split -- without it, an
// agent's budget is only the global limiter's per-delegated-human split,
// with no cap on the agent as a whole.
const agentAggregateLimitPerMinute = 1200

// agentAggregateLimit applies limit to agent principals only, keyed on the
// principal alone, evaluated before agentPrincipalGate substitutes the
// delegated subject into the request context.
func agentAggregateLimit(limit func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limit(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if user := auth.UserFromContext(r.Context()); user != nil {
				if _, isAgent := user.AgentName(); isAgent {
					limited.ServeHTTP(w, r)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
