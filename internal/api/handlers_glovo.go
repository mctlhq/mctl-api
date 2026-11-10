// Copyright 2026 MCTL Authors
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
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovo/connect"
	"github.com/mctlhq/mctl-api/internal/glovo/scope"
)

// GlovoRoutes configures the synthetic Glovo connection routes (mctl-api#961):
// the facade, tenant administration and worker families under /api/v1/glovo.
// Everything is inert unless Enabled (GLOVO_ENABLED) and every dependency is
// configured and healthy; a nil GlovoRoutes answers 503 not_ready on every
// route. The provider is synthetic: no cookie, consumer credential or Glovo
// HTTP call exists behind these routes.
type GlovoRoutes struct {
	// Enabled is GLOVO_ENABLED.
	Enabled bool
	// ResourceConfigured is true when GLOVO_MCP_RESOURCE is set.
	ResourceConfigured bool
	// WorkerConfigured is true when the worker credential is configured.
	WorkerConfigured bool
	// Store is the connection store (opened with the end purger installed).
	Store *glovo.Store
	// Resolver resolves the caller's scope from the selected-team grant.
	Resolver *scope.Resolver
	// Connect is the one connection-creating code path.
	Connect *connect.Service
	// ReadyTTL caches a positive readiness answer; zero checks every request.
	ReadyTTL time.Duration

	mu      sync.Mutex
	okUntil time.Time
}

// ready reports nil only when the routes may serve: switch on, store, resolver,
// connect service, resource and worker identity configured, store.Ready() nil
// and the handoff purge installed.
func (g *GlovoRoutes) ready(ctx context.Context) error {
	if g == nil || !g.Enabled || g.Store == nil || g.Resolver == nil || g.Connect == nil ||
		!g.ResourceConfigured || !g.WorkerConfigured {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	g.mu.Lock()
	cached := g.ReadyTTL > 0 && time.Now().Before(g.okUntil)
	g.mu.Unlock()
	if cached {
		return nil
	}
	if err := g.Store.Ready(ctx); err != nil {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	if !g.Store.EndPurgerInstalled() {
		return glovo.Refuse(glovo.CodeNotReady)
	}
	if g.ReadyTTL > 0 {
		g.mu.Lock()
		g.okUntil = time.Now().Add(g.ReadyTTL)
		g.mu.Unlock()
	}
	return nil
}

var glovoRouteRefusals = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_glovo_route_refusals_total",
	Help: "Refusals written by the synthetic Glovo connection routes, by route class and code.",
}, []string{"route", "code"})

func init() { prometheus.MustRegister(glovoRouteRefusals) }

func (h *Handlers) glovoRoutes() *GlovoRoutes { return h.opts.Glovo }

// glovoReady is the readiness every Glovo route needs.
func (h *Handlers) glovoReady(ctx context.Context) error { return h.glovoRoutes().ready(ctx) }

// glovoFeatureGate answers 503 not_ready on every route of the subtree before
// the body is read.
func (h *Handlers) glovoFeatureGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.glovoReady(r.Context()); err != nil {
			glovoRouteRefusals.WithLabelValues("gate", string(glovo.CodeNotReady)).Inc()
			glovo.WriteError(w, glovo.Refuse(glovo.CodeNotReady))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// glovoRefuse writes err as a closed refusal. Store failures are 503
// unavailable, never a refusal that could read as "no". Only ids and codes
// are logged.
func glovoRefuse(w http.ResponseWriter, route string, err error, attrs ...any) *glovo.Error {
	ge := glovo.AsError(err)
	glovoRouteRefusals.WithLabelValues(route, string(ge.Code)).Inc()
	args := append([]any{"route", route, "code", string(ge.Code)}, attrs...)
	if ge.Code == glovo.CodeUnavailable {
		slog.Warn("glovo route failed", append(args, "error", err)...)
	} else {
		slog.Info("glovo route refused", args...)
	}
	glovo.WriteError(w, ge)
	return ge
}

// glovoNoAudit lists the refusals that cannot name an existing entity of the
// caller (or name none): they are logged and counted, never written to the
// audit table with fabricated values.
func glovoNoAudit(c glovo.Code) bool {
	switch c {
	case glovo.CodeNotReady, glovo.CodeUnavailable, glovo.CodeNotAuthorized, glovo.CodeInvalidRequest,
		glovo.CodeNotFound, glovo.CodeNoInstall, glovo.CodeAmbiguousTenant, glovo.CodeNoTenant,
		glovo.CodeScopeUnsupported, glovo.CodeNotInPilot, glovo.CodeRateLimited, glovo.CodeTenantBusy:
		return true
	}
	return false
}

// glovoAuditRefusal appends the audit row of a refusal on a mutating route
// that names an existing entity. A failure to audit is logged, never turned
// into a different answer.
func (h *Handlers) glovoAuditRefusal(ctx context.Context, ge *glovo.Error, tenant, kind, entityID string, actor glovo.Actor) {
	if ge == nil || glovoNoAudit(ge.Code) || entityID == "" {
		return
	}
	if err := h.glovoRoutes().Store.AppendRefusal(ctx, glovo.RefusalEvent{
		TenantID: tenant, EntityKind: kind, EntityID: entityID, Code: ge.Code, Actor: actor,
	}); err != nil {
		slog.Warn("glovo refusal audit failed", "entity", entityID, "code", string(ge.Code), "error", err)
	}
}

// glovoWorkerGate confines the Glovo worker to /api/v1/glovo/worker/ (POST
// only); on every other route it answers 403. It runs in the authenticated
// chain before r.Route("/api/v1"), so the worker never reaches /mcp, the
// DevLoop routes, the bridge routes, the facade or the installation routes.
func (h *Handlers) glovoWorkerGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsGlovoWorker() &&
			(r.Method != http.MethodPost || !glovoWorkerPath.MatchString(r.URL.Path)) {
			glovoRouteRefusals.WithLabelValues("worker_gate", string(glovo.CodeNotAuthorized)).Inc()
			glovo.WriteError(w, glovo.Refuse(glovo.CodeNotAuthorized))
			return
		}
		next.ServeHTTP(w, r)
	})
}

var glovoWorkerPath = regexp.MustCompile(`^/api/v1/glovo/worker/`)
