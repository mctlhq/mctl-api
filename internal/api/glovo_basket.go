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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovobasket"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// GlovoBasketPayloads reads the revision behind a basket approval, for the
// owner's decision surface.
type GlovoBasketPayloads interface {
	DecisionPayload(ctx context.Context, approvalRef string) (*glovobasket.DecisionPayload, error)
}

// GlovoBasketRoutes is the Glovo basket MCP (mctl-api#1006). It is dark: the
// router mounts it only when every field is set, and cmd/api sets them only
// when GLOVO_BASKET_MCP_ENABLED is true and every dependency is configured.
//
// The MCP is host-routed: on Host only /mcp and the protected-resource
// metadata exist, the metadata names Resource, and /mcp admits a token whose
// audience is exactly the Glovo resource. The main host is unchanged; its
// /mcp still refuses a Glovo-audience token.
type GlovoBasketRoutes struct {
	// Host is the basket MCP's host name, e.g. glovo.mctl.ai.
	Host string
	// Resource is the exact token audience, e.g. https://glovo.mctl.ai/mcp.
	Resource string
	// MCP is glovobasket.NewHandler.
	MCP http.Handler
	// Decisions decide a glovo.basket_approval through the existing
	// decision route.
	Decisions GlovoApprovalDecisions
	// Payloads back GET /api/v1/action-approvals/{id}/glovo-basket.
	Payloads GlovoBasketPayloads
}

func (g *GlovoBasketRoutes) complete() bool {
	return g != nil && g.Host != "" && g.Resource != "" && g.MCP != nil && !glovo.IsNil(g.Decisions) && !glovo.IsNil(g.Payloads)
}

// glovoDecisionsFor is the ledger of a Glovo kind: the basket approvals have
// their own, every other Glovo kind is the order ledger.
func (h *Handlers) glovoDecisionsFor(kind string) GlovoApprovalDecisions {
	if kind == workitems.ActionKindGlovoBasketApproval {
		if !h.opts.GlovoBasket.complete() {
			return nil
		}
		return h.opts.GlovoBasket.Decisions
	}
	if glovo.IsNil(h.opts.GlovoApprovals) {
		return nil
	}
	return h.opts.GlovoApprovals
}

// glovoKindOpen is the build gate of a Glovo kind. The order kinds stay behind
// glovo.Default; a basket approval has no order and no provider effect, so
// its gate is the basket MCP being configured and ready.
func glovoKindOpen(kind string) bool {
	return kind == workitems.ActionKindGlovoBasketApproval || glovo.Default.Open
}

// hostOnly is r.Host lowercased without a port.
func hostOnly(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// withGlovoBasketHost routes requests for the basket host to the basket
// router and everything else to main.
func (h *Handlers) withGlovoBasketHost(main http.Handler) http.Handler {
	g := h.opts.GlovoBasket
	host := strings.ToLower(g.Host)
	basket := h.glovoBasketRouter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostOnly(r) == host {
			basket.ServeHTTP(w, r)
			return
		}
		main.ServeHTTP(w, r)
	})
}

func (h *Handlers) glovoBasketMetadataURL() string {
	u, err := url.Parse(h.opts.GlovoBasket.Resource)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"
}

func (h *Handlers) glovoBasketRouter() http.Handler {
	opts := h.opts
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(clientMetaMiddleware(opts.TrustedProxyCIDRs))
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders())
	r.Use(metricsMiddleware())
	r.Use(httprate.Limit(120, time.Minute, httprate.WithKeyFuncs(keyByTrustedIP)))
	r.Get("/.well-known/oauth-protected-resource", h.handleGlovoBasketResourceMeta)
	r.Get("/.well-known/oauth-protected-resource/mcp", h.handleGlovoBasketResourceMeta)
	r.Group(func(r chi.Router) {
		r.Use(h.glovoBasketBearerRequired)
		if opts.AuthMiddleware != nil {
			r.Use(opts.AuthMiddleware)
		}
		r.Use(h.glovoBasketAudienceGate)
		r.Use(middleware.Timeout(30 * time.Second))
		mcpH := opts.GlovoBasket.MCP
		r.Post("/mcp", mcpH.ServeHTTP)
		r.Get("/mcp", mcpH.ServeHTTP)
		r.Delete("/mcp", mcpH.ServeHTTP)
	})
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	})
	return r
}

// handleGlovoBasketResourceMeta is the RFC 9728 metadata of the basket host:
// the resource is the Glovo resource, so a client asks for a token with
// exactly that audience.
func (h *Handlers) handleGlovoBasketResourceMeta(w http.ResponseWriter, _ *http.Request) {
	if h.opts.OAuthServer == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(ProtectedResourceMeta{
		Resource:             h.opts.GlovoBasket.Resource,
		AuthorizationServers: []string{h.opts.OAuthServer.BaseURL},
		ScopesSupported:      []string{},
	})
}

func (h *Handlers) glovoBasketUnauthorized(w http.ResponseWriter, errCode, desc string) {
	v := `Bearer resource_metadata="` + h.glovoBasketMetadataURL() + `"`
	if errCode != "" {
		v += `, error="` + errCode + `", error_description="` + desc + `"`
	}
	w.Header().Set("WWW-Authenticate", v)
	body := map[string]string{"error": "unauthenticated"}
	if errCode != "" {
		body = map[string]string{"error": errCode, "error_description": desc}
	}
	writeJSON(w, http.StatusUnauthorized, body)
}

// glovoBasketBearerRequired answers a request without a bearer with the 401
// that points the client at this host's metadata.
func (h *Handlers) glovoBasketBearerRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") || strings.TrimSpace(a[7:]) == "" {
			h.glovoBasketUnauthorized(w, "", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// glovoBasketAudienceGate is the basket host's counterpart of
// glovoAudienceGate: here only a token whose audience is exactly the Glovo
// resource passes. scope.Resolve checks it again, with the grant, the
// membership and the allowlist.
func (h *Handlers) glovoBasketAudienceGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.UserFromContext(r.Context())
		if u == nil {
			h.glovoBasketUnauthorized(w, "", "")
			return
		}
		if !u.IsGlovoAudience() {
			glovoAudienceRefusals.WithLabelValues("glovo_basket_mcp").Inc()
			h.glovoBasketUnauthorized(w, "invalid_token", "this token's audience is not the glovo resource")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// glovoBasketPayloadResponse is the read model of the later human decision
// surface: the approval, its decision context, the exact frozen revision and
// the binding a decision must send.
type glovoBasketPayloadResponse struct {
	Approval        approvalWithContext          `json:"approval"`
	Basket          *glovobasket.DecisionPayload `json:"basket"`
	DecisionBinding decisionBinding              `json:"decision_binding"`
}

// GetGlovoBasketApproval handles GET /api/v1/action-approvals/{id}/glovo-basket:
// the bound owner, a human acting directly, reads what they are asked to
// approve. Every other caller and every unknown id get the same 404.
func (h *Handlers) GetGlovoBasketApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := h.workItemsUser(w, r)
	if !ok {
		return
	}
	notFound := func() { writeErrorCode(w, http.StatusNotFound, aarCodeNotFound, "action approval not found", nil) }
	g := h.opts.GlovoBasket
	if !g.complete() || !isGlovoOwnerCandidate(user) {
		notFound()
		return
	}
	id := chi.URLParam(r, "id")
	p, err := g.Payloads.DecisionPayload(r.Context(), id)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		notFound()
		return
	case err != nil:
		writeErrorCode(w, http.StatusServiceUnavailable, "unavailable", "cannot read this approval right now; try again later", nil)
		return
	}
	if p.Owner != user.PrincipalID() {
		notFound()
		return
	}
	// The same live membership the decision requires (glovoOwnerCheck): an
	// owner removed from the team reads nothing here either.
	var read func() ([][]string, error)
	if h.opts.TenantAuthzMode == TenantAuthzPrincipal && h.opts.PrincipalMembership != nil {
		prn := user.PrincipalID()
		read = func() ([][]string, error) {
			return h.opts.PrincipalMembership.MemberRolesForPrincipal(p.Tenant, prn)
		}
	}
	if ref := decideWrittenRole(user.PrincipalID(), "principal membership reader", p.Tenant, glovoMinDeciderRole,
		"reading a Glovo basket approval", read); ref.refused() {
		if ref.status == http.StatusForbidden {
			notFound()
			return
		}
		writeErrorCode(w, http.StatusServiceUnavailable, "unavailable", "cannot read this approval right now; try again later", nil)
		return
	}
	a, err := h.opts.WorkItems.ActionApproval(r.Context(), id)
	if err != nil {
		if errors.Is(err, workitems.ErrApprovalNotFound) {
			// The binding names this row: its absence is a broken ledger.
			writeErrorCode(w, http.StatusServiceUnavailable, "unavailable", "cannot read this approval right now; try again later", nil)
			return
		}
		writeActionApprovalError(w, err)
		return
	}
	c := h.decisionContext(a)
	writeJSON(w, http.StatusOK, glovoBasketPayloadResponse{
		Approval:        approvalWithContext{ActionApprovalRequest: a, DecisionContext: c},
		Basket:          p,
		DecisionBinding: decisionBinding{ApprovalRef: a.ID, ContextDigest: c.ContextDigest, ContentDigest: a.ArtifactHash},
	})
}
