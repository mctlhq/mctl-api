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
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// glovoBasketJoinMount is the basket join prefix relative to /api/v1.
const glovoBasketJoinMount = "/assistants/glovo-basket/v1"

// glovoBasketJoinPrefix is the full path prefix the basket service reaches.
const glovoBasketJoinPrefix = "/api/v1" + glovoBasketJoinMount + "/"

// GlovoBasketJoinRoutes is the basket join API (glovobasketjoin) that the
// separate Glovo basket service calls. It is dark: mounted only when Enabled
// and the one allowed service principal is configured, and cmd/api sets it
// only when GLOVO_BASKET_JOIN_ENABLED is true. Unmounted, the prefix is 404
// for everyone.
type GlovoBasketJoinRoutes struct {
	Enabled bool
	// ServiceProvider and ServiceSubject name the one federated service
	// identity (MCTL_OIDC_PROVIDERS entry of kind service, and its subject)
	// that may call the routes.
	ServiceProvider, ServiceSubject string
	// Handler is glovobasketjoin.Service.Handler().
	Handler http.Handler
}

func (g *GlovoBasketJoinRoutes) mounted() bool {
	return g != nil && g.Enabled && g.ServiceProvider != "" && g.ServiceSubject != "" &&
		!auth.IsReservedProviderName(g.ServiceProvider) && g.Handler != nil
}

// isService reports whether u is the configured basket service: a verified
// federated identity of kind service with exactly the configured provider
// and subject, no customer binding and none of the built-in principal types.
// Only a mounted configuration names a service at all.
func (g *GlovoBasketJoinRoutes) isService(u *auth.User) bool {
	if !g.mounted() || u == nil {
		return false
	}
	id, ok := u.Identity()
	return ok && id.Kind == auth.KindService && id.Customer == nil &&
		id.Provider == g.ServiceProvider && id.Subject == g.ServiceSubject &&
		!u.IsOrchestratorDevLoop() && !u.IsGlovoFacade() && !u.IsService() && !u.IsAgent() && !u.IsCI() &&
		!u.IsGlovoAudience() && !u.IsSupportAudience()
}

// glovoBasketJoinGate confines the basket join surface in both directions,
// like glovoJoinGate: the basket service reaches only the basket join prefix
// (every other path, /mcp included, is 401), and nobody else reaches the
// prefix (401). Unmounted, it does nothing and the prefix is the router's 404.
func (h *Handlers) glovoBasketJoinGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := h.opts.GlovoBasketJoin
		if !g.mounted() {
			next.ServeHTTP(w, r)
			return
		}
		user := auth.UserFromContext(r.Context())
		onPrefix := strings.HasPrefix(r.URL.Path, glovoBasketJoinPrefix)
		isSvc := g.isService(user)
		switch {
		case isSvc && !onPrefix:
			glovoRouteRefusals.WithLabelValues("basket_join_gate", "service_off_prefix").Inc()
			glovo.WriteUnauthenticated(w, "")
			return
		case !isSvc && onPrefix:
			glovoRouteRefusals.WithLabelValues("basket_join_gate", "not_service_identity").Inc()
			glovo.WriteUnauthenticated(w, "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// skipGlovoBasketServiceRateLimit exempts the basket service from the global
// per-principal limiter: one service id stands for every end user. The join
// routes enforce per-subject and aggregate limits themselves.
func (h *Handlers) skipGlovoBasketServiceRateLimit(limitMW func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limitMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.opts.GlovoBasketJoin.isService(auth.UserFromContext(r.Context())) {
				next.ServeHTTP(w, r)
				return
			}
			limited.ServeHTTP(w, r)
		})
	}
}
