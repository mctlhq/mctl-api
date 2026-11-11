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

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovojoin"
)

// glovoJoinMount is the join prefix relative to /api/v1; with /api/v1 it is
// contract.BasePath.
const glovoJoinMount = "/assistants/glovo/v1alpha1"

// GlovoJoinRoutes configures the join facade routes (mctl-api#957). A nil
// value or a false Enabled leaves every route unmounted (404).
type GlovoJoinRoutes struct {
	// Enabled is GLOVO_JOIN_ENABLED.
	Enabled bool
	// Routes serves the nine routes. Nil mounts a Routes with no dependency,
	// so every route that needs one answers 503 not_ready and /compatibility
	// reports deploy_ready false: the flag alone never makes the join live.
	Routes *glovojoin.Routes
}

func (g *GlovoJoinRoutes) mounted() bool { return g != nil && g.Enabled }

func (g *GlovoJoinRoutes) handler() http.Handler {
	var rt *glovojoin.Routes
	if g.Routes == nil {
		rt = &glovojoin.Routes{}
	} else {
		// A copy: the caller's hook is wrapped, never replaced in place.
		rt = glovojoin.CloneRoutes(g.Routes)
	}
	prev := rt.OnRefused
	rt.OnRefused = func(e glovojoin.Refused) {
		glovoRouteRefusals.WithLabelValues("join_"+e.Route, e.Reason).Inc()
		if prev != nil {
			prev(e)
		}
	}
	return rt.Handler()
}

// skipGlovoFacadeRateLimit exempts the facade principal from the global
// per-principal limiter: every facade request carries the same principal id,
// so one limiter would be a single 300/min bucket for all end users. The join
// routes enforce their own per-subject and aggregate limits.
func skipGlovoFacadeRateLimit(limitMW func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		limited := limitMW(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.UserFromContext(r.Context()).IsGlovoFacade() {
				next.ServeHTTP(w, r)
				return
			}
			limited.ServeHTTP(w, r)
		})
	}
}
