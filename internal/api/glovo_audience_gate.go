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
	"regexp"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// glovoAudienceRoutes are the only requests a Glovo-audience access token
// may make. Empty in this slice: the token is refused on every route of the
// authenticated group, /mcp included.
var glovoAudienceRoutes = []struct {
	method string
	path   *regexp.Regexp
}{}

var glovoAudienceRefusals = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_glovo_audience_refusals_total",
	Help: "Requests refused because a glovo-audience token was presented on a route it may not reach, by route class.",
}, []string{"route_class"})

func init() { prometheus.MustRegister(glovoAudienceRefusals) }

func glovoAudienceRouteAllowed(method, path string) bool {
	for _, e := range glovoAudienceRoutes {
		if e.method == method && e.path.MatchString(path) {
			return true
		}
	}
	return false
}

// glovoAudienceGate confines a caller holding a Glovo-audience token to
// glovoAudienceRoutes. It runs first in the authenticated group, so a route
// added later is closed to such a token by default.
func (h *Handlers) glovoAudienceGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsGlovoAudience() && !glovoAudienceRouteAllowed(r.Method, r.URL.Path) {
			const desc = "this token's audience is the glovo resource; it is not valid for this route"
			glovoAudienceRefusals.WithLabelValues(supportAudienceRouteClass(r.URL.Path)).Inc()
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+desc+`"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": desc,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
