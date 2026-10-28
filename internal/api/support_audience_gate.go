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

// supportAudienceRoutes are the only requests an access token minted for the
// support resource may make: the routes mctl-support calls with the caller's
// bearer (mctl-api#849). Everything else, /mcp included, is refused.
var supportAudienceRoutes = []struct {
	method string
	path   *regexp.Regexp
}{
	{http.MethodGet, regexp.MustCompile(`^/api/v1/whoami$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/executions$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/agent-run-tokens$`)},
}

var supportAudienceRefusals = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_support_audience_refusals_total",
	Help: "Requests refused because a support-audience token was presented on a route it may not reach (mctl-api#849), by route class.",
}, []string{"route_class"})

func init() { prometheus.MustRegister(supportAudienceRefusals) }

func supportAudienceRouteAllowed(method, path string) bool {
	for _, e := range supportAudienceRoutes {
		if e.method == method && e.path.MatchString(path) {
			return true
		}
	}
	return false
}

// supportAudienceRouteClass bounds the metric's label to two values.
func supportAudienceRouteClass(path string) string {
	if path == "/mcp" {
		return "mcp"
	}
	return "api"
}

// supportAudienceGate confines a caller holding a support-audience access
// token to supportAudienceRoutes. It must run before every other gate in the
// authenticated group, which also mounts /mcp, so a route added later is
// closed to such a token by default. 401, not 403: to any other route the
// token is not a credential at all.
func (h *Handlers) supportAudienceGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsSupportAudience() && !supportAudienceRouteAllowed(r.Method, r.URL.Path) {
			const desc = "this token's audience is the support agent; it is not valid for this route"
			supportAudienceRefusals.WithLabelValues(supportAudienceRouteClass(r.URL.Path)).Inc()
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
