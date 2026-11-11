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

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
)

// glovoJoinPrefix is the one route prefix the Glovo join facade principal
// reaches (mctl-api#957 design 2). It equals the contract BasePath.
var glovoJoinPath = regexp.MustCompile(`^/api/v1/assistants/glovo/v1alpha1/`)

// glovoJoinGate is the confinement of the join surface in both directions
// (T2). It runs right after the audience gates, before every other gate and
// before /mcp, so a route added later is closed by default:
//
//   - the facade principal reaches only glovoJoinPath; every other path,
//     /mcp included, is 401 not_authorized;
//   - any other principal on glovoJoinPath is 401 not_authorized too: the join
//     routes accept the facade identity and nothing else, so an admin, a user
//     or another machine token is not a credential for them.
//
// 401, not 403: to a route it may not reach the credential is not a credential
// at all, which is also what keeps this gate from being an oracle on which
// routes exist.
func (h *Handlers) glovoJoinGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		onJoin := glovoJoinPath.MatchString(r.URL.Path)
		switch {
		case user.IsGlovoFacade() && !onJoin:
			glovoRouteRefusals.WithLabelValues("join_gate", "facade_off_prefix").Inc()
			glovo.WriteUnauthenticated(w, "")
			return
		case !user.IsGlovoFacade() && onJoin:
			glovoRouteRefusals.WithLabelValues("join_gate", "not_facade_identity").Inc()
			glovo.WriteUnauthenticated(w, "")
			return
		}
		next.ServeHTTP(w, r)
	})
}
