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

	"github.com/mctlhq/mctl-api/internal/auth"
)

// The registry-publisher principal (mctlhq/mctl-agents#470): publishing a
// release to the agent registry with a dedicated least-privilege credential.
// See docs/agent-platform-registry.md, "Registry publisher principal".

const (
	codeRegistryPublisherForbidden = "registry_publisher_route_not_allowed"

	// registryPublisherRoutePrefix is the collection the publication routes
	// hang off. The three routes the publisher may call are:
	//
	//	POST /api/v1/agents                  create a definition
	//	POST /api/v1/agents/{name}/versions  publish a version
	//	POST /api/v1/agents/{name}/releases  promote, or roll back
	//
	// They are exactly the requests mctl-agents' tools/publish_agent_release.py
	// makes. That tool issues no GET: it learns that a definition is missing
	// from the 404 its own publish receives, so the publisher has no read
	// access to the registry at all.
	registryPublisherRoutePrefix = "/api/v1/agents"
)

// registryPublisherRouteAllowed reports whether a request is one of the
// three publication routes. It matches on the path chi itself routes on, and
// refuses outright when the request carries an encoded path: chi routes on
// URL.RawPath when it is set, so a request whose decoded and encoded
// spellings differ could otherwise be judged on one and dispatched on the
// other. Agent names need no percent-encoding, so nothing legitimate is lost.
func registryPublisherRouteAllowed(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.RawPath != "" {
		return false
	}
	rest, ok := strings.CutPrefix(r.URL.Path, registryPublisherRoutePrefix)
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	if !strings.HasPrefix(rest, "/") {
		return false
	}
	segments := strings.Split(rest[1:], "/")
	if len(segments) != 2 || segments[0] == "" {
		return false
	}
	return segments[1] == "versions" || segments[1] == "releases"
}

// registryPublisherGate confines the registry-publisher principal to the
// publication routes. Everything else -- the registry's own reads, its
// v1alpha2 mutations, /mcp, every tenant and admin route -- answers 403
// before any handler runs, mirroring usageWriterGate and evidenceWriterGate:
// the credential is one capability, not an API key.
func registryPublisherGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := auth.UserFromContext(r.Context()); user.IsRegistryPublisher() && !registryPublisherRouteAllowed(r) {
			writeErrorCode(w, http.StatusForbidden, codeRegistryPublisherForbidden,
				"the registry publisher may only call POST "+registryPublisherRoutePrefix+
					", POST "+registryPublisherRoutePrefix+"/{name}/versions and POST "+
					registryPublisherRoutePrefix+"/{name}/releases", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mayPublishToAgentRegistry is the one place that decides who may create a
// definition, publish a version, or promote and roll back a release: a
// person who is an admin, acting directly, or the registry publisher the
// mctl-agents release pipeline authenticates as.
//
// Not the agent service principal, although it carries the admins group
// (mctlhq/mctl-agents#470). That token is what every agent pod runs with,
// so admitting it here meant an agent could publish and promote a
// definition -- its own included -- on its own authority. The release
// pipeline has published as the registry publisher since mctl-agents
// 1.68.3; nothing else called these routes with the service token.
func mayPublishToAgentRegistry(u *auth.User) bool {
	return isHumanAdmin(u) || u.IsRegistryPublisher()
}

// requireAgentRegistryHumanAdmin guards the v1alpha2 mutations: publishing
// a definition or profile version, moving one through its lifecycle, and
// creating or rolling back a release binding. Same answers as
// requireAgentRegistryAdmin, but only a person who is an admin gets past
// it. These activate an agent as surely as the publication routes do, so
// the agent service principal is refused here for the same reason; the
// registry publisher never reaches them (registryPublisherGate).
func (h *Handlers) requireAgentRegistryHumanAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.AgentRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "agent registry not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !isHumanAdmin(user) {
		writeError(w, http.StatusForbidden, "agent registry changes need a human admin")
		return nil, false
	}
	return user, true
}

// requireAgentRegistryPublisherOrAdmin guards the three publication routes
// and only those. Same checks and same answers as requireAgentRegistryAdmin
// -- 503 unconfigured, 401 unauthenticated, 403 otherwise -- with
// mayPublishToAgentRegistry deciding the last one. The v1alpha2 mutations
// are on requireAgentRegistryHumanAdmin; every read, and
// RecordAgentExecution, stays on requireAgentRegistryAdmin.
func (h *Handlers) requireAgentRegistryPublisherOrAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	if h.opts.AgentRegistry == nil {
		writeError(w, http.StatusServiceUnavailable, "agent registry not configured")
		return nil, false
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !mayPublishToAgentRegistry(user) {
		writeError(w, http.StatusForbidden, "agent registry publication needs a human admin or the registry publisher")
		return nil, false
	}
	return user, true
}
