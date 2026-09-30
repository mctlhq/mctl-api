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

// Delegation grants for agent principals (mctl-api#376 slice B).
//
// An agent run token (mctl-api#376 slice A) authenticates the agent itself
// and carries no subject: it cannot say who the agent is acting for. This
// file is the mechanism layered on top: the X-MCTL-On-Behalf-Of header
// names a grant ref already bound to the run token's execution or work
// item, and the subject is read out of that stored grant row -- never from
// the header value, the request body, or the run token itself.
//
// Modelled closely on handlers_surface_identity.go's surfacePrincipalGate /
// relaySubject: agentPrincipalGate is the one place delegation resolves, so
// a delegation-eligible route can never be reached by an agent as itself
// when it names a header it cannot honour, and every gap fails closed with
// a typed, audited refusal.
import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/delegation"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// OnBehalfOfHeader names the grant an agent run is acting under. It carries
// a RECORD ID, never a principal: the subject is read from the record.
const OnBehalfOfHeader = "X-MCTL-On-Behalf-Of"

// maxGrantRefBytes bounds X-MCTL-On-Behalf-Of the same way every other
// grant/external id in this API is bounded (workitems.MaxExternalIDBytes).
// This gate runs before the global rate limiter (router.go) and writes the
// header verbatim into the agent_identity.delegation_refused audit entry on
// every refusal (refuseDelegation below), so an unvalidated, unbounded
// value here would let an authenticated-but-unaccepted caller grow audit
// storage on every request, unthrottled, before anything limits it.
const maxGrantRefBytes = workitems.MaxExternalIDBytes

// boundedRef truncates ref to maxGrantRefBytes before it is ever used in a
// log line or an audit parameter. It is never used to decide whether the
// grant is valid -- an over-long ref still fails delegation.Resolve's own
// lookup normally (ErrNotBound), this only caps what gets written about it.
func boundedRef(ref string) string {
	if len(ref) > maxGrantRefBytes {
		return ref[:maxGrantRefBytes]
	}
	return ref
}

// Typed refusal codes a client can branch on.
const (
	delegationCodeNotAccepted  = "delegation_not_accepted"
	delegationCodeNotSupported = "delegation_not_supported"
	delegationCodeNotBound     = "grant_not_bound"
	delegationCodeUnresolved   = "grant_subject_unresolved"
	delegationCodeUnavailable  = "delegation_unavailable"
)

// delegationRoute is one route an agent principal may delegate on.
type delegationRoute struct {
	method  string
	pattern *regexp.Regexp
}

// delegationRoutes is the narrowest set that makes the worker-side C7
// possible: the work-item and human-input routes a relayed human can
// already reach (surfaceRoutes in handlers_surface_identity.go), minus the
// ones where there is no prior grant to bind to. POST /work-items is
// deliberately excluded: creation NAMES an owner, so there is no prior
// grant to bind it to. POST /agent-run-tokens, POST /agents/dev-loop/*,
// POST /operations/{name}/execute and every /surface-identities/* route are
// excluded as privileged or identity-establishing (requirements.md "Open
// questions").
var delegationRoutes = []delegationRoute{
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/intents$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/surface-refs$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/work-items/[^/]+/execution-requests$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/v1/human-input/[^/]+/response$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/work-items/[^/]+$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/human-input$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/v1/human-input/[^/]+$`)},
}

// delegationAllowlisted reports whether method+path may carry
// X-MCTL-On-Behalf-Of.
func delegationAllowlisted(method, path string) bool {
	for _, route := range delegationRoutes {
		if route.method == method && route.pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// refuseDelegation answers one typed refusal and writes exactly one
// agent_identity.delegation_refused audit entry, shaped after
// relaySubject's refuse closure (handlers_surface_identity.go).
func (h *Handlers) refuseDelegation(w http.ResponseWriter, r *http.Request, acting *auth.User, agentName, ref, code string, status int, msg string) {
	h.logAudit(r, audit.Entry{
		UserID: acting.ID, Operation: "agent_identity.delegation_refused", Status: "failed",
		RiskLevel: string(operations.RiskMedium),
		Parameters: map[string]string{
			"acting_principal": acting.ID, "agent": agentName, "grant_ref": ref,
			"route": r.Method + " " + r.URL.Path, "reason": code,
		},
	})
	writeErrorCode(w, status, code, msg, nil)
}

// agentPrincipalGate resolves X-MCTL-On-Behalf-Of for an agent run token
// into the delegated subject the grant names, or refuses the request with a
// typed code. Every gap fails closed; unlike surfacePrincipalGate's relay,
// a delegation whose principal cannot be recorded refuses rather than
// proceeding without one (design.md B2 step 9): the whole point of this
// mechanism is a recorded subject.
func (h *Handlers) agentPrincipalGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ref := r.Header.Get(OnBehalfOfHeader)
		if user == nil || ref == "" {
			next.ServeHTTP(w, r)
			return
		}
		ref = boundedRef(ref)
		agentName, isAgent := user.AgentName()
		if !isAgent {
			h.refuseDelegation(w, r, user, "", ref, delegationCodeNotAccepted, http.StatusBadRequest,
				OnBehalfOfHeader+" may only be sent by an agent principal")
			return
		}
		if !delegationAllowlisted(r.Method, r.URL.Path) {
			h.refuseDelegation(w, r, user, agentName, ref, delegationCodeNotSupported, http.StatusBadRequest,
				"an agent principal may not delegate on "+r.Method+" "+r.URL.Path)
			return
		}
		if h.opts.Delegation == nil {
			writeErrorCode(w, http.StatusServiceUnavailable, delegationCodeUnavailable, "delegation is not configured", nil)
			return
		}
		bound := auth.AgentRun{
			Agent: agentName, ExecutionID: user.ExecutionID(), WorkItemID: user.WorkItemID(), RunID: user.AgentRunID(),
		}
		grant, err := h.opts.Delegation.Resolve(r.Context(), ref, bound)
		switch {
		case errors.Is(err, delegation.ErrNotBound):
			h.refuseDelegation(w, r, user, agentName, ref, delegationCodeNotBound, http.StatusForbidden,
				"the presented grant is not bound to this run")
			return
		case errors.Is(err, delegation.ErrSubjectUnresolved):
			h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
				"the presented grant names no resolvable subject")
			return
		case err != nil:
			slog.Error("delegation resolve failed", "error", err)
			writeErrorCode(w, http.StatusServiceUnavailable, delegationCodeUnavailable, "could not resolve the delegation grant", nil)
			return
		}
		login, isGitHub := strings.CutPrefix(grant.Subject, "github:")
		if !isGitHub || login == "" {
			h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
				"the grant does not name a GitHub principal")
			return
		}
		var groups []string
		if h.opts.TenantResolver != nil {
			// Same as authentication and as the surface relay: a failed
			// lookup grants no tenant, even if the resolver returned a
			// partial list alongside the error.
			if g, gerr := h.opts.TenantResolver.GetTenantsForUser(login); gerr != nil {
				slog.Warn("delegation: tenant lookup failed; delegating with no tenant access", "subject", grant.Subject, "error", gerr)
			} else {
				groups = g
			}
		}
		subject := auth.NewDelegatedUser(login, groups, user)
		if subject == nil {
			// Unreachable in practice: user.AgentName() already proved
			// isAgent, and login is non-empty by the check above. Refused
			// defensively rather than passing a nil user downstream.
			h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
				"the grant could not be resolved to a delegated subject")
			return
		}
		// Fail closed on every AttachPrincipal error, unlike the relay: a
		// delegated write whose principal id cannot be recorded must not
		// run at all, because a recorded subject is this mechanism's only
		// product (design.md B2 step 9).
		if aerr := auth.AttachPrincipal(r.Context(), h.opts.Principals, subject); aerr != nil {
			switch {
			case errors.Is(aerr, auth.ErrPrincipalDisabled):
				h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
					"the principal named by this grant is disabled")
				return
			case errors.Is(aerr, auth.ErrIdentityRefused):
				h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
					"the identity named by this grant is refused")
				return
			}
			slog.Error("delegation: principal could not be resolved", "subject", grant.Subject, "error", aerr)
			writeErrorCode(w, http.StatusServiceUnavailable, delegationCodeUnavailable, "could not resolve the delegated principal", nil)
			return
		}
		// The one place the two independent derivations of the subject's
		// principal (the stored grant column, and the live principal
		// resolver) are cross-checked. For KindSurfaceLink, grant carries no
		// SubjectPrincipalID of its own (a link stores none): this check is
		// how it gets one, from whatever AttachPrincipal just resolved via
		// the surface-link mirror.
		if grant.Kind == delegation.KindSurfaceLink {
			if subject.PrincipalID() == "" {
				h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
					"the grant names no resolvable principal")
				return
			}
		} else if subject.PrincipalID() != grant.SubjectPrincipalID {
			h.refuseDelegation(w, r, user, agentName, ref, delegationCodeUnresolved, http.StatusForbidden,
				"the grant's stored principal does not match its resolved identity")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), subject)))
	})
}
