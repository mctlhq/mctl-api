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
	"errors"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/ghactions"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// The one workflow this endpoint can start, pinned as constants rather than
// taken from the request. There is no repo/workflow/ref parameter on purpose:
// a generic "dispatch any workflow" endpoint would make mctl-api's GitHub
// token a remote-execution primitive for every workflow in the organisation,
// and the admin check here would be the only thing between an MCP client and
// all of them. One named target means the blast radius is the target, and it
// is reviewable in this diff.
//
// portalServerAuthRef is `main` because the workflow refuses to run on
// anything else (its apply job carries `if: github.ref == 'refs/heads/main'`,
// and the cloudflare-apply environment's branch policy allows main alone).
// Sending another ref would produce a run that starts and immediately skips.
//
// portalServerAuthRoot is a CONSTANT, and that is the whole security argument
// of this endpoint. cloudflare-apply.yml applies whichever OpenTofu root its
// `root` input names -- the four Cloudflare zone and account roots included --
// and it maps that root to a matching write credential. Taking the root from
// the caller would turn this into "apply any Cloudflare root", with the admin
// check as the only thing in the way. Pinned here, the blast radius is this
// one root, and it is reviewable in this diff. The handler accepts no body
// for the same reason.
const (
	portalServerAuthOwner    = "mctlhq"
	portalServerAuthRepo     = "mctl-gitops"
	portalServerAuthWorkflow = "cloudflare-apply.yml"
	portalServerAuthRef      = "main"
	portalServerAuthRoot     = "infrastructure/cloudflare/portal"
)

// portalServerAuthRunsURL is where a caller watches what this started. The
// dispatch API answers 204 with no run id — at that moment the run does not
// exist yet — so this is a link to the workflow's run list, not to a run. See
// ghactions.Dispatcher.Dispatch.
const portalServerAuthRunsURL = "https://github.com/" + portalServerAuthOwner + "/" + portalServerAuthRepo +
	"/actions/workflows/" + portalServerAuthWorkflow

// DispatchPortalServerAuthApply handles
// POST /api/v1/cloudflare/portal/server-auth/apply.
//
// It starts mctl-gitops' cloudflare-apply.yml on the portal root, which applies the
// committed OAuth registration (endpoints, client, and above all the scope)
// of the Cloudflare MCP portal's upstream servers.
//
// What this endpoint deliberately does NOT do is apply anything. It holds no
// Cloudflare credential and cannot obtain one: the write token is an
// environment secret on mctl-gitops' `cloudflare-apply` environment, issued
// only to a job that requests that environment, and only after a human
// reviewer approves it. So a call here starts a plan someone still has to
// look at and approve — the same two-decision shape the workflow has for an
// operator dispatching it by hand. An MCP client that wanted to change a
// portal scope on its own would have to get past a person to do it, and that
// property is why the dispatch lives here instead of a Cloudflare client.
func (h *Handlers) DispatchPortalServerAuthApply(w http.ResponseWriter, r *http.Request) {
	if h.opts.WorkflowDispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "GitHub workflow dispatch not configured (set GITOPS_ACTIONS_TOKEN)")
		return
	}
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "portal server-auth apply is admin-only")
		return
	}

	// No request body is read. The workflow takes no inputs — what it applies
	// is the file at HEAD of main, and the script refuses anything else — so
	// there is nothing a caller could say here that would change the outcome,
	// and accepting a body would only invite the belief that there is.
	// The root belongs in the record as much as the workflow does:
	// cloudflare-apply.yml applies whichever root it is handed, so "which
	// root" is the whole meaning of this dispatch. An audit entry naming only
	// the workflow would read the same for an apply of any Cloudflare root.
	auditParams := map[string]string{
		"repo":     portalServerAuthOwner + "/" + portalServerAuthRepo,
		"workflow": portalServerAuthWorkflow,
		"ref":      portalServerAuthRef,
		"root":     portalServerAuthRoot,
	}

	err := h.opts.WorkflowDispatcher.Dispatch(r.Context(),
		portalServerAuthOwner, portalServerAuthRepo, portalServerAuthWorkflow, portalServerAuthRef,
		map[string]string{"root": portalServerAuthRoot})
	if err != nil {
		// A dispatch that never started is not a 500 on this side: the
		// request was well-formed and the caller can do nothing differently.
		// 502 says the far side refused, which is what happened.
		status := http.StatusBadGateway
		if errors.Is(err, ghactions.ErrNotConfigured) {
			status = http.StatusServiceUnavailable
		}
		slog.Error("failed to dispatch portal server-auth apply", "error", err, "user", user.ID)
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "portal-server-auth-apply",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(operations.RiskMedium),
			Message:    "failed to dispatch portal server-auth apply: " + err.Error(),
		})
		writeError(w, status, "failed to dispatch portal server-auth apply: "+err.Error())
		return
	}

	// Logged as succeeded because the dispatch succeeded — which is all this
	// endpoint did. Whether Cloudflare changed is decided later, by a human
	// approving the workflow's apply job, and is recorded in that run. The
	// audit entry must not read as if this call applied anything.
	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  "portal-server-auth-apply",
		Parameters: auditParams,
		Status:     "succeeded",
		RiskLevel:  string(operations.RiskMedium),
		Message:    "dispatched cloudflare-apply.yml on " + portalServerAuthRoot + "; the apply job still needs environment approval",
	})
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"repo":     portalServerAuthOwner + "/" + portalServerAuthRepo,
		"workflow": portalServerAuthWorkflow,
		"ref":      portalServerAuthRef,
		// Named for the same reason it is in the audit entry: the workflow is
		// shared across every Cloudflare root, so the root is what says which
		// one this call started.
		"root":     portalServerAuthRoot,
		"runs_url": portalServerAuthRunsURL,
		"message": "Dispatched cloudflare-apply.yml on main for " + portalServerAuthRoot + ". Nothing has been written to Cloudflare yet: " +
			"the run's plan job publishes the live-vs-committed comparison, and the apply job waits for a required " +
			"reviewer on the cloudflare-apply environment. Open the run to read the plan and approve it. " +
			"After an apply, the upstream must be signed out and back in in the portal — a refresh cannot widen an existing grant.",
	})
}
