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
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/lifecycle"
	"github.com/mctlhq/mctl-api/internal/temporalclient"
)

// GetLifecycleConflict is the one READ in the recovery family: it answers
// what a follow-up recovery call needs before it is made, so an operator
// (or mctl_inspect_lifecycle_conflict) never has to assemble the picture from
// four separate reads. It is deliberately in its own file, distinct from
// handlers_lifecycle_recovery.go's four mutations: those import no client but
// the lifecycle store and the audit log, and answering the legacy
// DevLoopWorkflow question here needs the (optional, read-only)
// TemporalClient the dev-loop describe route already uses
// (handlers_dev_loop.go). Nothing in this file can signal, approve or start a
// workflow -- DescribeDevLoop and QueryShepherdInLoop are both pure reads.
//
// A nil TemporalClient degrades to "legacy answer unavailable", never to "no
// DevLoop": see legacyAnswer's own doc comment.

const (
	legacyAnswerOwned   = "owned"
	legacyAnswerFree    = "free"
	legacyAnswerUnknown = "unknown"
)

// legacyAnswer mirrors internal/mcp/lifecycle.go's lifecycleLegacy for the
// HTTP surface: whether a live DevLoopWorkflow is driving the same entity.
// Available is false whenever the question could not be put (no Temporal
// client configured, no proposal_ref/temporal_workflow_id on the record, the
// describe route unreachable) -- never omitted and never conflated with "no
// DevLoop", which is a real, obtained answer of its own.
type legacyAnswer struct {
	Available bool   `json:"available"`
	Answer    string `json:"answer"`
	Reason    string `json:"reason,omitempty"`

	WorkflowID     string `json:"workflow_id,omitempty"`
	Status         string `json:"status,omitempty"`
	ShepherdInLoop *bool  `json:"shepherd_in_loop,omitempty"`
}

func legacyAnswerToEnum(answer string) lifecycle.LegacyAnswer {
	switch answer {
	case legacyAnswerOwned:
		return lifecycle.LegacyOwned
	case legacyAnswerFree:
		return lifecycle.LegacyFree
	default:
		return lifecycle.LegacyUnknown
	}
}

// recoveryPreconditionsView is the exact precondition values a follow-up
// recovery call must send, read off the same row this response describes.
// Serving them here is what lets an operator (or an agent reading this tool)
// copy them verbatim into mctl_fence_lifecycle_claim and friends instead of
// re-deriving a CAS input by hand.
type recoveryPreconditionsView struct {
	ExpectedOwnerType  string `json:"expected_owner_type"`
	ExpectedOwnerID    string `json:"expected_owner_id"`
	ExpectedEpoch      int    `json:"expected_epoch"`
	ExpectedVersion    string `json:"expected_version"`
	ExpectedLastSeenAt string `json:"expected_last_seen_at"`
}

type lifecycleConflictResponse struct {
	Ownership     *lifecycle.Ownership      `json:"ownership"`
	Derived       lifecycle.Derived         `json:"derived"`
	Legacy        legacyAnswer              `json:"legacy"`
	Divergence    lifecycle.Divergence      `json:"divergence"`
	Events        []*lifecycle.Event        `json:"events"`
	Preconditions recoveryPreconditionsView `json:"preconditions"`
}

// lifecycleConflictEventsLimit bounds the transition history attached to one
// conflict read. This route answers about ONE entity phase, unlike the
// fan-out-capped list mode in internal/mcp/lifecycle.go, so a single generous
// page is enough context without a cap of its own.
const lifecycleConflictEventsLimit = 20

// GetLifecycleConflict handles GET /api/v1/lifecycle/ownership/conflict.
func (h *Handlers) GetLifecycleConflict(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireLifecycleAdmin(w, r); !ok {
		return
	}
	q := r.URL.Query()
	kind, id, phase := q.Get("kind"), q.Get("id"), q.Get("phase")
	if kind == "" || id == "" || phase == "" {
		writeError(w, http.StatusBadRequest, "kind, id and phase are required")
		return
	}
	entity := lifecycle.EntityRef{Kind: kind, ID: id}

	owned, err := h.opts.Lifecycle.Get(r.Context(), entity, phase)
	if err != nil {
		writeLifecycleError(w, err, nil)
		return
	}

	now := time.Now().UTC()
	derived := lifecycle.Derive(owned, now)
	legacy := h.lifecycleLegacyFor(r.Context(), owned)
	divergence := lifecycle.ClassifyDerived(owned, derived, true, legacyAnswerToEnum(legacy.Answer))

	events, err := h.opts.Lifecycle.Events(r.Context(), entity, phase, lifecycleConflictEventsLimit)
	if err != nil {
		// Events are detail, not the answer: a failed events read must not
		// fail the conflict read the caller actually asked for. An empty
		// slice here reads identically to "no transitions", which is a
		// pre-existing ambiguity this route inherits from ListLifecycleEvents
		// rather than one it introduces.
		events = nil
	}

	writeJSON(w, http.StatusOK, lifecycleConflictResponse{
		Ownership:  owned,
		Derived:    derived,
		Legacy:     legacy,
		Divergence: divergence,
		Events:     events,
		Preconditions: recoveryPreconditionsView{
			ExpectedOwnerType:  owned.Owner.Type,
			ExpectedOwnerID:    owned.Owner.ID,
			ExpectedEpoch:      owned.Epoch,
			ExpectedVersion:    owned.Entity.Version,
			ExpectedLastSeenAt: owned.LastSeenAt.UTC().Format(time.RFC3339Nano),
		},
	})
}

// devLoopWorkflowIDPrefix is what temporalclient.WorkflowIDForProposalRef
// builds -- the only thing on a stored id that says which kind of workflow it
// names. Mirrors internal/mcp/lifecycle.go's constant of the same name (a
// different package; not shared to avoid a cross-package dependency for one
// string literal).
const devLoopWorkflowIDPrefix = "dev-loop-" //nolint:gosec // G101 matches ID+literal; a Temporal workflow id prefix, not a credential

// lifecycleLegacyFor asks the old mechanism about one entity, in-process
// (unlike internal/mcp/lifecycle.go's version of this logic, which is a
// separate binary that can only reach mctl-api over HTTP). The mapping is the
// same: a DEVLOOP-SHAPED stored id first, then reconstruction from
// proposal_ref, then "no way to ask".
func (h *Handlers) lifecycleLegacyFor(ctx context.Context, o *lifecycle.Ownership) legacyAnswer {
	if h.opts.TemporalClient == nil {
		return legacyAnswer{Answer: legacyAnswerUnknown, Reason: "dev-loop Temporal client not configured"}
	}
	stored := strings.TrimSpace(o.TemporalWorkflowID)
	if strings.HasPrefix(stored, devLoopWorkflowIDPrefix) {
		return h.lifecycleDescribeLegacy(ctx, stored)
	}
	if ref := strings.TrimSpace(o.ProposalRef); ref != "" {
		workflowID, err := temporalclient.WorkflowIDForProposalRef(ref)
		switch {
		case errors.Is(err, temporalclient.ErrNoDevLoopForProposalRef):
			// A slug with no issue-<N>- prefix never had a DevLoopWorkflow.
			// That is an answer, not a failure.
			return legacyAnswer{
				Available: true, Answer: legacyAnswerFree,
				Reason: fmt.Sprintf("proposal_ref %q names no DevLoopWorkflow", ref),
			}
		case err != nil:
			return legacyAnswer{Answer: legacyAnswerUnknown, Reason: err.Error()}
		}
		return h.lifecycleDescribeLegacy(ctx, workflowID)
	}
	if stored != "" {
		return legacyAnswer{
			Answer: legacyAnswerUnknown,
			Reason: fmt.Sprintf(
				"temporal_workflow_id %q is not a DevLoopWorkflow id, and the record carries no proposal_ref", stored),
		}
	}
	return legacyAnswer{Answer: legacyAnswerUnknown, Reason: "record carries neither proposal_ref nor temporal_workflow_id"}
}

// devLoopStatusUnknown is DescribeDevLoop's answer for an execution status it
// could not determine -- a statement about the read, not a workflow status.
const devLoopStatusUnknown = "Unknown"

func (h *Handlers) lifecycleDescribeLegacy(ctx context.Context, workflowID string) legacyAnswer {
	status, err := h.opts.TemporalClient.DescribeDevLoop(ctx, workflowID)
	if err != nil {
		if temporalclient.IsNotFound(err) {
			return legacyAnswer{
				Available: true, Answer: legacyAnswerFree, WorkflowID: workflowID,
				Reason: "no such DevLoopWorkflow (never started, or past retention)",
			}
		}
		return legacyAnswer{
			Answer: legacyAnswerUnknown, WorkflowID: workflowID,
			Reason: fmt.Sprintf("dev-loop describe failed: %v", err),
		}
	}
	out := legacyAnswer{WorkflowID: workflowID, Status: status}
	switch {
	case status == "" || status == devLoopStatusUnknown:
		out.Available = false
		out.Answer = legacyAnswerUnknown
		out.Reason = "the describe route did not report an execution status"
		return out
	case status != "Running":
		out.Available = true
		out.Answer = legacyAnswerFree
		return out
	}

	// Running: only a live execution can be shepherding anything, so ask.
	// The query gets its own short deadline (shepherdQueryTimeout,
	// handlers_dev_loop.go) rather than the request's, for the reason
	// GetDevLoopWorkflow's own comment gives -- a worker outage should
	// degrade to "unavailable" quickly, not hold this request open.
	qctx, cancel := context.WithTimeout(ctx, shepherdQueryTimeout)
	inLoop, qerr := h.opts.TemporalClient.QueryShepherdInLoop(qctx, workflowID)
	cancel()
	if qerr != nil {
		out.Available = false
		out.Answer = legacyAnswerUnknown
		out.Reason = "running, but the shepherd_in_loop query did not complete"
		return out
	}
	out.Available = true
	out.ShepherdInLoop = &inLoop
	if inLoop {
		out.Answer = legacyAnswerOwned
	} else {
		out.Answer = legacyAnswerFree
	}
	return out
}
