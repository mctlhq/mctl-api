package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// DefaultIssueWorkItemTenant is the tenant that owns the work item of an
// issue-driven run unless Options.IssueWorkItemTenant says otherwise. It is
// the tenant mctl-agents' SERVICE_TENANTS maps every service to, so a run
// submitted here and a DevLoop for the same issue dedupe onto one item.
const DefaultIssueWorkItemTenant = "mctl"

var issueURLParts = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/issues/([0-9]+)$`)

// canonicalIssueURL is the byte-exact external_key of an issue's work item:
// owner and repo lowercased, the number in decimal without leading zeros.
// It matches mctl-agents' canonical_issue_url, so every submitter opens the
// same item for the same issue. ok is false for a URL that does not parse.
func canonicalIssueURL(issueURL string) (key, title string, ok bool) {
	m := issueURLParts.FindStringSubmatch(issueURL)
	if m == nil {
		return "", "", false
	}
	n, err := strconv.ParseUint(m[3], 10, 63)
	if err != nil {
		return "", "", false
	}
	repo := strings.ToLower(m[1]) + "/" + strings.ToLower(m[2])
	return fmt.Sprintf("https://github.com/%s/issues/%d", repo, n), fmt.Sprintf("Investigate %s#%d", repo, n), true
}

// submitExecution is the execution a submitter created for a run it is about
// to submit.
type submitExecution struct {
	h    *Handlers
	item string
	exec string
	ref  string
	mut  workitems.Mutation
	// namespace is where the Workflow is created.
	namespace string
}

// prepareSubmitExecution makes sure a run of an operation that must carry a
// we_ execution has one before it is submitted (mctlhq/mctl-agents#717 S3,
// owner decision 2026-10-24: the submitter creates the execution, the agent
// never attaches its own).
//
//   - Not such an operation, or the caller already names an execution_id
//     (the DevLoop path): nothing to do, nothing changes.
//   - Otherwise the work item is resolved (the caller's work_item_id, else
//     the open item of the issue, created if there is none) and a Pending
//     argo execution is attached under the workflow's own name. input gains
//     work_item_id and execution_id.
//   - Any failure to do that is a refusal: the run is never submitted
//     without an execution, because "could not create the execution" is not
//     "no execution needed".
//
// The returned context carries the workflow name the execution was recorded
// under; ended must be called with Submit's outcome so an execution whose
// workflow never started does not stay open.
func (h *Handlers) prepareSubmitExecution(w http.ResponseWriter, r *http.Request, user *auth.User, op operations.Operation, tenant string, input map[string]string) (ctx context.Context, ended func(*operations.SubmitResult, error) string, ok bool) {
	ctx = r.Context()
	required, err := operations.ExecutionRequired(op.Name)
	if err != nil {
		slog.Error("submit-creates-execution switch is unreadable", "error", err)
		writeErrorCode(w, http.StatusInternalServerError, "submit_switch_invalid", err.Error(), nil)
		return nil, nil, false
	}
	// Switch off (the default) or another operation: exactly today's path.
	if !required || strings.TrimSpace(input["execution_id"]) != "" {
		return ctx, func(*operations.SubmitResult, error) string { return "" }, true
	}
	if h.opts.WorkItems == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, wiCodeUnavailable,
			op.Name+" needs the work-items store to record its execution; it is not configured", nil)
		return nil, nil, false
	}
	key, title, parsed := canonicalIssueURL(input["issue_url"])
	if !parsed {
		writeErrorCode(w, http.StatusBadRequest, wiCodeInvalid, "issue_url does not name a GitHub issue", nil)
		return nil, nil, false
	}

	surface := defaultWorkItemSurface
	if relay, relayed := user.RelaySurface(); relayed {
		surface = relay
	}
	mut := workitems.Mutation{
		Actor: principalOf(user), ActingPrincipal: user.ActingPrincipal(),
		ActorPrincipalID: user.PrincipalID(), ViaPrincipalID: user.ViaPrincipalID(),
		ViaExecutionID: user.ExecutionID(), ActorClientID: user.OAuthClientID(),
		Surface: surface,
	}
	if meta, found := ClientMetaFromContext(ctx); found {
		mut.RequestID = truncateRequestID(meta.RequestID)
	}

	itemID := strings.TrimSpace(input["work_item_id"])
	if itemID == "" {
		tenant := h.opts.IssueWorkItemTenant
		if tenant == "" {
			tenant = DefaultIssueWorkItemTenant
		}
		item, _, err := h.opts.WorkItems.Create(ctx, workitems.CreateInput{
			Mutation: mut, Tenant: tenant, Visibility: workitems.VisibilityTenant,
			OriginSurface: surface, Title: title, ExternalKey: key,
		})
		if err != nil {
			writeWorkItemError(w, err)
			return nil, nil, false
		}
		itemID = item.ID
	}

	requestID := operations.NewWorkflowRequestID()
	ref := operations.WorkflowNameFor(op, requestID)
	exec, _, err := h.opts.WorkItems.AttachExecution(ctx, workitems.ExecutionInput{
		Mutation: mut, WorkItemID: itemID, Engine: workitems.EngineArgo, EngineRef: ref, Phase: workitems.PhasePending,
	})
	if err != nil {
		writeWorkItemError(w, err)
		return nil, nil, false
	}
	input["work_item_id"] = itemID
	input["execution_id"] = exec.ID

	se := &submitExecution{h: h, item: itemID, exec: exec.ID, ref: ref, mut: mut,
		namespace: operations.WorkflowNamespace(op.WorkflowTemplate, tenant)}
	return operations.WithWorkflowRequestID(ctx, requestID), se.ended, true
}

// ended settles the execution after Submit. It returns a note for the error
// response, "" when there is nothing to add.
//
// A Submit error does not prove the Workflow was never created (a timeout or
// a cancelled context can follow an accepted create), so the execution is
// ended in Error only once the Workflow is confirmed absent. Any other
// answer, including a failed lookup, leaves it open and says so: "could not
// observe" is not "absent".
func (se *submitExecution) ended(result *operations.SubmitResult, submitErr error) string {
	if submitErr == nil {
		if result != nil && result.WorkflowName != se.ref {
			// The execution was recorded under a name the workflow does not
			// bear, so the run cannot be correlated by it. Loud, not silent.
			slog.Error("workflow name differs from the name its execution was recorded under",
				"workflow", result.WorkflowName, "engine_ref", se.ref, "execution_id", se.exec)
		}
		return ""
	}
	// The request context may be what failed; the lookup and close must still be tried.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 10*time.Second)
	defer cancel()
	_, lookupErr := se.h.opts.Executor.GetWorkflowStatus(ctx, se.namespace, se.ref)
	switch {
	case lookupErr == nil:
		slog.Error("submit failed but the workflow exists; its execution stays open",
			"work_item_id", se.item, "execution_id", se.exec, "workflow", se.ref, "submit_error", submitErr)
		return fmt.Sprintf("; workflow %s exists and its execution %s was left open", se.ref, se.exec)
	case !apierrors.IsNotFound(lookupErr):
		slog.Error("submit failed and whether the workflow exists could not be determined; its execution stays open",
			"work_item_id", se.item, "execution_id", se.exec, "workflow", se.ref, "submit_error", submitErr, "error", lookupErr)
		return fmt.Sprintf("; could not determine whether workflow %s was created, so its execution %s was left open", se.ref, se.exec)
	}
	_, _, err := se.h.opts.WorkItems.AttachExecution(ctx, workitems.ExecutionInput{
		Mutation: se.mut, WorkItemID: se.item, Engine: workitems.EngineArgo, EngineRef: se.ref, Phase: workitems.PhaseError,
	})
	if err != nil {
		slog.Error("submit failed and its execution could not be ended; it stays open",
			"work_item_id", se.item, "execution_id", se.exec, "engine_ref", se.ref, "submit_error", submitErr, "error", err)
		return fmt.Sprintf("; its execution %s could not be ended and was left open", se.exec)
	}
	return ""
}
