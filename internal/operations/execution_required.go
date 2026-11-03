package operations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// InvestigateOperation is the issue-investigator operation, the one whose
// runs must carry the work-item execution they belong to.
const InvestigateOperation = "mctl-agents-investigate"

// ErrExecutionRequired is returned (wrapped) when an operation that must be
// correlated to a work-item execution is submitted without an execution_id.
// The agent no longer attaches its own execution (mctlhq/mctl-agents#717,
// owner decision 2026-10-24): the submitter creates it first.
var ErrExecutionRequired = errors.New("operation requires an execution_id")

// RequiresExecution reports whether runs of the named operation must be
// submitted with a work-item execution.
func RequiresExecution(opName string) bool {
	return opName == InvestigateOperation
}

func checkExecutionRequired(op Operation, params map[string]string) error {
	if RequiresExecution(op.Name) && strings.TrimSpace(params["execution_id"]) == "" {
		return fmt.Errorf("%w: %s", ErrExecutionRequired, op.Name)
	}
	return nil
}

type workflowRequestIDKey struct{}

var workflowRequestIDPattern = regexp.MustCompile(`^[0-9a-f]{8}$`)

// NewWorkflowRequestID returns a fresh request id, the suffix of the
// workflow name Submit creates. A caller that must record the workflow's
// name before the workflow exists passes it through WithWorkflowRequestID.
func NewWorkflowRequestID() string {
	return uuid.New().String()[:8]
}

// WithWorkflowRequestID makes Submit name the workflow
// <template>-<requestID> instead of drawing a fresh id.
func WithWorkflowRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, workflowRequestIDKey{}, requestID)
}

// WorkflowRequestIDFrom returns the id set by WithWorkflowRequestID, when it
// has the shape Submit generates.
func WorkflowRequestIDFrom(ctx context.Context) (string, bool) {
	id, _ := ctx.Value(workflowRequestIDKey{}).(string)
	return id, workflowRequestIDPattern.MatchString(id)
}

// WorkflowNameFor is the name Submit gives a workflow of op submitted with
// requestID.
func WorkflowNameFor(op Operation, requestID string) string {
	return fmt.Sprintf("%s-%s", op.WorkflowTemplate, requestID)
}
