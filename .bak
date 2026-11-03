package operations

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// SubmitCreatesExecutionEnv is the kill switch for the submitter-creates-the-
// execution behaviour: "on" or "off", empty is off. It stays off until the
// mctl-agents DevLoop continuation carries its own execution (mctl-agents#717
// S3); turning it on is a separate gitops step.
const SubmitCreatesExecutionEnv = "MCTL_SUBMIT_CREATES_EXECUTION"

// SubmitCreatesExecution reads MCTL_SUBMIT_CREATES_EXECUTION. Any value other
// than on, off or empty is an error: a mistyped switch must be refused
// loudly, never read as a mode the operator did not ask for.
func SubmitCreatesExecution() (bool, error) {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(SubmitCreatesExecutionEnv))); v {
	case "", "off":
		return false, nil
	case "on":
		return true, nil
	default:
		return false, fmt.Errorf("%s=%q: want on or off", SubmitCreatesExecutionEnv, v)
	}
}

// ExecutionRequired reports whether a submit of the named operation must
// carry an execution right now: the operation needs one and the switch is on.
func ExecutionRequired(opName string) (bool, error) {
	if !RequiresExecution(opName) {
		return false, nil
	}
	return SubmitCreatesExecution()
}

func checkExecutionRequired(op Operation, params map[string]string) error {
	required, err := ExecutionRequired(op.Name)
	if err != nil {
		return err
	}
	if required && strings.TrimSpace(params["execution_id"]) == "" {
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
