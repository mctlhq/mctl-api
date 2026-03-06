package operations

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// Executor submits Argo Workflows for platform operations.
type Executor struct {
	namespace string
}

// SubmitResult contains the result of submitting a workflow.
type SubmitResult struct {
	WorkflowName string `json:"workflowName"`
	Namespace    string `json:"namespace"`
	RequestID    string `json:"requestId"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
}

// NewExecutor creates an Executor for the given Argo Workflows namespace.
func NewExecutor(namespace string) *Executor {
	return &Executor{namespace: namespace}
}

// Submit creates and submits an Argo Workflow from a ClusterWorkflowTemplate.
//
// In production, this uses the Kubernetes API (client-go) to create a Workflow CR
// that references the ClusterWorkflowTemplate. For the PoC, we construct the
// Workflow manifest and apply it.
func (e *Executor) Submit(ctx context.Context, op Operation, params map[string]string, userID string) (*SubmitResult, error) {
	requestID := uuid.New().String()[:8]
	workflowName := fmt.Sprintf("%s-%s", op.WorkflowTemplate, requestID)

	slog.Info("submitting workflow",
		"operation", op.Name,
		"workflow", workflowName,
		"user", userID,
		"requestId", requestID,
	)

	// Build workflow parameters, filtering out secret values from logs.
	logParams := make(map[string]string, len(params))
	for _, p := range op.Parameters {
		if v, ok := params[p.Name]; ok {
			if p.Secret {
				logParams[p.Name] = "[REDACTED]"
			} else {
				logParams[p.Name] = v
			}
		}
	}
	slog.Info("workflow parameters", "params", logParams)

	// TODO: Use client-go to create the Workflow CR.
	// For now, return a simulated result for local development.
	//
	// Production implementation:
	//   wf := &unstructured.Unstructured{}
	//   wf.SetGroupVersionKind(schema.GroupVersionKind{
	//       Group: "argoproj.io", Version: "v1alpha1", Kind: "Workflow",
	//   })
	//   wf.SetName(workflowName)
	//   wf.SetNamespace(e.namespace)
	//   wf.SetLabels(map[string]string{
	//       "mctl.ai/operation":  op.Name,
	//       "mctl.ai/request-id": requestID,
	//       "mctl.ai/user":       userID,
	//   })
	//   spec := map[string]interface{}{
	//       "workflowTemplateRef": map[string]interface{}{
	//           "name":         op.WorkflowTemplate,
	//           "clusterScope": true,
	//       },
	//       "arguments": map[string]interface{}{
	//           "parameters": buildArgoParams(params),
	//       },
	//   }
	//   wf.Object["spec"] = spec
	//   _, err := dynamicClient.Resource(workflowGVR).Namespace(e.namespace).Create(ctx, wf, metav1.CreateOptions{})

	return &SubmitResult{
		WorkflowName: workflowName,
		Namespace:    e.namespace,
		RequestID:    requestID,
		Status:       "Pending",
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}
