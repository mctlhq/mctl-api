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

package operations

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var workflowGVR = schema.GroupVersionResource{
	Group:    "argoproj.io",
	Version:  "v1alpha1",
	Resource: "workflows",
}

// Executor submits Argo Workflows for platform operations.
type Executor struct {
	dynamicClient dynamic.Interface
}

// SubmitResult contains the result of submitting a workflow.
type SubmitResult struct {
	WorkflowName string `json:"workflowName"`
	Namespace    string `json:"namespace"`
	RequestID    string `json:"requestId"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
}

// NewExecutor creates an Executor that submits workflows to team namespaces.
// Tries in-cluster config first, falls back to KUBECONFIG for local dev.
func NewExecutor() *Executor {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			slog.Warn("failed to build kubeconfig — workflow submission will be unavailable", "error", err)
			return &Executor{}
		}
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		slog.Warn("failed to create dynamic client — workflow submission will be unavailable", "error", err)
		return &Executor{}
	}

	return &Executor{dynamicClient: dynClient}
}

// WorkflowNamespace returns the namespace a workflow should run in.
// Most workflows execute in the tenant's namespace where team-scoped secrets live.
// Tenant lifecycle operations (create/delete) run in argo-workflows namespace
// because the tenant namespace may not exist yet (create) or is being removed (delete).
// OpenClaw skill workflows (save/delete) also run in argo-workflows: they only
// need the gitops deploy key secret (cluster-wide) and would otherwise contend
// with the tenant's running OpenClaw pod for its CPU quota.
func WorkflowNamespace(workflowTemplate, team string) string {
	switch workflowTemplate {
	case "create-tenant", "delete-tenant", "delete-tenant-safe",
		"openclaw-skill-save", "openclaw-skill-delete":
		return "argo-workflows"
	}
	return team
}

// Submit creates an Argo Workflow CR referencing the ClusterWorkflowTemplate.
func (e *Executor) Submit(ctx context.Context, op Operation, params map[string]string, userID string, team string) (*SubmitResult, error) {
	if team == "" {
		return nil, fmt.Errorf("team is required for workflow submission")
	}
	namespace := WorkflowNamespace(op.WorkflowTemplate, team)
	requestID := uuid.New().String()[:8]
	workflowName := fmt.Sprintf("%s-%s", op.WorkflowTemplate, requestID)

	// Log params, redacting secrets.
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
	slog.Info("submitting workflow",
		"operation", op.Name,
		"workflow", workflowName,
		"user", userID,
		"requestId", requestID,
		"params", logParams,
	)

	if e.dynamicClient == nil {
		return nil, fmt.Errorf("kubernetes client not available — check cluster config")
	}

	wf := &unstructured.Unstructured{}
	wf.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "Workflow",
	})
	wf.SetName(workflowName)
	wf.SetNamespace(namespace)
	labels := map[string]string{
		"mctl.ai/operation":  op.Name,
		"mctl.ai/request-id": requestID,
		"mctl.ai/user":       userID,
		"mctl.ai/team":       team,
	}
	wf.SetLabels(labels)
	wf.Object["spec"] = map[string]interface{}{
		"workflowTemplateRef": map[string]interface{}{
			"name":         op.WorkflowTemplate,
			"clusterScope": true,
		},
		"arguments": map[string]interface{}{
			"parameters": buildArgoParams(params),
		},
	}

	_, err := e.dynamicClient.Resource(workflowGVR).Namespace(namespace).Create(ctx, wf, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create workflow %s: %w", workflowName, err)
	}

	slog.Info("workflow created", "workflow", workflowName, "namespace", namespace)

	return &SubmitResult{
		WorkflowName: workflowName,
		Namespace:    namespace,
		RequestID:    requestID,
		Status:       "Pending",
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// GetWorkflowStatus fetches the current state of a workflow from the Kubernetes API.
// Returns a trimmed view with only the fields useful for status reporting.
func (e *Executor) GetWorkflowStatus(ctx context.Context, namespace, name string) (map[string]interface{}, error) {
	if e.dynamicClient == nil {
		return nil, fmt.Errorf("kubernetes client not available")
	}

	wf, err := e.dynamicClient.Resource(workflowGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return trimWorkflowStatus(wf.Object), nil
}

// trimWorkflowStatus extracts only the fields needed for status reporting,
// dropping verbose metadata (managedFields, annotations) and the full spec.
func trimWorkflowStatus(obj map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{}

	// Minimal metadata: name, namespace, labels, creationTimestamp.
	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		trimmed := map[string]interface{}{}
		for _, key := range []string{"name", "namespace", "creationTimestamp", "labels"} {
			if v, exists := meta[key]; exists {
				trimmed[key] = v
			}
		}
		result["metadata"] = trimmed
	}

	// Full status block — contains phase, nodes, conditions, timestamps.
	if status, ok := obj["status"].(map[string]interface{}); ok {
		trimmedStatus := map[string]interface{}{}
		for _, key := range []string{"phase", "startedAt", "finishedAt", "estimatedDuration", "progress", "message", "conditions"} {
			if v, exists := status[key]; exists {
				trimmedStatus[key] = v
			}
		}
		// Trim nodes to essential fields only.
		if nodes, ok := status["nodes"].(map[string]interface{}); ok {
			trimmedNodes := map[string]interface{}{}
			for nodeID, nodeVal := range nodes {
				if node, ok := nodeVal.(map[string]interface{}); ok {
					tn := map[string]interface{}{}
					for _, key := range []string{"displayName", "phase", "type", "startedAt", "finishedAt", "message", "templateName"} {
						if v, exists := node[key]; exists {
							tn[key] = v
						}
					}
					trimmedNodes[nodeID] = tn
				}
			}
			trimmedStatus["nodes"] = trimmedNodes
		}
		result["status"] = trimmedStatus
	}

	return result
}

func buildArgoParams(params map[string]string) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(params))
	for k, v := range params {
		result = append(result, map[string]interface{}{"name": k, "value": v})
	}
	return result
}
