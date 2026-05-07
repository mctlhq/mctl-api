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
	"strings"
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
// OpenClaw skill and identity workflows (save/delete) also run in argo-workflows:
// they only need the gitops deploy key secret (cluster-wide) and would otherwise
// contend with the tenant's running OpenClaw pod for its CPU quota.
// mctl-agents-run is platform-scoped and lives in argo-workflows ns where its
// secrets (mctl-agents-secrets, ghcr-credentials, mctl-gitops-deploy-key) are.
// mctl-agents-implement (Tier 2) shares the same secrets and runs in the same ns.
// mctl-agents-shepherd (Tier 3) likewise reuses the argo-workflows secrets.
func WorkflowNamespace(workflowTemplate, team string) string {
	switch workflowTemplate {
	case "create-tenant", "delete-tenant", "delete-tenant-safe",
		"openclaw-skill-save", "openclaw-skill-delete",
		"openclaw-identity-save", "openclaw-identity-delete",
		"mctl-agents-run",
		"mctl-agents-implement",
		"mctl-agents-shepherd":
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

// ListCronAgentRuns returns Argo Workflows in `namespace` that were
// launched directly by a CronWorkflow (label
// `workflows.argoproj.io/cron-workflow=<name>`) where the cron name
// matches `cronNamePrefix`. Workflows older than `since` are dropped.
//
// The audit log only records operator-initiated triggers (mctl-api
// REST POST → AuditLog.Append), so without this method
// `mctl_list_recent_agent_runs` is blind to cron-driven runs and the
// operator gets a false "agent system idle" reading. See
// ~/.claude/plans/mctl-agents-daily-cron-visibility.md for the
// 2026-05-07 incident that exposed this gap.
//
// Returns the same shape as audit-log entries (workflowName,
// operation, status, user, timestamp, riskLevel, message) plus a
// `source: "cron"` tag so the handler can merge cleanly.
func (e *Executor) ListCronAgentRuns(ctx context.Context, namespace, cronNamePrefix string, since time.Time) ([]map[string]interface{}, error) {
	if e.dynamicClient == nil {
		return nil, fmt.Errorf("kubernetes client not available")
	}

	list, err := e.dynamicClient.Resource(workflowGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		// Label selector: any Workflow with the cron-workflow label
		// (Argo CronWorkflow controller stamps this on every spawned
		// child Workflow). We further filter by name prefix in code
		// because LabelSelector doesn't support starts-with semantics.
		LabelSelector: "workflows.argoproj.io/cron-workflow",
	})
	if err != nil {
		return nil, fmt.Errorf("list cron-driven workflows: %w", err)
	}

	items := make([]map[string]interface{}, 0, len(list.Items))
	for i := range list.Items {
		wf := &list.Items[i]
		meta, _ := wf.Object["metadata"].(map[string]interface{})
		if meta == nil {
			continue
		}
		labels, _ := meta["labels"].(map[string]interface{})
		cronName, _ := labels["workflows.argoproj.io/cron-workflow"].(string)
		if cronNamePrefix != "" && !strings.HasPrefix(cronName, cronNamePrefix) {
			continue
		}
		creationTimestamp, _ := meta["creationTimestamp"].(string)
		if !since.IsZero() && creationTimestamp != "" {
			t, err := time.Parse(time.RFC3339, creationTimestamp)
			if err == nil && t.Before(since) {
				continue
			}
		}
		name, _ := meta["name"].(string)
		status, _ := wf.Object["status"].(map[string]interface{})
		phase, _ := status["phase"].(string)
		message, _ := status["message"].(string)

		items = append(items, map[string]interface{}{
			"workflowName": name,
			"operation":    cronName,
			"status":       phaseToOpStatus(phase),
			"user":         "cron",
			"timestamp":    creationTimestamp,
			"riskLevel":    "low",
			"message":      message,
			"source":       "cron",
		})
	}
	return items, nil
}

// phaseToOpStatus maps Argo's workflow.status.phase to the same
// status vocabulary the audit log uses ("submitted" / "succeeded" /
// "failed" / "error"), so audit + cron entries can be merged in the
// handler without the caller second-guessing two formats.
func phaseToOpStatus(phase string) string {
	switch phase {
	case "Pending", "Running":
		return "submitted"
	case "Succeeded":
		return "succeeded"
	case "Failed":
		return "failed"
	case "Error":
		return "error"
	default:
		return "unknown"
	}
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
