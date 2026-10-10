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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/mctlhq/mctl-api/internal/telemetry"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
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
// mctl-agents-run is platform-scoped and lives in argo-workflows ns where its
// secrets (mctl-agents-secrets, ghcr-credentials, mctl-gitops-deploy-key) are.
// mctl-agents-implement (Tier 2) shares the same secrets and runs in the same ns.
// mctl-agents-shepherd (Tier 3) likewise reuses the argo-workflows secrets.
// mctl-agents-investigate (issue-driven entry) reuses them as well.
// mctl-agents-approve (proposal flip) needs the deploy key + gitops mutex there.
func WorkflowNamespace(workflowTemplate, team string) string {
	switch workflowTemplate {
	case "create-tenant", "delete-tenant", "delete-tenant-safe",
		// add/remove-custom-domain moved out of tenant namespaces
		// (2026-08-29): they need the Backstage workflow token, and
		// replicating that platform credential into tenant namespaces
		// would let any tenant read it (tenant SAs can get secrets) and
		// impersonate the workflow tier against the auth-gated
		// custom-domains routes (mctl-portal#89, mctl-gitops#933). Both
		// workflows only mount platform-level secrets (deploy key,
		// backstage-workflow-token) that live in argo-workflows.
		"add-custom-domain", "remove-custom-domain",
		"platform-skill-publish", "platform-skill-deprecate",
		"platform-skill-enable", "platform-skill-disable",
		"mctl-agents-run",
		"mctl-agents-implement",
		"mctl-agents-shepherd",
		"mctl-agents-investigate",
		// approve flips a proposal's .status.yaml via gitops commit — it
		// needs the same argo-workflows-namespace deploy key and the
		// mctl-gitops-main-writes mutex as its siblings above.
		"mctl-agents-approve",
		// reconcile writes the same .status.yaml files from the same
		// clone-and-push shape, so it needs that deploy key and that
		// mutex too. Omitting it here returns the team verbatim
		// ("platform" for an AdminOnly op with no team_name), which is
		// not a namespace that exists — the operation would be declared
		// and unusable (claude P1 on #234).
		"mctl-agents-reconcile":
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
		"mctl.ai/user":       labelValue(userID),
		"mctl.ai/team":       labelValue(team),
	}
	wf.SetLabels(labels)
	// Trace correlation: inert metadata, set only when a trace context exists.
	if tp := telemetry.TraceparentFrom(ctx); tp != "" {
		wf.SetAnnotations(map[string]string{
			"mctl.ai/traceparent": tp,
			"mctl.ai/trace-id":    telemetry.TraceIDFrom(ctx),
		})
	}
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
			"status":       PhaseToOpStatus(phase),
			"user":         "cron",
			"timestamp":    creationTimestamp,
			"riskLevel":    "low",
			"message":      message,
			"source":       "cron",
		})
	}
	return items, nil
}

// PhaseToOpStatus maps Argo's workflow.status.phase to the same
// status vocabulary the audit log uses ("submitted" / "succeeded" /
// "failed" / "error"), so audit + cron entries can be merged in the
// handler without the caller second-guessing two formats.
func PhaseToOpStatus(phase string) string {
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

	// Status is an ALLOWLIST, not the full block: only the keys below
	// survive, and a caller that needs another one has to add it here.
	if status, ok := obj["status"].(map[string]interface{}); ok {
		trimmedStatus := map[string]interface{}{}
		for _, key := range []string{"phase", "startedAt", "finishedAt", "estimatedDuration", "progress", "message", "conditions"} {
			if v, exists := status[key]; exists {
				trimmedStatus[key] = v
			}
		}
		// Trim nodes to essential fields only.
		//
		// `hostNodeName` is here because it is the only field in this
		// projection that says whether a Pod node ever reached a kubelet.
		// `phase` cannot answer that: a node blocked on a synchronization
		// lock and then killed by a deadline is Failed with no pod, and a
		// pod that ran and exited non-zero is Failed too. Dropping it made
		// those two indistinguishable to mctl-agents' implement-outcome
		// taxonomy, which then read every FAILED implementer as one that
		// never started and requeued it — including, in principle, one
		// that had already committed and pushed (mctl-agents#395, #399).
		// `startedAt` is not a substitute: Argo stamps it when the node is
		// created, which for a node waiting on a mutex is while it is
		// still Pending.
		//
		// `templateRef` is here for the same reason in a smaller way: a
		// step resolved through a templateRef leaves `templateName` empty
		// on the node, so without it a caller cannot tell which template
		// a node ran once a CWFT pulls one in by reference.
		//
		// Both are scalars. `outputs` is deliberately still excluded — it
		// carries artifacts and parameters and would undo the trimming
		// this function exists for.
		if nodes, ok := status["nodes"].(map[string]interface{}); ok {
			trimmedNodes := map[string]interface{}{}
			for nodeID, nodeVal := range nodes {
				if node, ok := nodeVal.(map[string]interface{}); ok {
					tn := map[string]interface{}{}
					for _, key := range []string{"displayName", "phase", "type", "startedAt", "finishedAt", "message", "templateName", "templateRef", "hostNodeName"} {
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

	if traceID, source := workflowTraceID(obj); traceID != "" {
		result["trace"] = map[string]interface{}{"trace_id": traceID, "source": source}
	}

	return result
}

var (
	w3cTraceparent = regexp.MustCompile(`^00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)
	w3cTraceID     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// workflowTraceID names the trace a workflow belongs to, so a caller holding
// only a workflow name (an ArgoWorkflowFailed alert, a ticket) can open the
// trace in Tempo and from there the logs (mctlhq/mctl-agent#97).
//
// The `traceparent` argument wins: it is the parent the pod's own spans are
// recorded under, which is the execution trace a DevLoop run lives in
// (mctlhq/mctl-agents#195). The `mctl.ai/trace-id` annotation, the trace of
// the mctl-api request that submitted the workflow, is the fallback. A value
// that is not a well-formed, non-zero W3C trace id is ignored rather than
// passed on, and no trace at all is reported as no `trace` key: a caller
// must read its absence as "not known", never as "no trace exists".
func workflowTraceID(obj map[string]interface{}) (string, string) {
	if spec, ok := obj["spec"].(map[string]interface{}); ok {
		if args, ok := spec["arguments"].(map[string]interface{}); ok {
			params, _ := args["parameters"].([]interface{})
			for _, p := range params {
				param, ok := p.(map[string]interface{})
				if !ok || param["name"] != "traceparent" {
					continue
				}
				value, _ := param["value"].(string)
				if m := w3cTraceparent.FindStringSubmatch(value); m != nil && !allZero(m[1]) {
					return m[1], "traceparent-argument"
				}
			}
		}
	}
	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		if ann, ok := meta["annotations"].(map[string]interface{}); ok {
			value, _ := ann["mctl.ai/trace-id"].(string)
			if w3cTraceID.MatchString(value) && !allZero(value) {
				return value, "submit-annotation"
			}
		}
	}
	return "", ""
}

func allZero(s string) bool {
	return strings.Trim(s, "0") == ""
}

// labelValue makes s usable as a Kubernetes label value. A value that is
// already valid is returned unchanged, so existing selectors keep matching.
// Anything else -- a CI principal "ci:owner/repo" (mctl-api#530), an OIDC
// display that is an email -- would make the apiserver reject the whole
// Workflow, so it is rewritten: invalid characters become '.', the result is
// cut to fit, and a short hash of the original keeps two distinct callers
// distinct. The unaltered value is still logged and audited elsewhere.
func labelValue(s string) string {
	if len(validation.IsValidLabelValue(s)) == 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('.')
		}
	}
	sum := sha256.Sum256([]byte(s))
	suffix := hex.EncodeToString(sum[:4])
	body := b.String()
	if max := validation.LabelValueMaxLength - len(suffix) - 1; len(body) > max {
		body = body[:max]
	}
	body = strings.Trim(body, "-_.")
	if body == "" {
		return "x" + suffix
	}
	return body + "-" + suffix
}

func buildArgoParams(params map[string]string) []interface{} {
	result := make([]interface{}, 0, len(params))
	for k, v := range params {
		result = append(result, map[string]interface{}{"name": k, "value": v})
	}
	return result
}
