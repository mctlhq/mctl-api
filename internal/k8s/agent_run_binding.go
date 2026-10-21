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

package k8s

// Agent run binding (mctlhq/mctl-agents#737): an agent pod proves which run
// it is with its projected ServiceAccount token, and nothing it says about
// itself. The token names the pod (TokenReview), the pod names its Workflow
// (label + owner reference), and the Workflow names the agent, the scope
// and the execution (its ClusterWorkflowTemplate and execution_id
// parameter). Every link is read from the Kubernetes API.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Keys Kubernetes puts in a TokenReview's user extra for a token bound to a
// pod.
const (
	podNameExtra = "authentication.kubernetes.io/pod-name"
	podUIDExtra  = "authentication.kubernetes.io/pod-uid"
	// workflowLabel names the Workflow an Argo pod belongs to.
	workflowLabel = "workflows.argoproj.io/workflow"
	// executionParam is the Workflow parameter carrying the run's execution.
	executionParam = "execution_id"
)

var workflowGVR = schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "workflows"}

// AgentRunTemplate is what one ClusterWorkflowTemplate's runs may become.
type AgentRunTemplate struct {
	Agent string
	Scope string
}

// AgentRunBinding is a verified agent pod's run.
type AgentRunBinding struct {
	Agent          string
	Scope          string
	ExecutionID    string
	Namespace      string
	ServiceAccount string
	Pod            string
	Workflow       string
	Template       string
	// Deadline is when the Workflow's activeDeadlineSeconds runs out; zero
	// when it has none.
	Deadline time.Time
}

// BindingRefusedError is a token or pod that does not bind to an agent run.
// Reason is a short fixed code, safe to audit and to return.
type BindingRefusedError struct {
	Reason string
	// Unauthenticated: the token itself was refused, not its binding.
	Unauthenticated bool
}

func (e *BindingRefusedError) Error() string { return "agent run binding refused: " + e.Reason }

func refused(reason string) error { return &BindingRefusedError{Reason: reason} }

// AgentRunBinder verifies agent pods. Any error that is not a
// *BindingRefusedError means the cluster could not be read: an unknown, not
// a refusal.
type AgentRunBinder struct {
	client kubernetes.Interface
	dyn    dynamic.Interface

	// Audience the projected token must carry.
	Audience string
	// Namespace the agent pods run in.
	Namespace string
	// ServiceAccounts a pod may run as, by name within Namespace.
	ServiceAccounts map[string]bool
	// Templates maps a ClusterWorkflowTemplate name to its runs' agent.
	Templates map[string]AgentRunTemplate
}

// NewAgentRunBinder builds a binder on the in-cluster config (KUBECONFIG
// for local development).
func NewAgentRunBinder(audience, namespace string, serviceAccounts map[string]bool, templates map[string]AgentRunTemplate) (*AgentRunBinder, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("k8s agent run binder: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s agent run binder: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s agent run binder: %w", err)
	}
	return newAgentRunBinder(cs, dyn, audience, namespace, serviceAccounts, templates), nil
}

func newAgentRunBinder(cs kubernetes.Interface, dyn dynamic.Interface, audience, namespace string, serviceAccounts map[string]bool, templates map[string]AgentRunTemplate) *AgentRunBinder {
	return &AgentRunBinder{
		client: cs, dyn: dyn, Audience: audience, Namespace: namespace,
		ServiceAccounts: serviceAccounts, Templates: templates,
	}
}

// Bind verifies a projected ServiceAccount token and returns the agent run
// of the pod it was issued to.
func (b *AgentRunBinder) Bind(ctx context.Context, token string) (*AgentRunBinding, error) {
	if b.Audience == "" {
		// An audience-less review accepts the API server's own audience,
		// i.e. any ordinary pod token.
		return nil, errors.New("k8s agent run binder: no audience configured")
	}
	review, err := b.client.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{b.Audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s agent run binder: token review: %w", err)
	}
	st := review.Status
	// The API server answered: an unauthenticated token is a refusal.
	if !st.Authenticated {
		return nil, &BindingRefusedError{Reason: "token_not_authenticated", Unauthenticated: true}
	}
	if !contains(st.Audiences, b.Audience) {
		return nil, &BindingRefusedError{Reason: "token_audience", Unauthenticated: true}
	}
	ns, sa, ok := parseServiceAccount(st.User.Username)
	if !ok || ns != b.Namespace || !b.ServiceAccounts[sa] {
		return nil, refused("service_account_not_allowed")
	}
	podName, podUID := single(st.User.Extra[podNameExtra]), single(st.User.Extra[podUIDExtra])
	if podName == "" || podUID == "" {
		return nil, refused("token_not_pod_bound")
	}

	pod, err := b.client.CoreV1().Pods(ns).Get(ctx, podName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, refused("pod_not_found")
	}
	if err != nil {
		return nil, fmt.Errorf("k8s agent run binder: get pod: %w", err)
	}
	if string(pod.UID) != podUID {
		return nil, refused("pod_replaced")
	}
	if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return nil, refused("pod_not_running")
	}
	if pod.Spec.ServiceAccountName != sa {
		return nil, refused("pod_service_account")
	}
	wfName := pod.Labels[workflowLabel]
	if wfName == "" {
		return nil, refused("pod_not_in_workflow")
	}

	wf, err := b.dyn.Resource(workflowGVR).Namespace(ns).Get(ctx, wfName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, refused("workflow_not_found")
	}
	if err != nil {
		return nil, fmt.Errorf("k8s agent run binder: get workflow: %w", err)
	}
	// The label alone is the pod's own claim; the controller owner
	// reference ties it to this very Workflow object.
	if !ownedBy(pod.OwnerReferences, "Workflow", wfName, string(wf.GetUID())) {
		return nil, refused("pod_not_owned_by_workflow")
	}
	if phase, _, _ := unstructured.NestedString(wf.Object, "status", "phase"); phase != "Running" {
		return nil, refused("workflow_not_running")
	}
	tmplName, _, _ := unstructured.NestedString(wf.Object, "spec", "workflowTemplateRef", "name")
	clusterScope, _, _ := unstructured.NestedBool(wf.Object, "spec", "workflowTemplateRef", "clusterScope")
	tmpl, ok := b.Templates[tmplName]
	if !ok || !clusterScope {
		return nil, refused("workflow_template_not_allowed")
	}
	execID := workflowParam(wf, executionParam)
	if execID == "" {
		return nil, refused("workflow_without_execution")
	}

	return &AgentRunBinding{
		Agent: tmpl.Agent, Scope: tmpl.Scope, ExecutionID: execID,
		Namespace: ns, ServiceAccount: sa, Pod: podName, Workflow: wfName, Template: tmplName,
		Deadline: workflowDeadline(wf),
	}, nil
}

func parseServiceAccount(username string) (ns, name string, ok bool) {
	parts := strings.Split(username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func single(v authnv1.ExtraValue) string {
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func ownedBy(refs []metav1.OwnerReference, kind, name, uid string) bool {
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller && ref.Kind == kind && ref.Name == name && string(ref.UID) == uid && uid != "" {
			return true
		}
	}
	return false
}

// workflowParam returns a parameter the Workflow was submitted with. Only
// submitted arguments count: a template default is not a run's identity.
func workflowParam(wf *unstructured.Unstructured, name string) string {
	params, _, _ := unstructured.NestedSlice(wf.Object, "spec", "arguments", "parameters")
	for _, p := range params {
		m, ok := p.(map[string]any)
		if !ok || m["name"] != name {
			continue
		}
		v, _ := m["value"].(string)
		return strings.TrimSpace(v)
	}
	return ""
}

// workflowDeadline is startedAt + activeDeadlineSeconds, taken from the
// Workflow itself or, for a templated one, the stored template spec.
func workflowDeadline(wf *unstructured.Unstructured) time.Time {
	started, _, _ := unstructured.NestedString(wf.Object, "status", "startedAt")
	start, err := time.Parse(time.RFC3339, started)
	if err != nil {
		return time.Time{}
	}
	for _, path := range [][]string{
		{"spec", "activeDeadlineSeconds"},
		{"status", "storedWorkflowTemplateSpec", "activeDeadlineSeconds"},
	} {
		if secs, found, err := unstructured.NestedInt64(wf.Object, path...); err == nil && found && secs > 0 {
			return start.Add(time.Duration(secs) * time.Second)
		}
	}
	return time.Time{}
}
