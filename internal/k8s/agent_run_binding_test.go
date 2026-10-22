package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	testAudience = "mctl-api-agent-run"
	testNS       = "argo-workflows"
	testSA       = "mctl-agents-runner"
	testPod      = "inv-abc-run-investigator-1"
	testPodUID   = "pod-uid-1"
	testWF       = "inv-abc"
	testWFUID    = "wf-uid-1"
)

// bindFixture is a converged cluster: a running investigate pod of a
// running Workflow, and a TokenReview that authenticates its token.
type bindFixture struct {
	status   authnv1.TokenReviewStatus
	pod      *corev1.Pod
	wf       *unstructured.Unstructured
	podErr   error
	reviewed []string
}

func newBindFixture() *bindFixture {
	yes := true
	return &bindFixture{
		status: authnv1.TokenReviewStatus{
			Authenticated: true,
			Audiences:     []string{testAudience},
			User: authnv1.UserInfo{
				Username: "system:serviceaccount:" + testNS + ":" + testSA,
				Extra: map[string]authnv1.ExtraValue{
					podNameExtra: {testPod},
					podUIDExtra:  {testPodUID},
				},
			},
		},
		pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: testPod, Namespace: testNS, UID: types.UID(testPodUID),
				Labels: map[string]string{workflowLabel: testWF},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "argoproj.io/v1alpha1", Kind: "Workflow", Name: testWF, UID: types.UID(testWFUID), Controller: &yes,
				}},
			},
			Spec:   corev1.PodSpec{ServiceAccountName: testSA},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		wf: &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "argoproj.io/v1alpha1",
			"kind":       "Workflow",
			"metadata":   map[string]any{"name": testWF, "namespace": testNS, "uid": testWFUID},
			"spec": map[string]any{
				"workflowTemplateRef": map[string]any{"name": "mctl-agents-investigate", "clusterScope": true},
				"arguments": map[string]any{"parameters": []any{
					map[string]any{"name": "issue_url", "value": "https://github.com/o/r/issues/1"},
					map[string]any{"name": "execution_id", "value": "we_run1"},
				}},
			},
			"status": map[string]any{
				"phase":                      "Running",
				"startedAt":                  "2026-10-22T10:00:00Z",
				"storedWorkflowTemplateSpec": map[string]any{"activeDeadlineSeconds": int64(7200)},
			},
		}},
	}
}

func (f *bindFixture) binder() *AgentRunBinder {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		tr := a.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		f.reviewed = append(f.reviewed, tr.Spec.Audiences...)
		return true, &authnv1.TokenReview{Spec: tr.Spec, Status: f.status}, nil
	})
	if f.pod != nil {
		_ = cs.Tracker().Add(f.pod)
	}
	if f.podErr != nil {
		cs.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, f.podErr
		})
	}
	scheme := runtime.NewScheme()
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{workflowGVR: "WorkflowList"})
	if f.wf != nil {
		_, _ = dyn.Resource(workflowGVR).Namespace(testNS).Create(context.Background(), f.wf, metav1.CreateOptions{})
	}
	return newAgentRunBinder(cs, dyn, testAudience, testNS, map[string]bool{testSA: true},
		map[string]AgentRunTemplate{"mctl-agents-investigate": {Agent: "issue-investigator", Scope: "investigate"}})
}

func TestAgentRunBinder_BindsARunningInvestigatePod(t *testing.T) {
	f := newBindFixture()
	got, err := f.binder().Bind(context.Background(), "sa-token")
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if got.Agent != "issue-investigator" || got.Scope != "investigate" || got.ExecutionID != "we_run1" ||
		got.Pod != testPod || got.Workflow != testWF || got.ServiceAccount != testSA {
		t.Errorf("binding = %+v", got)
	}
	if want := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC); !got.Deadline.Equal(want) {
		t.Errorf("deadline = %v, want %v", got.Deadline, want)
	}
	if len(f.reviewed) != 1 || f.reviewed[0] != testAudience {
		t.Errorf("token reviewed for audiences %v, want [%s]", f.reviewed, testAudience)
	}
}

func TestAgentRunBinder_RefusesWhatDoesNotBind(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*bindFixture)
		reason string
	}{
		{"unauthenticated", func(f *bindFixture) { f.status.Authenticated = false }, "token_not_authenticated"},
		{"other audience", func(f *bindFixture) { f.status.Audiences = []string{"https://kubernetes.default.svc"} }, "token_audience"},
		{"other service account", func(f *bindFixture) {
			f.status.User.Username = "system:serviceaccount:" + testNS + ":argo-workflow-sa"
		}, "service_account_not_allowed"},
		{"other namespace", func(f *bindFixture) {
			f.status.User.Username = "system:serviceaccount:tenant-a:" + testSA
		}, "service_account_not_allowed"},
		{"not a service account", func(f *bindFixture) { f.status.User.Username = "alice" }, "service_account_not_allowed"},
		{"token not bound to a pod", func(f *bindFixture) { delete(f.status.User.Extra, podUIDExtra) }, "token_not_pod_bound"},
		{"pod gone", func(f *bindFixture) { f.pod = nil }, "pod_not_found"},
		{"pod replaced", func(f *bindFixture) { f.pod.UID = "pod-uid-2" }, "pod_replaced"},
		{"pod finished", func(f *bindFixture) { f.pod.Status.Phase = corev1.PodSucceeded }, "pod_not_running"},
		{"pod runs as another account", func(f *bindFixture) { f.pod.Spec.ServiceAccountName = "other" }, "pod_service_account"},
		{"pod outside a workflow", func(f *bindFixture) { delete(f.pod.Labels, workflowLabel) }, "pod_not_in_workflow"},
		{"workflow gone", func(f *bindFixture) { f.wf = nil }, "workflow_not_found"},
		{"label without owner", func(f *bindFixture) { f.pod.OwnerReferences = nil }, "pod_not_owned_by_workflow"},
		{"owner is another object", func(f *bindFixture) { f.pod.OwnerReferences[0].UID = "wf-uid-old" }, "pod_not_owned_by_workflow"},
		{"owner is a Workflow of another API group", func(f *bindFixture) {
			f.pod.OwnerReferences[0].APIVersion = "example.com/v1"
		}, "pod_not_owned_by_workflow"},
		{"workflow finished", func(f *bindFixture) {
			_ = unstructured.SetNestedField(f.wf.Object, "Failed", "status", "phase")
		}, "workflow_not_running"},
		{"other template", func(f *bindFixture) {
			_ = unstructured.SetNestedField(f.wf.Object, "mctl-agents-implement", "spec", "workflowTemplateRef", "name")
		}, "workflow_template_not_allowed"},
		{"namespaced template of the same name", func(f *bindFixture) {
			_ = unstructured.SetNestedField(f.wf.Object, false, "spec", "workflowTemplateRef", "clusterScope")
		}, "workflow_template_not_allowed"},
		{"no execution", func(f *bindFixture) {
			_ = unstructured.SetNestedSlice(f.wf.Object, []any{map[string]any{"name": "execution_id", "value": ""}}, "spec", "arguments", "parameters")
		}, "workflow_without_execution"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newBindFixture()
			c.mutate(f)
			got, err := f.binder().Bind(context.Background(), "sa-token")
			var refusal *BindingRefusedError
			if !errors.As(err, &refusal) {
				t.Fatalf("Bind = %+v, %v; want refusal %s", got, err, c.reason)
			}
			if refusal.Reason != c.reason {
				t.Errorf("reason = %s, want %s", refusal.Reason, c.reason)
			}
		})
	}
}

// A cluster that cannot be read is an unknown, never a refusal and never a
// binding.
func TestAgentRunBinder_UnreadableClusterIsNotARefusal(t *testing.T) {
	f := newBindFixture()
	f.podErr = errors.New("connection refused")
	got, err := f.binder().Bind(context.Background(), "sa-token")
	var refusal *BindingRefusedError
	if err == nil || errors.As(err, &refusal) || got != nil {
		t.Fatalf("Bind = %+v, %v; want an unknown error", got, err)
	}
}

func TestAgentRunBinder_RequiresAnAudience(t *testing.T) {
	b := newBindFixture().binder()
	b.Audience = ""
	if _, err := b.Bind(context.Background(), "sa-token"); err == nil {
		t.Fatal("an audience-less binder bound a token")
	}
	for aud := range apiServerAudiences {
		// The review would accept it: any pod token carries this audience.
		f := newBindFixture()
		f.status.Audiences = []string{aud}
		b := f.binder()
		b.Audience = aud
		if _, err := b.Bind(context.Background(), "sa-token"); err == nil {
			t.Fatalf("a binder on the API server's audience %q bound a token", aud)
		}
		if _, err := NewAgentRunBinder(aud, "argo-workflows", nil, nil); err == nil || !strings.Contains(err.Error(), "API server's own") {
			t.Fatalf("NewAgentRunBinder(%q) = %v, want the audience refused", aud, err)
		}
	}
}
