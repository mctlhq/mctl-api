package k8s

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestListServicePods_MapsStatesAndHidesSecrets(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "acme-web-7c9d-xyz", Namespace: "acme",
			Labels: map[string]string{"app.kubernetes.io/instance": "acme-web"}},
		Spec: corev1.PodSpec{
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}},
			Volumes: []corev1.Volume{{Name: "v", VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: "volume-secret-name"}}}},
			Containers: []corev1.Container{{
				Name: "web", Image: "img:1",
				Env:     []corev1.EnvVar{{Name: "DB_PASSWORD_VAR", Value: "SECRET_VALUE_X"}},
				EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "envfrom-secret"}}}},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")},
				},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "web", RestartCount: 3,
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason: "CrashLoopBackOff", Message: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
					Reason: "OOMKilled", ExitCode: 137}},
			}},
		},
	}
	c := NewWorkloadClient(fake.NewSimpleClientset(pod))
	got, err := c.ListServicePods(context.Background(), "acme", "acme-web")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	ct := got[0].Containers[0]
	if ct.State.Reason != "CrashLoopBackOff" || ct.LastTermination.Reason != "OOMKilled" || *ct.LastTermination.ExitCode != 137 {
		t.Errorf("states not mapped: %+v", ct)
	}
	if ct.Limits["memory"] != "512Mi" || ct.RestartCount != 3 {
		t.Errorf("limits/restarts not mapped: %+v", ct)
	}
	if !strings.HasPrefix(ct.State.Message, "[redacted: ") {
		t.Errorf("message not redacted: %q", ct.State.Message)
	}
	b, _ := json.Marshal(got)
	for _, bad := range []string{"SECRET_VALUE_X", "DB_PASSWORD_VAR", "volume-secret-name", "envfrom-secret"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("response leaks %q: %s", bad, b)
		}
	}
	if !strings.Contains(string(b), "regcred") {
		t.Errorf("imagePullSecret name missing: %s", b)
	}
}

func TestListServicePods_NamePrefixFallback(t *testing.T) {
	mk := func(name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "acme"}}
	}
	sibling := mk("acme-web-worker-base-service-7c9d-xyz")
	sibling.Labels = map[string]string{instanceLabel: "acme-web-worker"}
	c := NewWorkloadClient(fake.NewSimpleClientset(mk("acme-web-abc"), mk("acme-webhook-abc"), sibling))
	got, err := c.ListServicePods(context.Background(), "acme", "acme-web")
	if err != nil || len(got) != 1 || got[0].Name != "acme-web-abc" {
		t.Fatalf("got %v, %v (a sibling release's labelled pod must not fall back in)", got, err)
	}
	empty, err := c.ListServicePods(context.Background(), "acme", "acme-none")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("want empty non-nil, got %v, %v", empty, err)
	}
}

func TestListEvents(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ev := func(name, obj, typ string, last metav1.Time, et metav1.MicroTime) *corev1.Event {
		return &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: name, Namespace: "acme"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: obj},
			Type:           typ, Reason: "R", Message: "m", LastTimestamp: last, EventTime: et,
		}
	}
	at := func(d time.Duration) metav1.Time { return metav1.NewTime(now.Add(-d)) }
	c := NewWorkloadClient(fake.NewSimpleClientset(
		ev("old", "acme-web-1", "Warning", at(3*time.Hour), metav1.MicroTime{}),
		ev("new", "acme-web-2", "Warning", at(5*time.Minute), metav1.MicroTime{}),
		ev("evt", "acme-web-3", "Normal", metav1.Time{}, metav1.NewMicroTime(now.Add(-20*time.Minute))),
		ev("hook", "acme-webhook-1", "Warning", at(time.Minute), metav1.MicroTime{}),
	))
	c.now = func() time.Time { return now }

	got, trunc, err := c.ListEvents(context.Background(), "acme", EventQuery{Since: time.Hour})
	if err != nil || trunc || len(got) != 3 {
		t.Fatalf("got %d trunc=%v err=%v", len(got), trunc, err)
	}
	if got[0].InvolvedName != "acme-webhook-1" || got[2].InvolvedName != "acme-web-3" {
		t.Errorf("order/fallback wrong: %+v", got)
	}
	// The handler passes the bare workload ("acme-web", no trailing dash):
	// its children and the workload object itself match, "acme-webhook-1"
	// does not.
	got, _, _ = c.ListEvents(context.Background(), "acme", EventQuery{Since: time.Hour, Workload: "acme-web"})
	if len(got) != 2 {
		t.Errorf("workload filter: %+v", got)
	}
	for _, e := range got {
		if e.InvolvedName == "acme-webhook-1" {
			t.Errorf("workload acme-web matched %q", e.InvolvedName)
		}
	}
	wc := NewWorkloadClient(fake.NewSimpleClientset(
		ev("dep", "acme-web", "Warning", at(time.Minute), metav1.MicroTime{}),
	))
	wc.now = func() time.Time { return now }
	if got, _, _ := wc.ListEvents(context.Background(), "acme", EventQuery{Since: time.Hour, Workload: "acme-web"}); len(got) != 1 {
		t.Errorf("event about the workload object itself dropped: %+v", got)
	}
	got, _, _ = c.ListEvents(context.Background(), "acme", EventQuery{Since: time.Hour, Type: "Normal"})
	if len(got) != 1 || got[0].InvolvedName != "acme-web-3" {
		t.Errorf("type filter: %+v", got)
	}
	got, trunc, _ = c.ListEvents(context.Background(), "acme", EventQuery{Since: time.Hour, Limit: 1})
	if len(got) != 1 || !trunc {
		t.Errorf("cap: %d %v", len(got), trunc)
	}
}

// A sibling release whose name extends the workload's ("acme-web-worker" for
// "acme-web") is found from pod instance labels, and its events are not
// reported as the workload's.
func TestListEvents_ExcludesSiblingRelease(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ev := func(name, obj string) *corev1.Event {
		return &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: name, Namespace: "acme"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: obj},
			Type:           "Warning", Reason: "R", Message: "m", LastTimestamp: metav1.NewTime(now.Add(-time.Minute)),
		}
	}
	pod := func(name, instance string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "acme", Labels: map[string]string{instanceLabel: instance}}}
	}
	c := NewWorkloadClient(fake.NewSimpleClientset(
		pod("acme-web-base-service-1-a", "acme-web"),
		pod("acme-web-worker-base-service-2-b", "acme-web-worker"),
		ev("own", "acme-web-base-service-1-a"),
		ev("dep", "acme-web-base-service"),
		ev("sib", "acme-web-worker-base-service-2-b"),
		ev("sibdep", "acme-web-worker-base-service"),
	))
	c.now = func() time.Time { return now }
	got, _, err := c.ListEvents(context.Background(), "acme", EventQuery{Since: time.Hour, Workload: "acme-web"})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range got {
		names[e.InvolvedName] = true
	}
	if len(got) != 2 || !names["acme-web-base-service-1-a"] || !names["acme-web-base-service"] {
		t.Errorf("got %v, want only acme-web's own objects", names)
	}
}
