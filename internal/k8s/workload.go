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

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/mctlhq/mctl-api/internal/secretscan"
)

// DefaultEventLimit caps the events returned by ListEvents.
const DefaultEventLimit = 200

// StateDetail is one container state. Kind is running, waiting or terminated.
type StateDetail struct {
	Kind       string     `json:"kind"`
	Reason     string     `json:"reason,omitempty"`
	Message    string     `json:"message,omitempty"`
	ExitCode   *int32     `json:"exit_code,omitempty"`
	Signal     *int32     `json:"signal,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ContainerState is the allow-listed view of one container of a pod.
type ContainerState struct {
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Ready           bool              `json:"ready"`
	RestartCount    int32             `json:"restart_count"`
	State           *StateDetail      `json:"state,omitempty"`
	LastTermination *StateDetail      `json:"last_termination,omitempty"`
	Requests        map[string]string `json:"requests,omitempty"`
	Limits          map[string]string `json:"limits,omitempty"`
}

// PodState is the allow-listed view of one pod. It is built field by field:
// env, envFrom, volumes, command and annotations are never copied.
type PodState struct {
	Name                 string           `json:"name"`
	Phase                string           `json:"phase"`
	Ready                bool             `json:"ready"`
	Reason               string           `json:"reason,omitempty"`
	Message              string           `json:"message,omitempty"`
	CreatedAt            time.Time        `json:"created_at"`
	StartedAt            *time.Time       `json:"started_at,omitempty"`
	ImagePullSecretNames []string         `json:"image_pull_secret_names,omitempty"`
	InitContainers       []ContainerState `json:"init_containers,omitempty"`
	Containers           []ContainerState `json:"containers"`
}

// Event is the allow-listed view of one Kubernetes event.
type Event struct {
	Type            string    `json:"type"`
	Reason          string    `json:"reason"`
	Message         string    `json:"message"`
	InvolvedKind    string    `json:"involved_kind"`
	InvolvedName    string    `json:"involved_name"`
	Count           int32     `json:"count"`
	FirstTimestamp  time.Time `json:"first_timestamp"`
	LastTimestamp   time.Time `json:"last_timestamp"`
	SourceComponent string    `json:"source_component,omitempty"`
}

// EventQuery selects events. Zero Since means no lower bound; zero Limit means
// DefaultEventLimit. NamePrefix keeps events whose involved object name starts
// with it.
type EventQuery struct {
	Since      time.Duration
	Type       string
	NamePrefix string
	Limit      int
}

// WorkloadClient reads pod state and events from a tenant namespace.
type WorkloadClient struct {
	client kubernetes.Interface
	now    func() time.Time
}

// NewWorkloadClient wraps a Kubernetes clientset.
func NewWorkloadClient(cs kubernetes.Interface) *WorkloadClient {
	return &WorkloadClient{client: cs, now: time.Now}
}

// NewWorkloadClientFromEnv creates a WorkloadClient using in-cluster config,
// falling back to KUBECONFIG.
func NewWorkloadClientFromEnv() (*WorkloadClient, error) {
	cs, err := newClientset()
	if err != nil {
		return nil, err
	}
	return NewWorkloadClient(cs), nil
}

// ListServicePods lists the pods of workload ({team}-{app}) in namespace. It
// selects by the app.kubernetes.io/instance label and falls back to the pod
// name prefix "<workload>-" when the label matches nothing.
func (c *WorkloadClient) ListServicePods(ctx context.Context, namespace, workload string) ([]PodState, error) {
	list, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/instance=" + workload,
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods in %s: %w", namespace, err)
	}
	pods := list.Items
	if len(pods) == 0 {
		all, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing pods in %s: %w", namespace, err)
		}
		for _, p := range all.Items {
			if strings.HasPrefix(p.Name, workload+"-") {
				pods = append(pods, p)
			}
		}
	}
	out := make([]PodState, 0, len(pods))
	for i := range pods {
		out = append(out, toPodState(&pods[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func toPodState(p *corev1.Pod) PodState {
	ps := PodState{
		Name:      p.Name,
		Phase:     string(p.Status.Phase),
		Reason:    p.Status.Reason,
		Message:   redactMessage(p.Status.Message),
		CreatedAt: p.CreationTimestamp.Time,
	}
	if p.Status.StartTime != nil {
		t := p.Status.StartTime.Time
		ps.StartedAt = &t
	}
	for _, cond := range p.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			ps.Ready = true
		}
	}
	for _, s := range p.Spec.ImagePullSecrets {
		ps.ImagePullSecretNames = append(ps.ImagePullSecretNames, s.Name)
	}
	ps.InitContainers = containerStates(p.Spec.InitContainers, p.Status.InitContainerStatuses)
	ps.Containers = containerStates(p.Spec.Containers, p.Status.ContainerStatuses)
	return ps
}

func containerStates(specs []corev1.Container, statuses []corev1.ContainerStatus) []ContainerState {
	byName := make(map[string]corev1.ContainerStatus, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}
	out := make([]ContainerState, 0, len(specs))
	for _, sp := range specs {
		cs := ContainerState{
			Name:     sp.Name,
			Image:    sp.Image,
			Requests: resourceListToStrings(sp.Resources.Requests),
			Limits:   resourceListToStrings(sp.Resources.Limits),
		}
		if len(cs.Requests) == 0 {
			cs.Requests = nil
		}
		if len(cs.Limits) == 0 {
			cs.Limits = nil
		}
		if st, ok := byName[sp.Name]; ok {
			cs.Ready = st.Ready
			cs.RestartCount = st.RestartCount
			if st.Image != "" {
				cs.Image = st.Image
			}
			cs.State = stateDetail(st.State)
			if st.LastTerminationState.Terminated != nil {
				cs.LastTermination = stateDetail(st.LastTerminationState)
			}
		}
		out = append(out, cs)
	}
	return out
}

func stateDetail(s corev1.ContainerState) *StateDetail {
	switch {
	case s.Running != nil:
		t := s.Running.StartedAt.Time
		return &StateDetail{Kind: "running", StartedAt: &t}
	case s.Waiting != nil:
		return &StateDetail{Kind: "waiting", Reason: s.Waiting.Reason, Message: redactMessage(s.Waiting.Message)}
	case s.Terminated != nil:
		t := s.Terminated
		exit := t.ExitCode
		d := &StateDetail{
			Kind:     "terminated",
			Reason:   t.Reason,
			Message:  redactMessage(t.Message),
			ExitCode: &exit,
		}
		if t.Signal != 0 {
			sig := t.Signal
			d.Signal = &sig
		}
		if !t.StartedAt.IsZero() {
			st := t.StartedAt.Time
			d.StartedAt = &st
		}
		if !t.FinishedAt.IsZero() {
			ft := t.FinishedAt.Time
			d.FinishedAt = &ft
		}
		return d
	}
	return nil
}

// redactMessage replaces a message that secretscan flags.
func redactMessage(msg string) string {
	if msg == "" {
		return msg
	}
	if pattern, found := secretscan.Scan([]byte(msg)); found {
		return "[redacted: " + pattern + "]"
	}
	return msg
}

// ListEvents lists events in namespace whose last-observed time is within
// q.Since, newest first, capped at q.Limit. truncated reports that the cap
// dropped events.
func (c *WorkloadClient) ListEvents(ctx context.Context, namespace string, q EventQuery) (events []Event, truncated bool, err error) {
	list, err := c.client.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, false, fmt.Errorf("listing events in %s: %w", namespace, err)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultEventLimit
	}
	var cutoff time.Time
	if q.Since > 0 {
		cutoff = c.now().Add(-q.Since)
	}
	events = []Event{}
	for i := range list.Items {
		e := &list.Items[i]
		last := eventLastSeen(e)
		if !cutoff.IsZero() && last.Before(cutoff) {
			continue
		}
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		if q.NamePrefix != "" && !strings.HasPrefix(e.InvolvedObject.Name, q.NamePrefix) {
			continue
		}
		first := e.FirstTimestamp.Time
		if first.IsZero() {
			first = last
		}
		src := e.Source.Component
		if src == "" {
			src = e.ReportingController
		}
		events = append(events, Event{
			Type:            e.Type,
			Reason:          e.Reason,
			Message:         redactMessage(e.Message),
			InvolvedKind:    e.InvolvedObject.Kind,
			InvolvedName:    e.InvolvedObject.Name,
			Count:           e.Count,
			FirstTimestamp:  first,
			LastTimestamp:   last,
			SourceComponent: src,
		})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].LastTimestamp.After(events[j].LastTimestamp) })
	if len(events) > limit {
		events = events[:limit]
		truncated = true
	}
	return events, truncated, nil
}

func eventLastSeen(e *corev1.Event) time.Time {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	return e.FirstTimestamp.Time
}
