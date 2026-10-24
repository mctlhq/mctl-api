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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ErrNamespaceAbsent is returned only for an observed NotFound on the preview namespace.
var ErrNamespaceAbsent = errors.New("preview namespace absent")

var previewIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// PreviewRelease is one preview Helm release observed through its Deployment.
type PreviewRelease struct {
	Release           string    `json:"release"`
	Service           string    `json:"service"`
	PreviewID         string    `json:"preview_id"`
	Namespace         string    `json:"namespace"`
	Replicas          int32     `json:"replicas"`
	ReadyReplicas     int32     `json:"ready_replicas"`
	AvailableReplicas int32     `json:"available_replicas"`
	CreatedAt         time.Time `json:"created_at"`
}

// PreviewClient lists preview Helm releases in a team's preview namespace.
type PreviewClient struct {
	client kubernetes.Interface
}

// NewPreviewClient wraps a Kubernetes clientset.
func NewPreviewClient(cs kubernetes.Interface) *PreviewClient {
	return &PreviewClient{client: cs}
}

// ParsePreviewRelease splits "preview-<service>-<id>" on the last hyphen.
func ParsePreviewRelease(release string) (service, id string, ok bool) {
	rest, found := strings.CutPrefix(release, "preview-")
	if !found {
		return "", "", false
	}
	i := strings.LastIndex(rest, "-")
	if i <= 0 {
		return "", "", false
	}
	service, id = rest[:i], rest[i+1:]
	if !previewIDPattern.MatchString(id) {
		return "", "", false
	}
	return service, id, true
}

// ListPreviewReleases lists preview releases in {team}-preview. Every API
// failure is an error; only an observed namespace NotFound yields
// ErrNamespaceAbsent.
func (c *PreviewClient) ListPreviewReleases(ctx context.Context, team, service string) ([]PreviewRelease, error) {
	ns := team + "-preview"
	list, err := c.client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=Helm",
	})
	if err != nil {
		return nil, fmt.Errorf("listing preview deployments in %s: %w", ns, err)
	}
	byRelease := map[string]PreviewRelease{}
	for i := range list.Items {
		d := &list.Items[i]
		rel := d.Labels["app.kubernetes.io/instance"]
		if !strings.HasPrefix(rel, "preview-") {
			continue
		}
		// Releases that do not parse are still reported (empty service/id)
		// when unfiltered, so a running preview is never silently dropped.
		svc, id, ok := ParsePreviewRelease(rel)
		if service != "" && (!ok || svc != service) {
			continue
		}
		if !ok {
			svc, id = "", ""
		}
		if _, dup := byRelease[rel]; dup {
			continue
		}
		var replicas int32
		if d.Spec.Replicas != nil {
			replicas = *d.Spec.Replicas
		}
		byRelease[rel] = PreviewRelease{
			Release:           rel,
			Service:           svc,
			PreviewID:         id,
			Namespace:         ns,
			Replicas:          replicas,
			ReadyReplicas:     d.Status.ReadyReplicas,
			AvailableReplicas: d.Status.AvailableReplicas,
			CreatedAt:         d.CreationTimestamp.Time,
		}
	}
	out := make([]PreviewRelease, 0, len(byRelease))
	for _, r := range byRelease {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Release < out[j].Release })
	if len(out) > 0 {
		return out, nil
	}
	// An empty list is ambiguous; confirm the namespace exists.
	if _, err := c.client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrNamespaceAbsent
		}
		return nil, fmt.Errorf("checking preview namespace %s: %w", ns, err)
	}
	return out, nil
}
