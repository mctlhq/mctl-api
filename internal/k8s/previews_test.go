// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func dep(name, instance, managedBy string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "labs-preview",
		Labels: map[string]string{"app.kubernetes.io/instance": instance, "app.kubernetes.io/managed-by": managedBy},
	}}
}

func nsObj() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "labs-preview"}}
}

func TestListPreviewReleases(t *testing.T) {
	cs := fake.NewSimpleClientset(nsObj(),
		dep("a", "preview-psa-smoke-abc123", "Helm"),
		dep("b", "preview-labs-psa-smoke-abc123", "Helm"),
		dep("c", "preview-psa-smoke-zzz999", "Manual"),
		dep("d", "other", "Helm"),
	)
	c := NewPreviewClient(cs)
	got, err := c.ListPreviewReleases(context.Background(), "labs", "psa-smoke")
	if err != nil || len(got) != 1 || got[0].Service != "psa-smoke" || got[0].PreviewID != "abc123" {
		t.Fatalf("got %+v err %v", got, err)
	}
	all, err := c.ListPreviewReleases(context.Background(), "labs", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("all: %+v err %v", all, err)
	}
	none, err := c.ListPreviewReleases(context.Background(), "labs", "psa")
	if err != nil || len(none) != 0 || none == nil {
		t.Fatalf("psa: %+v err %v", none, err)
	}
}

func TestListPreviewReleasesErrors(t *testing.T) {
	list := func(err error) *fake.Clientset {
		cs := fake.NewSimpleClientset(nsObj())
		cs.PrependReactor("list", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, err })
		return cs
	}
	for _, e := range []error{
		apierrors.NewForbidden(schema.GroupResource{Resource: "deployments"}, "", errors.New("no")),
		errors.New("boom"),
	} {
		got, err := NewPreviewClient(list(e)).ListPreviewReleases(context.Background(), "labs", "")
		if err == nil || got != nil || errors.Is(err, ErrNamespaceAbsent) {
			t.Fatalf("want plain error, got %v %v", got, err)
		}
	}
	// Empty list, namespace absent.
	_, err := NewPreviewClient(fake.NewSimpleClientset()).ListPreviewReleases(context.Background(), "labs", "")
	if !errors.Is(err, ErrNamespaceAbsent) {
		t.Fatalf("want absent, got %v", err)
	}
	// Empty list, namespace get fails.
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("boom") })
	_, err = NewPreviewClient(cs).ListPreviewReleases(context.Background(), "labs", "")
	if err == nil || errors.Is(err, ErrNamespaceAbsent) {
		t.Fatalf("want error, got %v", err)
	}
	// Empty list, namespace present.
	got, err := NewPreviewClient(fake.NewSimpleClientset(nsObj())).ListPreviewReleases(context.Background(), "labs", "")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestParsePreviewRelease(t *testing.T) {
	cases := []struct {
		in, svc, id string
		ok          bool
	}{
		{"preview-psa-smoke-abc123", "psa-smoke", "abc123", true},
		{"preview-api-x1", "api", "x1", true},
		{"psa-abc123", "", "", false},
		{"preview--abc123", "", "", false},
		{"preview-api-abcdefg", "", "", false},
		{"preview-api-ABC", "", "", false},
		{"preview-api", "", "", false},
	}
	for _, tc := range cases {
		svc, id, ok := ParsePreviewRelease(tc.in)
		if svc != tc.svc || id != tc.id || ok != tc.ok {
			t.Errorf("%s: got %q %q %v", tc.in, svc, id, ok)
		}
	}
}
