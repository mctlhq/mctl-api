// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package operations

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// reservedCases is the contract with tenant_name_reserved in
// mctl-gitops wft-create-tenant.yaml (mctl-gitops#1770). Each row is a name
// and whether the gitops `case` statement matches it.
//
// Look-alike rule, as the gitops check applies it: a wildcard matches only at
// the end it is written on. "kube-*", "argo*", "platform-*", "mctl-*",
// "grafana-*" and "vault*" are PREFIX rules; "*-system" is a SUFFIX rule.
// Anything else that merely contains or resembles a reserved word is allowed.
var reservedCases = []struct {
	name     string
	reserved bool
	why      string
}{
	// Every exact name in the gitops list.
	{"argocd", true, "exact"},
	{"argo-workflows", true, "exact"},
	{"argo-events", true, "exact"},
	{"kube-system", true, "exact"},
	{"kube-public", true, "exact"},
	{"kube-node-lease", true, "exact"},
	{"default", true, "exact"},
	{"cert-manager", true, "exact"},
	{"traefik", true, "exact"},
	{"vault", true, "exact"},
	{"external-secrets", true, "exact"},
	{"monitoring", true, "exact"},
	{"temporal", true, "exact"},
	{"backstage", true, "exact"},
	{"minio", true, "exact"},
	{"database", true, "exact"},
	{"forgejo", true, "exact"},
	{"zitadel", true, "exact"},
	{"local-path-storage", true, "exact"},
	{"system-upgrade", true, "exact"},
	{"observability-eval", true, "exact"},

	// Prefix patterns.
	{"kube-system-team", true, "prefix kube-"},
	{"kube-anything", true, "prefix kube-"},
	{"argo", true, "prefix argo (no hyphen)"},
	{"argonaut", true, "prefix argo (no hyphen)"},
	{"argo-rollouts", true, "prefix argo"},
	{"platform-team", true, "prefix platform-"},
	{"mctl-labs", true, "prefix mctl-"},
	{"grafana-oncall", true, "prefix grafana-"},
	{"vault2", true, "prefix vault (no hyphen)"},
	{"vault-backup", true, "prefix vault"},

	// Suffix pattern.
	{"my-system", true, "suffix -system"},
	{"ingress-system", true, "suffix -system"},

	// Case variants never get past this layer.
	{"Kube-System", true, "case-insensitive"},
	{"ARGOCD", true, "case-insensitive"},

	// Platform Argo CD Application names and their hyphen-prefixes: a tenant
	// with one of these names could spell the Application as
	// <tenant>-<service>.
	{"root", true, "platform app root-app"},
	{"root-app", true, "platform app root-app"},
	{"shared", true, "platform app shared-pg"},
	{"shared-pg", true, "platform app shared-pg"},
	{"cloudnative", true, "platform app cloudnative-pg"},
	{"external", true, "platform app external-secrets"},
	{"grafana", true, "platform app grafana-iac"},
	{"loki", true, "platform app loki-stack"},
	{"otel", true, "platform app otel-collector"},
	{"otel-eval", true, "platform app otel-eval-tempo"},
	{"otel-anything", true, "prefix otel-"},
	{"reflector", true, "platform app reflector"},
	{"valkey", true, "platform app valkey"},
	{"temporal-web", true, "platform app temporal-web"},
	{"tenant", true, "tenants ApplicationSet"},
	{"tenant-x", true, "prefix tenant-"},
	{"sync", true, "argocd Role argo-workflow-argocd-sync"},
	{"SYNC", true, "case-insensitive"},

	// The existing tenants stay valid: none of them is a hyphen-prefix of a
	// platform Application in platformApplicationNames.
	{"admins", false, "existing tenant"},
	{"erpact", false, "existing tenant"},
	{"karabu", false, "existing tenant"},
	{"labs", false, "existing tenant"},
	{"mctl", false, "existing tenant"},
	{"ovk", false, "existing tenant"},

	// Allowed: no pattern matches, including near-misses on the boundaries.
	{"billing", false, "normal"},
	{"data-team", false, "normal"},
	{"acme", false, "normal"},
	{"team-kube", false, "kube- is a prefix rule only"},
	{"kube", false, "kube- needs the hyphen"},
	{"kubernetes", false, "kube- needs the hyphen"},
	{"team-argo", false, "argo is a prefix rule only"},
	{"my-platform", false, "platform- is a prefix rule only"},
	{"platform", false, "platform- needs the hyphen"},
	{"mctlhq", false, "mctl- needs the hyphen"},
	{"team-vault", false, "vault is a prefix rule only"},
	{"system", false, "-system needs the hyphen"},
	{"systems", false, "suffix -system must end the name"},
	{"system-team", false, "-system is a suffix rule only"},
	{"my-system-team", false, "-system is a suffix rule only"},
	{"defaults", false, "exact match only"},
	{"default-team", false, "exact match only"},
	{"monitoring-team", false, "exact match only"},
	{"my-monitoring", false, "exact match only"},
	{"minio2", false, "exact match only"},
	{"temporal-labs", false, "exact match only"},
	{"rooted", false, "root-app needs root followed by a hyphen"},
	{"sharedteam", false, "shared-pg needs shared followed by a hyphen"},
	{"team-root", false, "platform-app rule is a prefix rule only"},
	{"tenants", false, "tenant- needs the hyphen"},
	{"syncer", false, "sync is an exact match only"},
	{"data-sync", false, "sync is an exact match only"},
}

func TestIsReservedTenantName(t *testing.T) {
	for _, tc := range reservedCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsReservedTenantName(tc.name); got != tc.reserved {
				t.Errorf("IsReservedTenantName(%q) = %v, want %v (%s)", tc.name, got, tc.reserved, tc.why)
			}
		})
	}
}

// Every exact name in the table above must be in the set, and the set must
// not hold anything the table does not cover: a name added to one list and
// not the other fails here.
func TestReservedTenantNamesAreAllCovered(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range reservedCases {
		if tc.reserved && tc.why == "exact" {
			covered[tc.name] = true
		}
	}
	for name := range reservedTenantNames {
		if !covered[name] {
			t.Errorf("reservedTenantNames has %q, reservedCases does not test it", name)
		}
	}
	for name := range covered {
		if _, ok := reservedTenantNames[name]; !ok {
			t.Errorf("reservedCases expects %q reserved, reservedTenantNames lacks it", name)
		}
	}
}

// ValidateInput is what the REST handler (and through it the MCP tool) calls.
func TestValidateInputCreateTenantRejectsReserved(t *testing.T) {
	reg := NewRegistry()
	op, ok := reg.Get("create-tenant")
	if !ok {
		t.Fatal("create-tenant not in registry")
	}
	for _, tc := range reservedCases {
		// Skip spellings the format pattern already refuses (upper case);
		// those are covered by TestIsReservedTenantName and the Submit test.
		if tc.name != strings.ToLower(tc.name) {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			errs := reg.ValidateInput(op, reg.ApplyDefaults(op, map[string]string{"tenant_name": tc.name}))
			var reserved bool
			for _, e := range errs {
				if strings.Contains(e, "reserved") {
					reserved = true
				}
			}
			if reserved != tc.reserved {
				t.Errorf("tenant_name %q: reserved error = %v, want %v (errors: %v)", tc.name, reserved, tc.reserved, errs)
			}
			if !tc.reserved && len(errs) != 0 {
				t.Errorf("tenant_name %q should validate cleanly, got %v", tc.name, errs)
			}
		})
	}
}

// The check is create-tenant's alone: other operations that carry a
// tenant_name (delete, skill bindings) must keep working on existing tenants
// whose names are on the list.
func TestReservedNamesStillValidForOtherOperations(t *testing.T) {
	reg := NewRegistry()
	op, ok := reg.Get("delete-tenant")
	if !ok {
		t.Fatal("delete-tenant not in registry")
	}
	if errs := reg.ValidateInput(op, map[string]string{"tenant_name": "mctl-labs"}); len(errs) != 0 {
		t.Errorf("delete-tenant must not apply the create-time reserved check: %v", errs)
	}
}

// Submit is the lower-level entry point other code can call directly; it must
// refuse a reserved name without relying on ValidateInput having run.
func TestSubmitCreateTenantRejectsReserved(t *testing.T) {
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{workflowGVR: "WorkflowList"})
	e := &Executor{dynamicClient: dyn}
	reg := NewRegistry()
	op, _ := reg.Get("create-tenant")

	for _, tc := range reservedCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := e.Submit(context.Background(), op, map[string]string{"tenant_name": tc.name}, "u", tc.name)
			if tc.reserved {
				if !errors.Is(err, ErrReservedTenantName) {
					t.Fatalf("Submit(%q) err = %v, want ErrReservedTenantName", tc.name, err)
				}
				if res != nil {
					t.Errorf("Submit(%q) returned a result for a reserved name", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("Submit(%q) unexpected error: %v", tc.name, err)
			}
		})
	}

	// Nothing reserved was created: only the accepted names produced workflows.
	list, err := dyn.Resource(workflowGVR).Namespace("argo-workflows").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, tc := range reservedCases {
		if !tc.reserved {
			want++
		}
	}
	if len(list.Items) != want {
		t.Errorf("%d workflows created, want %d (one per allowed name, none for reserved)", len(list.Items), want)
	}
}

// Keyed on the workflow template too: an Operation value that carries the
// create-tenant template under another name is still checked.
func TestSubmitChecksByWorkflowTemplate(t *testing.T) {
	e := &Executor{}
	op := Operation{Name: "renamed", WorkflowTemplate: "create-tenant"}
	_, err := e.Submit(context.Background(), op, map[string]string{"tenant_name": "kube-system"}, "u", "kube-system")
	if !errors.Is(err, ErrReservedTenantName) {
		t.Fatalf("err = %v, want ErrReservedTenantName", err)
	}
}

// A missing tenant_name is not "reserved"; ValidateInput reports it as
// missing and Submit leaves other operations alone.
func TestSubmitOtherOperationsUnaffected(t *testing.T) {
	e := &Executor{}
	op := Operation{Name: "deploy-service", WorkflowTemplate: "deploy-service"}
	_, err := e.Submit(context.Background(), op, map[string]string{"tenant_name": "kube-system"}, "u", "team")
	if errors.Is(err, ErrReservedTenantName) {
		t.Fatalf("deploy-service must not apply the create-tenant check: %v", err)
	}
}

// An oversized name is not reflected in full: the reserved check runs
// independently of the length pattern.
func TestReservedTenantNameMessageIsBounded(t *testing.T) {
	long := "mctl-" + strings.Repeat("a", 100000)
	msg := reservedTenantNameMessage(long)
	if len(msg) > 200 {
		t.Errorf("message is %d bytes; the caller's name must be truncated", len(msg))
	}
	if !strings.Contains(msg, "reserved") {
		t.Errorf("message = %q", msg)
	}
	err := checkCreateTenantName(Operation{Name: "create-tenant"}, map[string]string{"tenant_name": long})
	if !errors.Is(err, ErrReservedTenantName) || len(err.Error()) > 200 {
		t.Errorf("err = %v", err)
	}
}
