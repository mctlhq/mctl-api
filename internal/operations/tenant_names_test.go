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
	"sort"
	"strings"
	"testing"
)

func TestIsReservedTenantName(t *testing.T) {
	var exact []string
	for n := range reservedTenantNames {
		exact = append(exact, n)
	}
	sort.Strings(exact)
	if len(exact) != 23 {
		t.Fatalf("expected 23 exact names, got %d", len(exact))
	}
	for _, n := range exact {
		if !IsReservedTenantName(n) {
			t.Errorf("%q should be reserved", n)
		}
	}
	for _, n := range []string{"kube-system-team", "kube-foo", "argo", "argonaut", "argocd-x", "billing-system", "platform-x", "mctl-foo", "grafana-x", "vault2", "vaultwarden"} {
		if !IsReservedTenantName(n) {
			t.Errorf("%q should be reserved (glob)", n)
		}
	}
	// Exact names do not imply prefixes: defaults and monitoring-team are fine.
	for _, n := range []string{"billing", "team-kube", "my-argo", "system-team", "systems", "mykube-system2", "defaults", "monitoring-team", "team-vault"} {
		if IsReservedTenantName(n) {
			t.Errorf("%q should be accepted", n)
		}
	}
}

func TestValidateInputRejectsReservedTenantName(t *testing.T) {
	reg := NewRegistry()
	op, ok := reg.Get("create-tenant")
	if !ok {
		t.Fatal("create-tenant missing")
	}
	for n := range reservedTenantNames {
		errs := reg.ValidateInput(op, map[string]string{"tenant_name": n})
		if !strings.Contains(strings.Join(errs, ";"), "is reserved") {
			t.Errorf("%q: expected reserved error, got %v", n, errs)
		}
	}
	if errs := reg.ValidateInput(op, map[string]string{"tenant_name": "billing"}); len(errs) != 0 {
		t.Errorf("billing: unexpected errors %v", errs)
	}
	del, ok := reg.Get("delete-tenant")
	if !ok {
		t.Fatal("delete-tenant missing")
	}
	errs := reg.ValidateInput(del, map[string]string{"tenant_name": "kube-system"})
	if strings.Contains(strings.Join(errs, ";"), "reserved") {
		t.Errorf("delete-tenant must not apply the check: %v", errs)
	}
}

func TestSubmitRejectsReservedTenantName(t *testing.T) {
	op, _ := NewRegistry().Get("create-tenant")
	_, err := (&Executor{}).Submit(context.Background(), op, map[string]string{"tenant_name": "kube-system"}, "u", "kube-system")
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved error, got %v", err)
	}
}
