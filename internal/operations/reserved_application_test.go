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
)

// existingTenants are the tenants in platform-gitops/tenants on 2026-10-11.
var existingTenants = []string{"admins", "erpact", "karabu", "labs", "mctl", "ovk"}

// liveApplications is `kubectl get applications -n argocd -o name` on
// 2026-10-11, the input platformApplicationNames was derived from.
var liveApplications = []string{
	"admins-mctl-agent", "admins-mctl-agents-worker", "admins-mctl-agents-worker-exec",
	"admins-mctl-agents-worker-implement", "admins-mctl-api", "admins-mctl-design",
	"admins-mctl-docs", "admins-mctl-portal", "admins-mctl-web", "argo-rollouts",
	"argo-workflows", "argo-workflows-config", "argocd-self-managed", "cloudnative-pg",
	"erpact-control", "erpact-deployer", "erpact-infra", "erpact-oidc-zitadel",
	"erpact-shared", "external-secrets", "forgejo", "grafana-iac",
	"karabu-draw-with-friends", "labs-agent-worker-preview", "labs-claude-remote",
	"labs-coolify-mcp", "labs-genai-leader", "labs-instruments-proxy", "labs-kuptsi-app",
	"labs-mctl-academy", "labs-mctl-alice", "labs-mctl-loyalty", "labs-mctl-pairdesk",
	"labs-mctl-telegram", "labs-mctl-telegram-preview", "labs-oidc-zitadel",
	"labs-payment-llm-pipelines", "labs-pelican-proxy", "labs-pelican-proxy-staging",
	"labs-pfeifenpatenschaft-backend", "labs-portfolio", "labs-projects-mcp",
	"labs-seerrsense", "loki-stack", "mctl-portal-oidc-zitadel", "minio", "monitoring",
	"otel-collector", "otel-eval-tempo", "ovk-mctl-academy", "reflector", "root-app",
	"shared-pg", "temporal", "temporal-web", "tenant-admins", "tenant-erpact",
	"tenant-karabu", "tenant-labs", "tenant-mctl", "tenant-ovk", "valkey", "vault",
	"vault-human-auth-iac", "zitadel",
}

// tenantServices are the platform-gitops/services/<tenant>/<service>
// directories on 2026-10-11: the apps ApplicationSet's Applications.
var tenantServices = map[string]bool{
	"admins-mctl-agents-worker": true, "admins-mctl-agents-worker-exec": true,
	"admins-mctl-agents-worker-implement": true, "admins-mctl-design": true,
	"admins-mctl-docs": true, "admins-mctl-web": true, "karabu-draw-with-friends": true,
	"labs-agent-worker-preview": true, "labs-claude-remote": true, "labs-coolify-mcp": true,
	"labs-genai-leader": true, "labs-instruments-proxy": true, "labs-kuptsi-app": true,
	"labs-mctl-academy": true, "labs-mctl-alice": true, "labs-mctl-loyalty": true,
	"labs-mctl-pairdesk": true, "labs-mctl-telegram": true, "labs-mctl-telegram-preview": true,
	"labs-payment-llm-pipelines": true, "labs-pelican-proxy": true,
	"labs-pelican-proxy-staging": true, "labs-pfeifenpatenschaft-backend": true,
	"labs-portfolio": true, "labs-projects-mcp": true, "labs-seerrsense": true,
	"ovk-mctl-academy": true,
}

func hyphenPrefixes(name string) []string {
	var out []string
	for i := range name {
		if name[i] == '-' {
			out = append(out, name[:i])
		}
	}
	return append(out, name)
}

// Every live Application that is not a tenant's own service or tenant
// Application is protected: either no new tenant can take any hyphen-prefix
// of its name, or it sits under an existing tenant and no service may be
// named so that <tenant>-<service> spells it. An Application added to the
// cluster without updating the lists fails here once added to the snapshot.
func TestLiveApplicationsAreProtected(t *testing.T) {
	isTenant := map[string]bool{}
	for _, tn := range existingTenants {
		isTenant[tn] = true
	}
	for _, app := range liveApplications {
		if tenantServices[app] || strings.HasPrefix(app, "tenant-") && isTenant[strings.TrimPrefix(app, "tenant-")] {
			continue
		}
		owner := ""
		for _, tn := range existingTenants {
			if strings.HasPrefix(app, tn+"-") {
				owner = tn
			}
		}
		if owner != "" {
			if !IsReservedServiceApplication(owner, strings.TrimPrefix(app, owner+"-")) {
				t.Errorf("%s: under tenant %q but %q is not a reserved service name", app, owner, strings.TrimPrefix(app, owner+"-"))
			}
			continue
		}
		for _, p := range hyphenPrefixes(app) {
			if !IsReservedTenantName(p) {
				t.Errorf("%s: tenant name %q is not reserved", app, p)
			}
		}
	}
	// The generated tenant Applications: "tenant" cannot be a tenant.
	if !IsReservedTenantName("tenant") {
		t.Error(`"tenant" must be reserved`)
	}
}

func TestExistingTenantsRemainValid(t *testing.T) {
	for _, tn := range existingTenants {
		if IsReservedTenantName(tn) {
			t.Errorf("existing tenant %q became reserved", tn)
		}
		if other, ok := TenantNameCollision(tn, existingTenants); ok {
			t.Errorf("existing tenant %q collides with %q", tn, other)
		}
	}
	// And every service they run today stays addressable.
	for app := range tenantServices {
		team, comp, _ := strings.Cut(app, "-")
		if IsReservedServiceApplication(team, comp) {
			t.Errorf("existing service %s/%s became reserved", team, comp)
		}
	}
}

func TestIsReservedServiceApplication(t *testing.T) {
	cases := []struct {
		team, component string
		want            bool
	}{
		{"root", "app", true},
		{"shared", "pg", true},
		{"argo", "workflows", true},
		{"vault", "human-auth-iac", true},
		{"tenant", "labs", true},
		{"tenant", "anything", true},
		{"labs", "oidc-zitadel", true},
		{"erpact", "control", true},
		{"erpact", "shared", true},
		{"admins", "mctl-api", true},
		{"mctl", "portal-oidc-zitadel", true},
		{"labs", "openclaw-skills", true},
		{"Root", "App", true},
		{"labs", "mctl-telegram", false},
		{"erpact", "web", false},
		{"admins", "mctl-web", false},
		{"labs", "oidc", false},
		{"acme", "app", false},
		{"", "app", false},
	}
	for _, tc := range cases {
		if got := IsReservedServiceApplication(tc.team, tc.component); got != tc.want {
			t.Errorf("IsReservedServiceApplication(%q, %q) = %v, want %v", tc.team, tc.component, got, tc.want)
		}
	}
}

// Every operation that addresses a <team>-<component> refuses a reserved
// pair in ValidateInput, whichever parameter names the service.
func TestValidateInputRejectsReservedServiceApplication(t *testing.T) {
	reg := NewRegistry()
	bodies := map[string]map[string]string{
		"retire-service":     {"team_name": "root", "component_name": "app"},
		"rollback-service":   {"team_name": "root", "component_name": "app", "target_tag": "1.0.0"},
		"deploy-service":     {"action": "onboard", "team_name": "labs", "component_name": "oidc-zitadel"},
		"preview-deploy":     {"team_name": "shared", "component_name": "pg", "image_tag": "1"},
		"provision-database": {"team_name": "root", "app_name": "app"},
		"add-custom-domain":  {"team_name": "erpact", "service_name": "control", "domain": "a.example.com"},
	}
	for name, body := range bodies {
		op, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s not in registry", name)
		}
		errs := reg.ValidateInput(op, reg.ApplyDefaults(op, body))
		if !strings.Contains(strings.Join(errs, ";"), "reserved for platform use") {
			t.Errorf("%s: reserved service not refused: %v", name, errs)
		}
		// The same operation on an ordinary service is untouched by it.
		ok2 := map[string]string{}
		for k, v := range body {
			ok2[k] = v
		}
		ok2["team_name"] = "acme"
		errs = reg.ValidateInput(op, reg.ApplyDefaults(op, ok2))
		if strings.Contains(strings.Join(errs, ";"), "reserved for platform use") {
			t.Errorf("%s: ordinary service refused as reserved: %v", name, errs)
		}
	}
}

// Submit refuses on its own, for callers that skip ValidateInput.
func TestSubmitRejectsReservedServiceApplication(t *testing.T) {
	e := &Executor{}
	reg := NewRegistry()
	op, _ := reg.Get("retire-service")
	res, err := e.Submit(context.Background(), op, map[string]string{"team_name": "root", "component_name": "app"}, "u", "root")
	if !errors.Is(err, ErrReservedServiceApplication) || res != nil {
		t.Fatalf("Submit = %v, %v; want ErrReservedServiceApplication", res, err)
	}
}

func TestTenantNameCollision(t *testing.T) {
	cases := []struct {
		name  string
		other string
		want  bool
	}{
		{"labs-mctl", "labs", true}, // extends an existing tenant
		{"admins-mctl", "admins", true},
		{"erpact-oidc", "erpact", true},
		{"ovk-x", "ovk", true},
		{"lab", "", false}, // "labs" does not start with "lab-"
		{"labsx", "", false},
		{"labs", "", false}, // the same tenant is not a collision
		{"karabu2", "", false},
		{"acme", "", false},
	}
	for _, tc := range cases {
		other, got := TenantNameCollision(tc.name, existingTenants)
		if got != tc.want || other != tc.other {
			t.Errorf("TenantNameCollision(%q) = %q, %v; want %q, %v", tc.name, other, got, tc.other, tc.want)
		}
	}
	// The reverse direction: a new name that an existing tenant extends.
	if other, got := TenantNameCollision("acme", []string{"acme-dev"}); !got || other != "acme-dev" {
		t.Errorf(`"acme" next to "acme-dev" = %q, %v; want a collision`, other, got)
	}
}

// Teardown operations are exempt: a record that exists for a reserved pair
// must stay removable (DELETE /domains keeps a row whose teardown fails).
func TestTeardownOperationsSkipReservedPairCheck(t *testing.T) {
	reg := NewRegistry()
	for name, body := range map[string]map[string]string{
		"remove-custom-domain": {"team_name": "erpact", "service_name": "control", "domain": "a.example.com"},
		"preview-delete":       {"team_name": "shared", "component_name": "pg", "preview_id": "abc123"},
	} {
		op, _ := reg.Get(name)
		if errs := reg.ValidateInput(op, reg.ApplyDefaults(op, body)); len(errs) != 0 {
			t.Errorf("%s: teardown refused: %v", name, errs)
		}
		if err := checkServiceApplication(op, body); err != nil {
			t.Errorf("%s: Submit backstop refused teardown: %v", name, err)
		}
	}
}

func TestPreviewIDIsPatterned(t *testing.T) {
	reg := NewRegistry()
	op, _ := reg.Get("preview-delete")
	for id, ok := range map[string]bool{"abc123": true, "x": true, "pr-42": true, "../x": false, "-x": false, "": false, "ABC": false} {
		body := map[string]string{"team_name": "acme", "component_name": "web", "preview_id": id}
		errs := reg.ValidateInput(op, body)
		if (len(errs) == 0) != ok {
			t.Errorf("preview_id %q: errs=%v, want ok=%v", id, errs, ok)
		}
	}
}

// preview-delete skips the pair check but not the name it composes: the
// hyphen joining component and preview_id is in neither parameter.
func TestPreviewDeleteComposedNameIsChecked(t *testing.T) {
	reg := NewRegistry()
	op, _ := reg.Get("preview-delete")
	for _, tc := range []struct {
		component, id string
		reserved      bool
	}{
		{"oidc", "zitadel", true}, // labs-oidc-zitadel
		{"mctl", "api", false},    // labs-mctl-api is not platform-owned
		{"web", "abc123", false},
		{"oidc-zitadel", "abc123", false}, // the pair itself is exempt for teardown
	} {
		body := map[string]string{"team_name": "labs", "component_name": tc.component, "preview_id": tc.id}
		errs := reg.ValidateInput(op, body)
		got := strings.Contains(strings.Join(errs, ";"), "reserved for platform use")
		if got != tc.reserved {
			t.Errorf("%s + %s: refused=%v, want %v (%v)", tc.component, tc.id, got, tc.reserved, errs)
		}
		if err := checkServiceApplication(op, body); errors.Is(err, ErrReservedServiceApplication) != tc.reserved {
			t.Errorf("%s + %s: Submit backstop err=%v, want reserved=%v", tc.component, tc.id, err, tc.reserved)
		}
	}
}
