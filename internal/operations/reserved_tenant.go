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
	"errors"
	"fmt"
	"strings"
)

// Reserved tenant names for create-tenant.
//
// SOURCE OF TRUTH: the tenant_name_reserved shell function in
// mctlhq/mctl-gitops, platform-gitops/argo-workflows/cluster-templates/
// wft-create-tenant.yaml (the "tenant-ns-guard" block, added in
// mctl-gitops#1770 for #1768). The lists below mirror it as of that change.
// When the shell list changes, change this file in the same sweep; the two
// are kept in sync by hand. This one is the early, caller-facing layer: it
// turns a name the workflow would refuse into a validation error before any
// workflow is submitted. The WorkflowTemplate's check (and its live-cluster
// namespace check) remain the authoritative defence.
//
// The shell function is a `case` statement, so a pattern there is a glob
// anchored at both ends. Each form is reproduced exactly:
//
//	exact names   ->  reservedTenantNames
//	"kube-*"      ->  prefix "kube-"
//	"argo*"       ->  prefix "argo"   (no hyphen: "argocd", "argonaut" match)
//	"*-system"    ->  suffix "-system"
//	"platform-*"  ->  prefix "platform-"
//	"mctl-*"      ->  prefix "mctl-"
//	"grafana-*"   ->  prefix "grafana-"
//	"vault*"      ->  prefix "vault"  (no hyphen: "vault2" matches)
//
// So look-alikes are NOT accepted: "kube-system-team" is reserved (prefix
// "kube-"), "my-system" is reserved (suffix "-system"), while "team-kube" or
// "systems" are not. The wildcards only match at the stated end.
//
// "platform" is the team mctl-gitops config/image-names.txt grants the
// platform's own images to (mctl-gitops#1648), so it must never be a tenant.
//
// There is deliberately no admin bypass. The workflow's own check has none
// either (reprovision=true does not skip it), so letting an admin past this
// layer would only move the refusal back into the workflow.
var reservedTenantNames = map[string]struct{}{
	"argocd":             {},
	"argo-workflows":     {},
	"argo-events":        {},
	"kube-system":        {},
	"kube-public":        {},
	"kube-node-lease":    {},
	"default":            {},
	"cert-manager":       {},
	"traefik":            {},
	"vault":              {},
	"external-secrets":   {},
	"monitoring":         {},
	"platform":           {},
	"temporal":           {},
	"backstage":          {},
	"minio":              {},
	"database":           {},
	"forgejo":            {},
	"zitadel":            {},
	"local-path-storage": {},
	"system-upgrade":     {},
	"observability-eval": {},
	"tracing":            {},
}

var (
	reservedTenantPrefixes = []string{"kube-", "argo", "platform-", "mctl-", "grafana-", "vault", "tenant-", "otel-"}
	reservedTenantSuffixes = []string{"-system"}
)

// Tenant names that would collide with Argo CD Application names.
//
// A tenant's services become Argo CD Applications named <tenant>-<service>
// (the "apps" ApplicationSet), and the tenant itself becomes tenant-<tenant>
// (the "tenants" ApplicationSet). Every Application lives in the argocd
// namespace, so the names share one space with the platform's own
// Applications. A tenant name that is a platform Application name, or a
// hyphen-prefix of one, would let that tenant's service names spell the
// platform Application's name. The rule is therefore structural over the list
// below: name N is reserved when N == P or P starts with N+"-" for some P in
// platformApplicationNames. "tenant" and the "tenant-" prefix are reserved
// outright for the tenants ApplicationSet.
//
// The list is the set of Argo CD Applications that are not tenant services
// and whose names do not start with an existing tenant's name. Derive it
// read-only from the cluster:
//
//	kubectl get applications -n argocd -o name
//
// and drop the generated ones: tenant-<x> (tenants ApplicationSet),
// <tenant>-<service> for every platform-gitops/services/<tenant>/<service>
// directory (apps ApplicationSet), <tenant>-openclaw-skills, and the
// platform Applications that sit under an existing tenant's prefix, which
// are listed in tenantScopedPlatformApplications instead. Also check
// platform-gitops/bootstrap/templates in mctl-gitops for Applications that
// are declared but not currently deployed. When this list changes, mirror
// the change in tenant_name_reserved in wft-create-tenant.yaml.
//
// Snapshot taken 2026-10-11 from the live cluster and bootstrap templates.
var platformApplicationNames = []string{
	"argo-rollouts",
	"argo-workflows",
	"argo-workflows-config",
	"argocd-self-managed",
	"cloudnative-pg",
	"external-secrets",
	"forgejo",
	"grafana-iac",
	"loki-stack",
	"minio",
	"monitoring",
	"otel-collector",
	"otel-eval-tempo",
	"reflector",
	"root-app",
	"shared-pg",
	"temporal",
	"temporal-web",
	"valkey",
	"vault",
	"vault-human-auth-iac",
	"zitadel",
}

// tenantScopedPlatformApplications are platform-managed Argo CD Applications
// whose names start with an existing tenant's name (admins, erpact, labs,
// mctl). They cannot feed the tenant-name rule above without reserving the
// existing tenants themselves, which would break re-running create-tenant for
// them. They are protected instead at the service level: no tenant operation
// may target <team>-<component> equal to one of them (see
// IsReservedServiceApplication), and the API refuses a new tenant name that
// is a hyphen-prefix extension of an existing tenant (TenantNameCollision).
var tenantScopedPlatformApplications = []string{
	"admins-mctl-agent",
	"admins-mctl-api",
	"admins-mctl-portal",
	"erpact-control",
	"erpact-deployer",
	"erpact-infra",
	"erpact-oidc-zitadel",
	"erpact-shared",
	"labs-oidc-zitadel",
	"mctl-portal-oidc-zitadel",
}

// reservedTenantExact are names reserved outright beyond the platform list:
// "tenant" would make the tenants ApplicationSet's tenant-<x> Applications
// reachable as <tenant>-<service>. "sync" would give the tenant the name of
// the platform tier's own argocd Role and RoleBinding,
// argo-workflow-argocd-sync, since the tenant chart names its pair
// argo-workflow-argocd-<tenant> (mctl-gitops#1805).
var reservedTenantExact = map[string]struct{}{
	"tenant": {},
	"sync":   {},
}

// collidesWithPlatformApplication reports whether n equals a platform
// Application name or is a hyphen-prefix of one.
func collidesWithPlatformApplication(n string) bool {
	for _, p := range platformApplicationNames {
		if n == p || strings.HasPrefix(p, n+"-") {
			return true
		}
	}
	return false
}

// ErrReservedTenantName is returned (wrapped) when create-tenant is asked for
// a name that collides with a platform namespace.
var ErrReservedTenantName = errors.New("tenant name is reserved for platform use")

// IsReservedTenantName reports whether name is one a new tenant must not
// take. It is create-time only: nothing here looks at existing tenants.
//
// The comparison is case-insensitive. The workflow's own check is
// case-sensitive but runs after a lowercase-only format check, so an
// upper-case spelling is refused there either way; refusing it here too
// means a caller that skips format validation cannot get a reserved name
// past this layer by changing its case.
func IsReservedTenantName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if _, ok := reservedTenantNames[n]; ok {
		return true
	}
	if _, ok := reservedTenantExact[n]; ok {
		return true
	}
	if collidesWithPlatformApplication(n) {
		return true
	}
	for _, p := range reservedTenantPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, s := range reservedTenantSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// createsTenant reports whether op is the create-tenant operation. It keys on
// both the operation name and the workflow template, so renaming one does not
// silently disable the check on the other.
func createsTenant(op Operation) bool {
	return op.Name == "create-tenant" || op.WorkflowTemplate == "create-tenant"
}

// maxEchoedTenantName bounds how much of a caller-supplied name is echoed
// back. The reserved check runs independently of the length pattern, so an
// oversized "mctl-..." name must not be reflected in full.
const maxEchoedTenantName = 64

func echoTenantName(name string) string {
	if len(name) > maxEchoedTenantName {
		return name[:maxEchoedTenantName] + "..."
	}
	return name
}

// reservedTenantNameMessage is the caller-facing text; it names no list.
func reservedTenantNameMessage(name string) string {
	return fmt.Sprintf("tenant_name: %q is reserved for platform use; choose a different name", echoTenantName(name))
}

// checkCreateTenantName returns a wrapped ErrReservedTenantName when op
// creates a tenant and params name a reserved one. Executor.Submit uses it as
// the backstop for any caller that does not go through the REST handler;
// Registry.ValidateInput applies the same predicate for the clear 400.
func checkCreateTenantName(op Operation, params map[string]string) error {
	if !createsTenant(op) {
		return nil
	}
	name := params["tenant_name"]
	if IsReservedTenantName(name) {
		return fmt.Errorf("%w: %q", ErrReservedTenantName, echoTenantName(name))
	}
	return nil
}
