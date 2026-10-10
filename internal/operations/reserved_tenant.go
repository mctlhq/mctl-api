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
	"temporal":           {},
	"backstage":          {},
	"minio":              {},
	"database":           {},
	"forgejo":            {},
	"zitadel":            {},
	"local-path-storage": {},
	"system-upgrade":     {},
	"observability-eval": {},
}

var (
	reservedTenantPrefixes = []string{"kube-", "argo", "platform-", "mctl-", "grafana-", "vault"}
	reservedTenantSuffixes = []string{"-system"}
)

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

// reservedTenantNameMessage is the caller-facing text; it names no list.
func reservedTenantNameMessage(name string) string {
	return fmt.Sprintf("tenant_name: %q is reserved for platform use; choose a different name", name)
}

// checkCreateTenantName returns a wrapped ErrReservedTenantName when op
// creates a tenant and params name a reserved one. It is the single check
// behind both Registry.ValidateInput (the clear 400) and Executor.Submit (the
// backstop for any caller that does not go through the REST handler).
func checkCreateTenantName(op Operation, params map[string]string) error {
	if !createsTenant(op) {
		return nil
	}
	name := params["tenant_name"]
	if IsReservedTenantName(name) {
		return fmt.Errorf("%w: %q", ErrReservedTenantName, name)
	}
	return nil
}
