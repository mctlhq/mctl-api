// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package operations

import (
	"fmt"
	"strings"
)

// Reserved tenant names.
//
// This mirrors tenant_name_reserved() in mctl-gitops:
// platform-gitops/argo-workflows/cluster-templates/wft-create-tenant.yaml
// (mctl-gitops#1770). The two lists must change together. The shell glob
// `X*` is a prefix and `*X` is a suffix; plain HasPrefix/HasSuffix keeps the
// semantics identical to the shell `case`.
var reservedTenantNames = map[string]struct{}{
	"argocd": {}, "argo-workflows": {}, "argo-events": {},
	"kube-system": {}, "kube-public": {}, "kube-node-lease": {},
	"default": {}, "cert-manager": {}, "traefik": {}, "vault": {},
	"external-secrets": {}, "monitoring": {}, "temporal": {},
	"backstage": {}, "minio": {}, "database": {}, "forgejo": {},
	"zitadel": {}, "local-path-storage": {}, "system-upgrade": {},
	"observability-eval": {},
	// Platform group and sentinel team names.
	"admins": {}, "platform": {},
}

var (
	reservedTenantNamePrefixes = []string{"kube-", "argo", "platform-", "mctl-", "grafana-", "vault"}
	reservedTenantNameSuffixes = []string{"-system"}
)

// IsReservedTenantName reports whether name collides with a platform namespace.
func IsReservedTenantName(name string) bool {
	if _, ok := reservedTenantNames[name]; ok {
		return true
	}
	for _, p := range reservedTenantNamePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, s := range reservedTenantNameSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// checkReservedTenantName rejects a reserved tenant_name for the create-tenant
// workflow template. It is keyed on the template so a hand-built Operation
// targeting it is covered too.
func checkReservedTenantName(op Operation, params map[string]string) error {
	if op.WorkflowTemplate != "create-tenant" {
		return nil
	}
	name := params["tenant_name"]
	if name != "" && IsReservedTenantName(name) {
		return fmt.Errorf("tenant_name: %q is reserved for a platform namespace; choose another name", name)
	}
	return nil
}
