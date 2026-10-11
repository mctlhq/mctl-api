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

// ErrReservedServiceApplication is returned (wrapped) when a tenant service
// operation names a team and component whose Argo CD Application name,
// <team>-<component>, belongs to the platform.
var ErrReservedServiceApplication = errors.New("service name maps to a platform-owned application")

// serviceComponentParams are the parameter names operations use for the
// service part of <team>-<component>.
var serviceComponentParams = []string{"component_name", "service_name", "app_name"}

// reservedComponentNames are component names the platform's own
// ApplicationSets append to a tenant name (<tenant>-openclaw-skills).
var reservedComponentNames = map[string]struct{}{
	"openclaw-skills": {},
}

// teardownOperations remove what a tenant already has, inside its own
// paths and namespaces, without acting on the <team>-<component> Argo CD
// Application: remove-custom-domain edits services/<team>/<service>, and
// preview-delete uninstalls a Helm release in <team>-preview or <team>. The
// reserved-pair check does not apply to them, so a record that exists can
// always be cleaned up (DELETE /domains keeps a row whose teardown fails).
var teardownOperations = map[string]struct{}{
	"remove-custom-domain": {},
	"preview-delete":       {},
}

// ChecksReservedPair reports whether op is refused for a reserved
// <team>-<component> pair: every operation that names a service, except the
// teardown operations above.
func ChecksReservedPair(op Operation) bool {
	_, teardown := teardownOperations[op.Name]
	return !teardown
}

// ServiceTarget returns the team and component an operation acts on, when it
// takes both. ok is false for operations that do not address a service.
func ServiceTarget(op Operation, params map[string]string) (team, component string, ok bool) {
	if !declares(op, "team_name") {
		return "", "", false
	}
	for _, name := range serviceComponentParams {
		if declares(op, name) {
			return params["team_name"], params[name], true
		}
	}
	return "", "", false
}

func declares(op Operation, name string) bool {
	for _, p := range op.Parameters {
		if p.Name == name {
			return true
		}
	}
	return false
}

// IsReservedServiceApplication reports whether <team>-<component> is the name
// of a platform-owned Argo CD Application, or a component name the platform's
// ApplicationSets generate themselves. A tenant service with that name would
// make the apps ApplicationSet produce an Application that collides with the
// platform's, and an operation on it would act on the platform's.
//
// The comparison is case-insensitive, like IsReservedTenantName.
func IsReservedServiceApplication(team, component string) bool {
	t := strings.ToLower(strings.TrimSpace(team))
	c := strings.ToLower(strings.TrimSpace(component))
	if t == "" || c == "" {
		return false
	}
	if _, ok := reservedComponentNames[c]; ok {
		return true
	}
	name := t + "-" + c
	if strings.HasPrefix(name, "tenant-") {
		return true
	}
	for _, list := range [][]string{platformApplicationNames, tenantScopedPlatformApplications} {
		for _, p := range list {
			if name == p {
				return true
			}
		}
	}
	return false
}

func reservedServiceApplicationMessage(team, component string) string {
	return fmt.Sprintf("%q/%q is reserved for platform use; choose a different service name",
		echoTenantName(team), echoTenantName(component))
}

// checkServiceApplication returns a wrapped ErrReservedServiceApplication
// when op addresses a service whose Application name is platform-owned.
// Executor.Submit uses it as the backstop; Registry.ValidateInput applies the
// same predicate for the clear 400.
func checkServiceApplication(op Operation, params map[string]string) error {
	team, component, ok := ServiceTarget(op, params)
	if !ok || !ChecksReservedPair(op) || !IsReservedServiceApplication(team, component) {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrReservedServiceApplication, echoTenantName(team+"-"+component))
}

// TenantNameCollision returns the existing tenant a new tenant name would
// share an Application namespace with, if any: name extends an existing
// tenant ("labs-x" next to "labs") or an existing tenant extends it ("lab"
// next to "lab-y"). Either way <a>-<service> of one tenant could spell the
// Application of a service of the other. Equality is not a collision: that
// is the same tenant, which create-tenant handles on its own.
func TenantNameCollision(name string, existing []string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, e := range existing {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" || e == n {
			continue
		}
		if strings.HasPrefix(n, e+"-") || strings.HasPrefix(e, n+"-") {
			return e, true
		}
	}
	return "", false
}
