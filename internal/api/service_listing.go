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

package api

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
)

// Who manages a listed service. Only catalogue services support deploy,
// rollback and scale; the other two are read-only through this API.
const (
	managedCatalogue = "catalogue" // has an entry under platform-gitops/services
	managedExternal  = "external"  // deployed by the tenant's own ArgoCD project
	managedPlatform  = "platform"  // deployed by the platform into the tenant namespace
)

// State of the ArgoCD read behind a listing.
const (
	argoStateOK            = "ok"
	argoStateUnavailable   = "unavailable"
	argoStateNotConfigured = "not_configured"
	// argoStateUnknown is used when the listing failed before ArgoCD mattered.
	argoStateUnknown = "unknown"
)

// servicesUnreadWarning accompanies a tenant whose service list could not be
// read at all.
const servicesUnreadWarning = "The service list could not be read: this is an unknown result, not an empty one."

// argoUnreadWarning is returned whenever ArgoCD was not read. Without it a
// tenant that deploys outside the catalogue would see an empty list and take
// it for "nothing runs here".
const argoUnreadWarning = "ArgoCD could not be read: services deployed outside the mctl catalogue are NOT listed, " +
	"and sync, health and hosts are unknown. This is an incomplete result, not an empty one."

// ServiceSource is where ArgoCD takes a service's manifests from.
type ServiceSource struct {
	Repo string `json:"repo,omitempty"`
	Path string `json:"path,omitempty"`
}

// ServiceEntry is one row of the service listing: a catalogue service, an
// ArgoCD application deployed into a tenant namespace, or both merged.
type ServiceEntry struct {
	gitops.Service
	Managed string `json:"managed"`
	// ArgoApp is the ArgoCD application name. The status and logs endpoints
	// address a service as {team}/{name} and resolve it to {team}-{name}, so
	// they work for a row exactly when ArgoApp equals {team}-{name}.
	ArgoApp string `json:"argoApp,omitempty"`
	// Deployed is nil when ArgoCD was not read: unknown, not false.
	Deployed   *bool          `json:"deployed,omitempty"`
	Health     string         `json:"health,omitempty"`
	SyncStatus string         `json:"syncStatus,omitempty"`
	Hosts      []string       `json:"hosts,omitempty"`
	Images     []string       `json:"images,omitempty"`
	Source     *ServiceSource `json:"source,omitempty"`

	// sourceIsTenants is set when the application sits in the tenant's own
	// project or namespace. Only then is its source the tenant's to read.
	sourceIsTenants bool
}

// serviceListing is a set of rows together with how much of it was observed.
type serviceListing struct {
	Items     []ServiceEntry
	ArgoState string
	Warning   string
}

func (l *serviceListing) complete() bool { return l.ArgoState == argoStateOK }

// listServiceEntries merges the catalogue with the ArgoCD applications that
// deploy into tenant namespaces, limited to what user may see.
//
// An error means the catalogue or the tenant list could not be read. A failed
// ArgoCD read is not an error: the catalogue rows are still returned, marked
// incomplete, so that an ArgoCD outage does not hide the catalogue.
func (h *Handlers) listServiceEntries(user *auth.User, teamFilter string) (*serviceListing, error) {
	catalogue, err := h.opts.GitReader.ListServices(teamFilter)
	if err != nil {
		return nil, fmt.Errorf("reading the service catalogue: %w", err)
	}

	entries := make([]ServiceEntry, 0, len(catalogue))
	// {team}-{name} is not unique: labs-a/b and labs/a-b share an application
	// name, so one name maps to every catalogue row that could own it.
	byApp := make(map[string][]int, len(catalogue))
	taken := make(map[string]bool, len(catalogue))
	for _, svc := range catalogue {
		app := svc.Team + "-" + svc.Name
		byApp[app] = append(byApp[app], len(entries))
		taken[rowKey(svc.Team, svc.Name)] = true
		entries = append(entries, ServiceEntry{Service: svc, Managed: managedCatalogue})
	}

	listing := &serviceListing{ArgoState: argoStateOK}
	var workloads []argocd.Workload
	if h.opts.ArgoCD == nil {
		listing.ArgoState = argoStateNotConfigured
	} else if workloads, err = h.opts.ArgoCD.ListWorkloads(); err != nil {
		// The response says only "unavailable"; the cause is for the operator.
		// An expired token makes this permanent, so it is called out.
		slog.Warn("listing argocd applications failed, service listing is incomplete",
			"team", teamFilter, "tokenRejected", errors.Is(err, argocd.ErrUnauthenticated), "error", err)
		listing.ArgoState = argoStateUnavailable
	}

	if listing.complete() {
		tenants, err := h.opts.GitReader.ListTenants()
		if err != nil {
			return nil, fmt.Errorf("reading the tenant list: %w", err)
		}
		isTenant := make(map[string]bool, len(tenants))
		for i := range tenants {
			isTenant[tenants[i].Name] = true
		}

		deployed, notDeployed := true, false
		for i := range entries {
			entries[i].Deployed = &notDeployed
		}
		// Applications that are not the deployment of a catalogue row, with
		// the tenant each one deploys into.
		type extra struct {
			w    *argocd.Workload
			team string
		}
		var extras []extra
		for i := range workloads {
			w := &workloads[i]
			// Previews have their own listing and are not services.
			if strings.HasPrefix(w.Name, "preview-") {
				continue
			}
			if idx, ok := catalogueRowFor(w, byApp[w.Name], entries, isTenant); ok {
				e := &entries[idx]
				e.ArgoApp, e.Deployed = w.Name, &deployed
				e.Health, e.SyncStatus = w.Health, w.SyncStatus
				e.Hosts, e.Images = w.Hosts, w.Images
				e.Source = sourceOf(w)
				e.sourceIsTenants = w.Project == e.Team || w.DestNamespace == e.Team
				continue
			}
			// Outside the catalogue an application belongs to the tenant it
			// deploys into, never to the tenant its name suggests.
			team := w.DestNamespace
			if !isTenant[team] || (teamFilter != "" && team != teamFilter) {
				continue
			}
			extras = append(extras, extra{w: w, team: team})
		}

		// {team}/{name} must stay a key. Application names are unique, so
		// every full name is reserved first and the short form is used only
		// where nothing else has it.
		inCatalogue := make(map[string]bool, len(taken))
		for key := range taken {
			inCatalogue[key] = true
		}
		for _, x := range extras {
			taken[rowKey(x.team, x.w.Name)] = true
		}
		for _, x := range extras {
			w, team := x.w, x.team
			name := w.Name
			if inCatalogue[rowKey(team, name)] {
				// A different application that carries the bare name of a
				// catalogue service. The catalogue row keeps the key.
				name += externalNameSuffix
			}
			if short, ok := strings.CutPrefix(w.Name, team+"-"); ok && short != "" && !taken[rowKey(team, short)] {
				name = short
				taken[rowKey(team, short)] = true
			}
			managed := managedPlatform
			if w.Project == team {
				// A tenant's own AppProject carries the tenant's name.
				managed = managedExternal
			}
			entries = append(entries, ServiceEntry{
				Service:    gitops.Service{Team: team, Name: name},
				Managed:    managed,
				ArgoApp:    w.Name,
				Deployed:   &deployed,
				Health:     w.Health,
				SyncStatus: w.SyncStatus,
				Hosts:      w.Hosts,
				Images:     w.Images,
				Source:     sourceOf(w),
				// The platform deploys into the tenant namespace too; that
				// does not make its manifests the tenant's.
				sourceIsTenants: managed == managedExternal,
			})
		}
	} else {
		listing.Warning = argoUnreadWarning
	}

	listing.Items = make([]ServiceEntry, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		if !user.IsAdmin() && !user.HasTenantAccess(e.Team) {
			continue
		}
		// Where the platform keeps its own manifests is not a tenant's
		// business, on a platform row and on a catalogue row alike.
		if !e.sourceIsTenants && !user.IsAdmin() {
			e.Source = nil
		}
		listing.Items = append(listing.Items, *e)
	}
	sort.SliceStable(listing.Items, func(i, j int) bool {
		a, b := &listing.Items[i], &listing.Items[j]
		if a.Team != b.Team {
			return a.Team < b.Team
		}
		return a.Name < b.Name
	})
	return listing, nil
}

// externalNameSuffix marks an application whose own name is already the key of
// a catalogue service it is not the deployment of.
const externalNameSuffix = "@argocd"

func rowKey(team, name string) string { return team + "/" + name }

// catalogueRowFor picks the catalogue row an application is the deployment
// of, among the rows whose {team}-{name} equals its name. Rows of a tenant the
// application does not deploy for are passed over, which also settles a name
// shared by two rows whenever the application lands in a tenant namespace.
func catalogueRowFor(w *argocd.Workload, candidates []int, entries []ServiceEntry, isTenant map[string]bool) (int, bool) {
	for _, idx := range candidates {
		if !deployedForOtherTenant(w, entries[idx].Team, isTenant) {
			return idx, true
		}
	}
	return 0, false
}

// deployedForOtherTenant reports whether w lands in, or is owned by, a tenant
// other than team. Such an application may carry any name, including the
// {team}-{name} of a catalogue service that is not deployed, and must not be
// merged into it. The namespace half holds however AppProjects are named.
func deployedForOtherTenant(w *argocd.Workload, team string, isTenant map[string]bool) bool {
	return (isTenant[w.Project] && w.Project != team) ||
		(isTenant[w.DestNamespace] && w.DestNamespace != team)
}

func sourceOf(w *argocd.Workload) *ServiceSource {
	if w.SourceRepo == "" && w.SourcePath == "" {
		return nil
	}
	return &ServiceSource{Repo: w.SourceRepo, Path: w.SourcePath}
}
