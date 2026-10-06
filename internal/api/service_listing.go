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
)

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
		return nil, err
	}

	entries := make([]ServiceEntry, 0, len(catalogue))
	byApp := make(map[string]int, len(catalogue))
	for _, svc := range catalogue {
		byApp[svc.Team+"-"+svc.Name] = len(entries)
		entries = append(entries, ServiceEntry{Service: svc, Managed: managedCatalogue})
	}

	listing := &serviceListing{ArgoState: argoStateOK}
	var workloads []argocd.Workload
	if h.opts.ArgoCD == nil {
		listing.ArgoState = argoStateNotConfigured
	} else if workloads, err = h.opts.ArgoCD.ListWorkloads(); err != nil {
		listing.ArgoState = argoStateUnavailable
	}

	if listing.complete() {
		tenants, err := h.opts.GitReader.ListTenants()
		if err != nil {
			return nil, err
		}
		isTenant := make(map[string]bool, len(tenants))
		for i := range tenants {
			isTenant[tenants[i].Name] = true
		}

		deployed, notDeployed := true, false
		for i := range entries {
			entries[i].Deployed = &notDeployed
		}
		for i := range workloads {
			w := &workloads[i]
			// Previews have their own listing and are not services.
			if strings.HasPrefix(w.Name, "preview-") {
				continue
			}
			if idx, ok := byApp[w.Name]; ok && !ownedByOtherTenant(w, entries[idx].Team, isTenant) {
				e := &entries[idx]
				e.ArgoApp, e.Deployed = w.Name, &deployed
				e.Health, e.SyncStatus = w.Health, w.SyncStatus
				e.Hosts, e.Images = w.Hosts, w.Images
				e.Source = sourceOf(w)
				continue
			}
			// Outside the catalogue an application belongs to the tenant it
			// deploys into, never to the tenant its name suggests.
			team := w.DestNamespace
			if !isTenant[team] || (teamFilter != "" && team != teamFilter) {
				continue
			}
			managed := managedPlatform
			if w.Project == team {
				// A tenant's own AppProject carries the tenant's name.
				managed = managedExternal
			}
			entries = append(entries, ServiceEntry{
				Service:    gitops.Service{Team: team, Name: strings.TrimPrefix(w.Name, team+"-")},
				Managed:    managed,
				ArgoApp:    w.Name,
				Deployed:   &deployed,
				Health:     w.Health,
				SyncStatus: w.SyncStatus,
				Hosts:      w.Hosts,
				Images:     w.Images,
				Source:     sourceOf(w),
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
		// Where the platform keeps its own manifests is not a tenant's business.
		if e.Managed == managedPlatform && !user.IsAdmin() {
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

// ownedByOtherTenant reports whether w sits in another tenant's own project.
// Such an application may carry any name, including the {team}-{name} of a
// catalogue service that is not deployed, and must not be merged into it.
func ownedByOtherTenant(w *argocd.Workload, team string, isTenant map[string]bool) bool {
	return w.Project != team && isTenant[w.Project]
}

func sourceOf(w *argocd.Workload) *ServiceSource {
	if w.SourceRepo == "" && w.SourcePath == "" {
		return nil
	}
	return &ServiceSource{Repo: w.SourceRepo, Path: w.SourcePath}
}
