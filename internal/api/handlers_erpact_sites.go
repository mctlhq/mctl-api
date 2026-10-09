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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/erpactsites"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// ERPact site tools (mctl-api#486, owner decision 2026-10-06): a temporary,
// tenant-`erpact`-only stopgap in front of the tenant's own site-deployer.
// Everything here is provisional and is removed once Option B (an MCP
// endpoint in the deployer itself) ships — do not extend this to a second
// tenant or generalize it; a new tenant with its own deployer gets its own
// package and its own handlers.
//
// erpactSiteCap bounds how many sites tenant `erpact` may have through this
// path, so an assistant cannot be asked to spin up an unbounded number of
// databases and disk volumes on existing cluster capacity (owner decision,
// 2026-10-08: cap is 10).
const erpactTenant = "erpact"
const erpactSiteCap = 10

// erpactCreateMu serializes the cap check and the create call, so two
// concurrent requests cannot both see "9 of 10" and both create. It covers
// one mctl-api process; across replicas the deployer's own single-flight
// lock (ErrBusy) is what refuses the second create. It is held across two
// HTTP calls (list, then create), bounded by the request's own 30s timeout,
// so a slow deployer queues other creates for up to ~30s; acceptable for a
// rare, owner-only operation.
var erpactCreateMu sync.Mutex

// erpactMainDomain mirrors the deployer's own MAIN_DOMAIN env var. The
// deployer's listing reports each site by its full host (name+"."+MAIN_DOMAIN);
// this API accepts and reports the short name a caller used at creation, so
// it needs the suffix to translate between the two.
const erpactMainDomain = "mctl.ai"

// erpactShortName strips the deployer's MAIN_DOMAIN suffix from a listed
// site's host, back to the short name CreateErpactSite accepted. A host
// that, unexpectedly, does not carry the suffix is returned unchanged
// rather than mangled — this only ever happens if MAIN_DOMAIN itself
// changes on the deployer side without this constant following it.
func erpactShortName(host string) string {
	return strings.TrimSuffix(host, "."+erpactMainDomain)
}

// erpactSiteHostPrefix mirrors the deployer's SITE_HOST_PREFIX env var. The
// running deployer (its argocd_controller.py comes from a ConfigMap override
// in erpact/mctl-apps, not from site-deployer main) builds a host as
// SITE_HOST_PREFIX + name + "." + MAIN_DOMAIN, so it is sent the label
// without this prefix. Sending the full name created
// "erpact-erpact-<label>" in prod on 2026-10-09.
const erpactSiteHostPrefix = "erpact-"

// erpactSiteNamePattern mirrors the deployer's own validate_site_name
// (app/argocd_controller.py: `^[A-Za-z\-0-9]*$`), narrowed to lowercase
// (the deployer host is used verbatim in DNS and nothing downstream
// uppercases it) and to the required "erpact-" prefix the issue asks for,
// so a tenant member cannot create a site that collides with, or is
// mistaken for, another product's naming.
var erpactSiteNamePattern = regexp.MustCompile(`^erpact-[a-z0-9-]{1,40}$`)

// erpactSystemNames mirrors the deployer's own SYSTEM_NAMES
// (app/argocd_controller.py), reserved regardless of the "erpact-" prefix
// check above — none of them would pass it, but a future prefix change
// must not silently drop this guard.
var erpactSystemNames = map[string]bool{
	"apps": true, "readme": true, "database": true, "mariadb": true,
	"helm-flow-master": true, "helm-guestbook": true, "helm-prajavani": true,
	"system": true, "root": true, "control": true,
}

// validateErpactSiteName normalizes and validates a caller-supplied site
// name before it reaches the deployer. The deployer's own validation is not
// a substitute for this: it is reached with the platform's identity, not the
// caller's, so a rejection there would not be attributable to the right
// person and would waste the deployer's single-flight creation lock.
func validateErpactSiteName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", errors.New("missing required field: name")
	}
	if !erpactSiteNamePattern.MatchString(name) {
		return "", fmt.Errorf("site name %q must start with \"erpact-\", contain only lowercase letters, digits and hyphens, and be at most 47 characters", name)
	}
	if strings.EqualFold(name+"."+erpactMainDomain, erpactBaseHostName) {
		return "", fmt.Errorf("site name %q is reserved", name)
	}
	if erpactSystemNames[strings.TrimPrefix(name, "erpact-")] {
		return "", fmt.Errorf("site name %q is reserved", name)
	}
	return name, nil
}

// erpactBaseHostName is the shared namespace's own infrastructure host,
// which the deployer's GET /sites/shared always lists alongside real tenant
// sites. Matched by this explicit name rather than by Site.Status being
// empty: a real site the deployer happens to report with no status yet
// would otherwise be hidden from the listing, excluded from erpactSiteCap's
// count, and 404 from a status lookup during exactly the create-then-poll
// window a caller needs it most (review finding on mctl-api#497).
const erpactBaseHostName = "erpact-shared-stteam." + erpactMainDomain

func erpactIsBaseHost(s erpactsites.Site) bool {
	return strings.EqualFold(s.Name, erpactBaseHostName)
}

// requireErpactAccess gates every erpact-sites route on authentication and
// tenant membership. A member of another tenant gets the same 404 a
// nonexistent tenant would (never 403): the tenant `erpact` itself is not
// secret, but a cross-tenant caller must not learn anything about whether
// a particular feature is enabled for it beyond what every other
// /api/v1/tenants/{name} route already discloses.
//
// The membership check runs BEFORE the deployer-configured check, and
// deliberately so: checking configuration first would mean a non-member's
// response (503 vs. 404) depends on whether the feature happens to be
// enabled on the platform — the exact disclosure this function exists to
// avoid.
func (h *Handlers) requireErpactAccess(w http.ResponseWriter, r *http.Request) *auth.User {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil
	}
	if !user.IsAdmin() && !user.HasTenantAccess(erpactTenant) {
		writeError(w, http.StatusNotFound, "tenant not found")
		return nil
	}
	if h.opts.ErpactDeployer == nil {
		writeError(w, http.StatusServiceUnavailable, "erpact site tools are not configured")
		return nil
	}
	return user
}

// erpactSiteResponse hides the deployer's internal "enabled" flag, which
// exists for the shared ingress template, not for a caller of this API.
type erpactSiteResponse struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	Status string `json:"status,omitempty"`
}

func erpactSiteResponseFor(s erpactsites.Site) erpactSiteResponse {
	return erpactSiteResponse{Name: erpactShortName(s.Name), Host: s.Name, Status: s.Status}
}

// ListErpactSites lists tenant `erpact`'s sites.
// GET /api/v1/tenants/erpact/sites
//
// A failed read of the deployer is an error, never an empty list: a caller
// must not be able to mistake "the deployer could not be reached" for
// "there are no sites" (mctl-api AGENTS.md, "could not observe is never
// observed absent").
func (h *Handlers) ListErpactSites(w http.ResponseWriter, r *http.Request) {
	if h.requireErpactAccess(w, r) == nil {
		return
	}

	sites, err := h.opts.ErpactDeployer.ListSites(r.Context())
	if err != nil {
		// The deployer's raw error can carry its response body verbatim
		// (internal/erpactsites/client.go); logged here, not returned to
		// the caller, per the convention in tenant_role.go.
		slog.Error("erpact deployer list failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not read erpact sites")
		return
	}

	out := make([]erpactSiteResponse, 0, len(sites))
	for _, s := range sites {
		if erpactIsBaseHost(s) {
			continue
		}
		out = append(out, erpactSiteResponseFor(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out})
}

// CreateErpactSite creates a new site for tenant `erpact`.
// POST /api/v1/tenants/erpact/sites  body: {"name"}
func (h *Handlers) CreateErpactSite(w http.ResponseWriter, r *http.Request) {
	user := h.requireErpactAccess(w, r)
	if user == nil {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name, err := validateErpactSiteName(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Creating, starting or stopping a site is an owner-level write (the
	// issue's "tenant admin-level role"; mctl-api has no tenant role literally
	// named "admin" — RoleAdmin is platform-only — so RoleOwner, the highest
	// tenant role, is what satisfies it).
	if !h.requireTenantRole(w, r, user, erpactTenant, operations.RoleOwner, "erpact.create_site", operations.RiskMedium) {
		return
	}

	auditParams := map[string]string{"tenant": erpactTenant, "site": name}

	erpactCreateMu.Lock()
	defer erpactCreateMu.Unlock()

	existing, err := h.opts.ErpactDeployer.ListSites(r.Context())
	if err != nil {
		slog.Error("erpact deployer list failed (cap check)", "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not check the erpact site cap")
		return
	}
	count := 0
	duplicate := false
	for _, s := range existing {
		if erpactIsBaseHost(s) {
			continue
		}
		count++
		if strings.EqualFold(erpactShortName(s.Name), name) {
			duplicate = true
		}
	}
	if count >= erpactSiteCap {
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "erpact.create_site",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(operations.RiskMedium),
			Message:    fmt.Sprintf("cap of %d reached", erpactSiteCap),
		})
		writeError(w, http.StatusConflict, fmt.Sprintf("tenant %q has reached its cap of %d erpact sites", erpactTenant, erpactSiteCap))
		return
	}
	if duplicate {
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "erpact.create_site",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(operations.RiskMedium),
			Message:    fmt.Sprintf("site %q already exists", name),
		})
		writeError(w, http.StatusConflict, fmt.Sprintf("erpact site %q already exists", name))
		return
	}

	host, err := h.opts.ErpactDeployer.CreateSite(r.Context(), strings.TrimPrefix(name, erpactSiteHostPrefix))
	if errors.Is(err, erpactsites.ErrOutcomeUnknown) {
		slog.Warn("erpact deployer create outcome unknown", "site", name, "error", err)
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "erpact.create_site",
			Parameters: auditParams,
			Status:     "unknown",
			RiskLevel:  string(operations.RiskMedium),
			Message:    err.Error(),
		})
		writeJSON(w, http.StatusAccepted, map[string]any{
			"name":    name,
			"status":  "unknown",
			"message": "the deployer did not answer in time; the site may still be created, check its status before retrying",
		})
		return
	}
	if err != nil {
		// The deployer's raw error can carry its response body verbatim
		// (internal/erpactsites/client.go); logged here, not returned to
		// the caller, per the convention in tenant_role.go. Only the two
		// sentinel cases get a caller-facing detail, since their message is
		// static and does not echo the body.
		slog.Error("erpact deployer create failed", "site", name, "error", err)
		status := http.StatusServiceUnavailable
		message := "could not create erpact site"
		switch {
		case errors.Is(err, erpactsites.ErrSiteExists):
			status = http.StatusConflict
			message = fmt.Sprintf("erpact site %q already exists", name)
		case errors.Is(err, erpactsites.ErrBusy):
			status = http.StatusConflict
			message = "erpact deployer is busy, try again later"
		}
		h.logAudit(r, audit.Entry{
			UserID:     user.ID,
			Operation:  "erpact.create_site",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(operations.RiskMedium),
			Message:    err.Error(),
		})
		writeError(w, status, message)
		return
	}

	h.logAudit(r, audit.Entry{
		UserID:     user.ID,
		Operation:  "erpact.create_site",
		Parameters: auditParams,
		Status:     "submitted",
		RiskLevel:  string(operations.RiskMedium),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"name":   name,
		"host":   host,
		"status": "creating",
	})
}

// GetErpactSiteStatus reports the lifecycle status of one site, by polling
// the same listing ListErpactSites uses — the deployer has no separate
// per-job status endpoint; a site's row in GET /sites/shared carries its
// current status directly (CREATING, then ACTIVE once the setup job calls
// the deployer back).
// GET /api/v1/tenants/erpact/sites/{name}/status
func (h *Handlers) GetErpactSiteStatus(w http.ResponseWriter, r *http.Request) {
	if h.requireErpactAccess(w, r) == nil {
		return
	}

	name := strings.ToLower(chi.URLParam(r, "name"))
	sites, err := h.opts.ErpactDeployer.ListSites(r.Context())
	if err != nil {
		slog.Error("erpact deployer list failed (status lookup)", "error", err)
		writeError(w, http.StatusServiceUnavailable, "could not read erpact sites")
		return
	}
	for _, s := range sites {
		if erpactIsBaseHost(s) {
			continue
		}
		if strings.ToLower(erpactShortName(s.Name)) == name {
			writeJSON(w, http.StatusOK, erpactSiteResponseFor(s))
			return
		}
	}
	writeError(w, http.StatusNotFound, fmt.Sprintf("erpact site %q not found", name))
}
