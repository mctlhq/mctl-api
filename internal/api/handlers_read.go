package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// ListTenants returns all workspaces from the GitOps repo.
func (h *Handlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.GitReader.ListTenants()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenants: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": tenants,
		"count": len(tenants),
	})
}

// GetTenant returns details of a single workspace.
func (h *Handlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tenant, err := h.GitReader.GetTenant(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+name)
		return
	}

	// Also list services for this tenant.
	services, _ := h.GitReader.ListServices(name)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant":   tenant,
		"services": services,
	})
}

// ListServices returns all deployed services.
func (h *Handlers) ListServices(w http.ResponseWriter, r *http.Request) {
	teamFilter := r.URL.Query().Get("team")
	services, err := h.GitReader.ListServices(teamFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list services: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": services,
		"count": len(services),
	})
}

// GetService returns details of a specific service.
func (h *Handlers) GetService(w http.ResponseWriter, r *http.Request) {
	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	svc, err := h.GitReader.GetService(team, app)
	if err != nil {
		writeError(w, http.StatusNotFound, "service not found: "+team+"/"+app)
		return
	}

	writeJSON(w, http.StatusOK, svc)
}

// GetServiceStatus returns ArgoCD health and sync status for a service.
func (h *Handlers) GetServiceStatus(w http.ResponseWriter, r *http.Request) {
	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	// ArgoCD app name follows the convention: {team}-{app}
	argoAppName := team + "-" + app

	status, err := h.ArgoCD.GetAppStatus(argoAppName)
	if err != nil {
		// Try with preview prefix (preview-{team}-{app} for preview env).
		status, err = h.ArgoCD.GetAppStatus("preview-" + argoAppName)
		if err != nil {
			writeError(w, http.StatusNotFound, "ArgoCD application not found: "+argoAppName)
			return
		}
	}

	// Enrich with service details from gitops.
	svc, _ := h.GitReader.GetService(team, app)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"argocd":  status,
		"service": svc,
	})
}

// ListWorkflows returns recent Argo Workflow runs.
// TODO: Connect to Argo Workflows API.
func (h *Handlers) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": []interface{}{},
		"count": 0,
		"note":  "Argo Workflows API integration pending — requires in-cluster deployment",
	})
}

// GetWorkflow returns details of a specific Argo Workflow run.
// TODO: Connect to Argo Workflows API.
func (h *Handlers) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":   name,
		"status": "unknown",
		"note":   "Argo Workflows API integration pending — requires in-cluster deployment",
	})
}

// GetResourceUsage returns resource quota usage for a tenant namespace.
// TODO: Connect to Kubernetes API.
func (h *Handlers) GetResourceUsage(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")

	// Read quota definitions from gitops.
	t, err := h.GitReader.GetTenant(tenant)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+tenant)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant":    tenant,
		"allocated": t.Quotas,
		"used":      map[string]string{}, // TODO: read from K8s API when in-cluster
		"note":      "Usage data requires in-cluster deployment with K8s API access",
	})
}

// ListAudit returns recent audit log entries.
func (h *Handlers) ListAudit(w http.ResponseWriter, r *http.Request) {
	entries := h.AuditLog.List(50)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": entries,
		"count": len(entries),
	})
}

// ListOperations returns all available operations.
func (h *Handlers) ListOperations(w http.ResponseWriter, r *http.Request) {
	ops := h.Registry.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": ops,
		"count": len(ops),
	})
}

// GetOperation returns details of a specific operation.
func (h *Handlers) GetOperation(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	op, ok := h.Registry.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "operation not found: "+name)
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
