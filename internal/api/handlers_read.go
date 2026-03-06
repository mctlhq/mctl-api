package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (h *Handlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.opts.GitReader.ListTenants()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenants: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": tenants,
		"count": len(tenants),
	})
}

func (h *Handlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tenant, err := h.opts.GitReader.GetTenant(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+name)
		return
	}
	services, _ := h.opts.GitReader.ListServices(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant":   tenant,
		"services": services,
	})
}

func (h *Handlers) ListServices(w http.ResponseWriter, r *http.Request) {
	teamFilter := r.URL.Query().Get("team")
	services, err := h.opts.GitReader.ListServices(teamFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list services: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": services,
		"count": len(services),
	})
}

func (h *Handlers) GetService(w http.ResponseWriter, r *http.Request) {
	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")
	svc, err := h.opts.GitReader.GetService(team, app)
	if err != nil {
		writeError(w, http.StatusNotFound, "service not found: "+team+"/"+app)
		return
	}
	writeJSON(w, http.StatusOK, svc)
}

func (h *Handlers) GetServiceStatus(w http.ResponseWriter, r *http.Request) {
	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	// ArgoCD app naming convention: {team}-{app} (or preview-{team}-{app})
	argoAppName := team + "-" + app
	status, err := h.opts.ArgoCD.GetAppStatus(argoAppName)
	if err != nil {
		status, err = h.opts.ArgoCD.GetAppStatus("preview-" + argoAppName)
		if err != nil {
			writeError(w, http.StatusNotFound, "ArgoCD application not found: "+argoAppName)
			return
		}
	}

	svc, _ := h.opts.GitReader.GetService(team, app)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"argocd":  status,
		"service": svc,
	})
}

func (h *Handlers) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": []interface{}{},
		"count": 0,
		"note":  "Argo Workflows API integration requires in-cluster deployment",
	})
}

func (h *Handlers) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	// Check audit log for a record of this workflow.
	entry := h.opts.AuditLog.GetByWorkflow(name)
	if entry != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"workflow": name,
			"audit":    entry,
			"note":     "Live Argo Workflows log requires in-cluster deployment",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow": name,
		"status":   "unknown",
		"note":     "Argo Workflows API integration requires in-cluster deployment",
	})
}

func (h *Handlers) GetResourceUsage(w http.ResponseWriter, r *http.Request) {
	tenant := chi.URLParam(r, "tenant")
	t, err := h.opts.GitReader.GetTenant(tenant)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+tenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant":    tenant,
		"allocated": t.Quotas,
		"used":      map[string]string{},
		"note":      "Live usage metrics require in-cluster deployment",
	})
}

func (h *Handlers) ListAudit(w http.ResponseWriter, r *http.Request) {
	entries := h.opts.AuditLog.List(50)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": entries,
		"count": len(entries),
	})
}

func (h *Handlers) ListOperations(w http.ResponseWriter, r *http.Request) {
	ops := h.opts.Registry.List()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": ops,
		"count": len(ops),
	})
}

func (h *Handlers) GetOperation(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	op, ok := h.opts.Registry.Get(name)
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
