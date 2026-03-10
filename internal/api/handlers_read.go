package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
)

func (h *Handlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil || !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "listing all tenants requires admin access")
		return
	}
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

	svc, _ := h.opts.GitReader.GetService(team, app)

	// ArgoCD app naming convention: {team}-{app} (or preview-{team}-{app})
	argoAppName := team + "-" + app
	status, err := h.opts.ArgoCD.GetAppStatus(argoAppName)
	if err != nil {
		if errors.Is(err, argocd.ErrUnauthenticated) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"argocd":  nil,
				"service": svc,
				"error":   "ArgoCD token invalid or expired — update ARGOCD_TOKEN in Vault at platform/mctl-api/argocd-token",
			})
			return
		}
		status, err = h.opts.ArgoCD.GetAppStatus("preview-" + argoAppName)
		if err != nil {
			if errors.Is(err, argocd.ErrUnauthenticated) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"argocd":  nil,
					"service": svc,
					"error":   "ArgoCD token invalid or expired — update ARGOCD_TOKEN in Vault at platform/mctl-api/argocd-token",
				})
				return
			}
			writeError(w, http.StatusNotFound, "ArgoCD application not found: "+argoAppName)
			return
		}
	}

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

	resp := map[string]interface{}{
		"tenant":    tenant,
		"allocated": t.Quotas,
		"used":      map[string]string{},
	}

	if h.opts.QuotaReader != nil {
		used, _, quotaErr := h.opts.QuotaReader.GetNamespaceUsage(r.Context(), tenant)
		if quotaErr == nil && used != nil {
			resp["used"] = used
		} else if quotaErr != nil {
			resp["note"] = "quota fetch error: " + quotaErr.Error()
		}
	} else {
		resp["note"] = "Live usage metrics require in-cluster deployment"
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) GetServiceLogs(w http.ResponseWriter, r *http.Request) {
	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")

	lines := 100
	if l := r.URL.Query().Get("lines"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			lines = n
		}
	}

	since := time.Hour
	if s := r.URL.Query().Get("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			since = d
		}
	}

	resp := map[string]interface{}{
		"team": team,
		"app":  app,
	}

	if h.opts.LogQuerier == nil {
		resp["lines"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "Log querying requires in-cluster deployment with Loki (set LOKI_URL)"
		writeJSON(w, http.StatusOK, resp)
		return
	}

	logLines, err := h.opts.LogQuerier.QueryRange(r.Context(), team, app, lines, since)
	if err != nil {
		resp["lines"] = []interface{}{}
		resp["count"] = 0
		resp["note"] = "Loki query error: " + err.Error()
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp["lines"] = logLines
	resp["count"] = len(logLines)
	writeJSON(w, http.StatusOK, resp)
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
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
