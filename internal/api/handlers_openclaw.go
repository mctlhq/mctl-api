package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"k8s.io/apimachinery/pkg/api/resource"
)

type openClawDeployStartRequest struct {
	TeamName        string `json:"team_name"`
	ComponentName   string `json:"component_name"`
	TelegramOwnerID string `json:"telegram_owner_id"`
	DefaultModel    string `json:"default_model"`
	Host            string `json:"host"`
}

type openClawDeployResumeRequest struct {
	TeamName        string `json:"team_name"`
	ComponentName   string `json:"component_name"`
	TelegramOwnerID string `json:"telegram_owner_id"`
	DefaultModel    string `json:"default_model"`
	Host            string `json:"host"`
}

type openClawApplyProfileRequest struct {
	Profile string `json:"profile"`
}

type openClawResourceProfile struct {
	Name            string
	RequestCPU      string
	RequestMemory   string
	LimitCPU        string
	LimitMemory     string
	NodeMaxOldSpace string
}

var openClawProfiles = map[string]openClawResourceProfile{
	"startup": {
		Name:            "startup",
		RequestCPU:      "500m",
		RequestMemory:   "1Gi",
		LimitCPU:        "2",
		LimitMemory:     "4Gi",
		NodeMaxOldSpace: "3072",
	},
	"steady-medium": {
		Name:            "steady-medium",
		RequestCPU:      "350m",
		RequestMemory:   "768Mi",
		LimitCPU:        "1500m",
		LimitMemory:     "3Gi",
		NodeMaxOldSpace: "2560",
	},
	"steady-small": {
		Name:            "steady-small",
		RequestCPU:      "250m",
		RequestMemory:   "512Mi",
		LimitCPU:        "1",
		LimitMemory:     "2Gi",
		NodeMaxOldSpace: "1536",
	},
}

func (h *Handlers) StartOpenClawDeploy(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req openClawDeployStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	normalizeOpenClawRequest(&req.TeamName, &req.ComponentName, &req.TelegramOwnerID, &req.DefaultModel, &req.Host)
	if req.ComponentName == "" {
		req.ComponentName = "openclaw"
	}
	if req.DefaultModel == "" {
		req.DefaultModel = "openai-codex/gpt-5.4"
	}
	if req.Host == "" {
		req.Host = defaultOpenClawHost(req.TeamName, req.ComponentName)
	}

	tenant, denied := h.requireOpenClawOwner(w, r, user, req.TeamName)
	if denied {
		return
	}
	if errs := validateOpenClawPreflight(tenant); len(errs) > 0 {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error":             "tenant does not meet the OpenClaw startup profile requirements",
			"requiredProfile":   openClawProfiles["startup"],
			"quotaRequirements": errs,
		})
		return
	}
	if _, err := h.opts.GitReader.GetService(req.TeamName, req.ComponentName); err == nil {
		writeError(w, http.StatusConflict, "service already exists: "+req.TeamName+"/"+req.ComponentName)
		return
	}

	intakeURL := h.openClawIntakeURL(req.TeamName, req.ComponentName, req.Host)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"teamName":          req.TeamName,
		"componentName":     req.ComponentName,
		"telegramOwnerID":   req.TelegramOwnerID,
		"defaultModel":      req.DefaultModel,
		"dashboardURL":      "https://" + req.Host + "/",
		"botTokenIntakeURL": intakeURL,
		"nextStep":          "Open the intake URL, save the Telegram bot token there, then call resume-openclaw-deploy.",
		"startupProfile":    openClawProfiles["startup"],
	})
}

func (h *Handlers) ResumeOpenClawDeploy(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req openClawDeployResumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	normalizeOpenClawRequest(&req.TeamName, &req.ComponentName, &req.TelegramOwnerID, &req.DefaultModel, &req.Host)
	if req.ComponentName == "" {
		req.ComponentName = "openclaw"
	}
	if req.DefaultModel == "" {
		req.DefaultModel = "openai-codex/gpt-5.4"
	}
	if req.Host == "" {
		req.Host = defaultOpenClawHost(req.TeamName, req.ComponentName)
	}

	tenant, denied := h.requireOpenClawOwner(w, r, user, req.TeamName)
	if denied {
		return
	}
	if errs := validateOpenClawPreflight(tenant); len(errs) > 0 {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error":             "tenant does not meet the OpenClaw startup profile requirements",
			"requiredProfile":   openClawProfiles["startup"],
			"quotaRequirements": errs,
		})
		return
	}
	if h.opts.VaultReader == nil {
		writeError(w, http.StatusServiceUnavailable, "vault reader is not configured")
		return
	}

	secretPath := fmt.Sprintf("teams/%s/%s/telegram", req.TeamName, req.ComponentName)
	secretData, err := h.opts.VaultReader.ReadKV(r.Context(), secretPath)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to check Telegram bot token in Vault: "+err.Error())
		return
	}
	if secretData == nil || strings.TrimSpace(secretData["telegram-bot-token"]) == "" {
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error":             "Telegram bot token has not been saved yet",
			"botTokenIntakeURL": h.openClawIntakeURL(req.TeamName, req.ComponentName, req.Host),
		})
		return
	}

	op, ok := h.opts.Registry.Get("deploy-service")
	if !ok {
		writeError(w, http.StatusInternalServerError, "deploy-service operation is not registered")
		return
	}
	params := map[string]string{
		"action":            "onboard",
		"team_name":         req.TeamName,
		"component_name":    req.ComponentName,
		"component_type":    "base-service",
		"service_template":  "openclaw",
		"host":              req.Host,
		"port":              "18789",
		"default_model":     req.DefaultModel,
		"telegram_owner_id": req.TelegramOwnerID,
	}
	params = h.opts.Registry.ApplyDefaults(op, params)
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed",
			"validationErrors": errs,
		})
		return
	}

	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, req.TeamName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"workflow":     result,
		"dashboardURL": "https://" + req.Host + "/",
		"message":      "OpenClaw onboarding submitted. Open the dashboard after rollout, then connect OpenAI Codex from the Control UI or chat.",
	})
}

func (h *Handlers) GetOpenClawSizingRecommendation(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")
	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if _, err := h.opts.GitReader.GetService(team, app); err != nil {
		writeError(w, http.StatusNotFound, "service not found: "+team+"/"+app)
		return
	}

	lookback := 24 * time.Hour
	if raw := strings.TrimSpace(r.URL.Query().Get("lookback_hours")); raw != "" {
		hours, err := strconv.Atoi(raw)
		if err != nil || hours <= 0 {
			writeError(w, http.StatusBadRequest, "lookback_hours must be a positive integer")
			return
		}
		lookback = time.Duration(hours) * time.Hour
	}

	if h.opts.MetricsQuerier == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"profile": openClawProfiles["startup"].Name,
			"stats":   ContainerUsageStats{},
			"note":    "VictoriaMetrics is not configured; defaulting to startup profile.",
		})
		return
	}

	stats, err := h.opts.MetricsQuerier.GetContainerUsage(r.Context(), team, app, "base-service", lookback)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to read VictoriaMetrics data: "+err.Error())
		return
	}
	profile := recommendOpenClawProfile(stats)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profile":       profile.Name,
		"profileSpec":   profile,
		"stats":         stats,
		"lookbackHours": int(lookback / time.Hour),
		"policy":        "deploy with startup, then explicitly trim after at least 24h of stable runtime",
	})
}

func (h *Handlers) ApplyOpenClawResourceProfile(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	team := chi.URLParam(r, "team")
	app := chi.URLParam(r, "app")
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}
	if _, err := h.opts.GitReader.GetService(team, app); err != nil {
		writeError(w, http.StatusNotFound, "service not found: "+team+"/"+app)
		return
	}

	var req openClawApplyProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	profile, ok := openClawProfiles[strings.TrimSpace(req.Profile)]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":    "unknown profile",
			"profiles": []string{"startup", "steady-medium", "steady-small"},
		})
		return
	}

	op, ok := h.opts.Registry.Get("deploy-service")
	if !ok {
		writeError(w, http.StatusInternalServerError, "deploy-service operation is not registered")
		return
	}
	params := map[string]string{
		"action":         "update-config",
		"team_name":      team,
		"component_name": app,
		"config_patch":   openClawConfigPatch(profile),
	}
	params = h.opts.Registry.ApplyDefaults(op, params)
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "validation failed",
			"validationErrors": errs,
		})
		return
	}

	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, team)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"workflow": result,
		"profile":  profile,
		"message":  "Resource profile update submitted.",
	})
}

func (h *Handlers) requireOpenClawOwner(w http.ResponseWriter, r *http.Request, user *auth.User, team string) (*gitops.Tenant, bool) {
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, true
	}
	if !user.IsAdmin() && !user.HasTenantAccess(team) {
		writeError(w, http.StatusForbidden, "access denied")
		return nil, true
	}

	tenant, err := h.opts.GitReader.GetTenant(team)
	if err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+team)
		return nil, true
	}
	if user.IsAdmin() {
		return tenant, false
	}
	for _, member := range tenant.Members {
		if strings.EqualFold(member.UserID, user.ID) && strings.EqualFold(member.Role, "owner") {
			return tenant, false
		}
	}
	writeError(w, http.StatusForbidden, "owner role is required for this OpenClaw action")
	return nil, true
}

func validateOpenClawPreflight(tenant *gitops.Tenant) []map[string]string {
	var issues []map[string]string
	required := openClawProfiles["startup"]

	if q := tenant.Quotas["limits.cpu"]; q != "" && quantityLessThan(q, required.LimitCPU) {
		issues = append(issues, map[string]string{"field": "limits.cpu", "required": required.LimitCPU, "actual": q})
	}
	if q := tenant.Quotas["limits.memory"]; q != "" && quantityLessThan(q, required.LimitMemory) {
		issues = append(issues, map[string]string{"field": "limits.memory", "required": required.LimitMemory, "actual": q})
	}
	if tenant.Networking != nil && !tenant.Networking["allowInternetEgress"] {
		issues = append(issues, map[string]string{"field": "networking.allowInternetEgress", "required": "true", "actual": "false"})
	}
	return issues
}

func quantityLessThan(actual, required string) bool {
	a, errA := resource.ParseQuantity(actual)
	r, errR := resource.ParseQuantity(required)
	if errA != nil || errR != nil {
		return false
	}
	return a.Cmp(r) < 0
}

func normalizeOpenClawRequest(fields ...*string) {
	for _, field := range fields {
		if field == nil {
			continue
		}
		*field = strings.TrimSpace(*field)
	}
}

func defaultOpenClawHost(team, app string) string {
	return fmt.Sprintf("%s-%s.mctl.ai", team, app)
}

func (h *Handlers) openClawIntakeURL(team, app, host string) string {
	base := strings.TrimRight(h.opts.BackstageURL, "/")
	if base == "" {
		base = "https://app.mctl.ai"
	}
	q := url.Values{}
	q.Set("team", team)
	q.Set("service", app)
	q.Set("returnTo", "https://"+host+"/")
	return base + "/api/vault-secrets/openclaw/intake?" + q.Encode()
}

func recommendOpenClawProfile(stats ContainerUsageStats) openClawResourceProfile {
	switch {
	case stats.MemoryMaxBytes >= 2.3*1024*1024*1024 || stats.CPUMaxCores >= 1.2:
		return openClawProfiles["startup"]
	case stats.MemoryP95Bytes >= 1.3*1024*1024*1024 || stats.CPUP95Cores >= 0.7:
		return openClawProfiles["steady-medium"]
	default:
		return openClawProfiles["steady-small"]
	}
}

func openClawConfigPatch(profile openClawResourceProfile) string {
	return fmt.Sprintf(
		`.resources.requests.cpu = %q | .resources.requests.memory = %q | .resources.limits.cpu = %q | .resources.limits.memory = %q | .env.NODE_OPTIONS = "--max-old-space-size=%s"`,
		profile.RequestCPU,
		profile.RequestMemory,
		profile.LimitCPU,
		profile.LimitMemory,
		profile.NodeMaxOldSpace,
	)
}
