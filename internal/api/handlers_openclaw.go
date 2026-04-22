package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/secretscan"
	"k8s.io/apimachinery/pkg/api/resource"
)

// openClawSkillNamePattern matches 2-64 char kebab-case names that start and end with an alphanumeric.
// Matches the same regex enforced by the openclaw-skill-save workflow template as defense-in-depth.
var openClawSkillNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

// telegramOwnerIDPattern matches a numeric Telegram user ID (1-20 digits).
var telegramOwnerIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)

// Per-skill size cap is now configurable via the OpenClawQuotaConfig on the
// router Options (chart values openclaw.skills.maxPerSkillBytes). The legacy
// constant has been removed — runtime calls read h.openClawQuota directly.

// parseTelegramOwnerIDs accepts the comma-separated MCP-friendly form plus
// the legacy single-ID field and returns the canonical []string + a JSON-
// encoded array string ready to ship as an Argo workflow parameter.
// Callers pass the preferred comma-separated string first, then the legacy
// single ID as a fallback. Returns an error if any ID fails numeric
// validation or if the combined list is empty.
func parseTelegramOwnerIDs(preferred, legacy string) ([]string, string, error) {
	var raw []string
	if preferred = strings.TrimSpace(preferred); preferred != "" {
		for _, part := range strings.Split(preferred, ",") {
			if part = strings.TrimSpace(part); part != "" {
				raw = append(raw, part)
			}
		}
	} else if legacy = strings.TrimSpace(legacy); legacy != "" {
		raw = []string{legacy}
	}
	if len(raw) == 0 {
		return nil, "", fmt.Errorf("at least one Telegram owner ID is required")
	}
	seen := make(map[string]struct{}, len(raw))
	dedup := make([]string, 0, len(raw))
	for _, id := range raw {
		if !telegramOwnerIDPattern.MatchString(id) {
			return nil, "", fmt.Errorf("invalid Telegram owner ID: %q (must be numeric, 1-20 digits)", id)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		dedup = append(dedup, id)
	}
	encoded, err := json.Marshal(dedup)
	if err != nil {
		return nil, "", fmt.Errorf("encode telegram owner ids: %w", err)
	}
	return dedup, string(encoded), nil
}

type openClawDeployStartRequest struct {
	TeamName         string `json:"team_name"`
	ComponentName    string `json:"component_name"`
	TelegramOwnerID  string `json:"telegram_owner_id"`  // deprecated; prefer telegram_owner_ids
	TelegramOwnerIDs string `json:"telegram_owner_ids"` // comma-separated list
	DefaultModel     string `json:"default_model"`
	Host             string `json:"host"`
}

type openClawDeployResumeRequest struct {
	TeamName         string `json:"team_name"`
	ComponentName    string `json:"component_name"`
	TelegramOwnerID  string `json:"telegram_owner_id"`  // deprecated; prefer telegram_owner_ids
	TelegramOwnerIDs string `json:"telegram_owner_ids"` // comma-separated list
	DefaultModel     string `json:"default_model"`
	Host             string `json:"host"`
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
		RequestMemory:   "1Gi",
		LimitCPU:        "1500m",
		LimitMemory:     "3Gi",
		NodeMaxOldSpace: "2048",
	},
	"steady-small": {
		Name:            "steady-small",
		RequestCPU:      "250m",
		RequestMemory:   "768Mi",
		LimitCPU:        "1",
		LimitMemory:     "2560Mi",
		NodeMaxOldSpace: "1792",
	},
}

var openClawStartupQuotaFloor = map[string]string{
	"requests.cpu":                   "500m",
	"requests.memory":                "1280Mi",
	"limits.cpu":                     "3",
	"limits.memory":                  "4Gi",
	"networking.allowInternetEgress": "true",
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
	normalizeOpenClawRequest(&req.TeamName, &req.ComponentName, &req.TelegramOwnerID, &req.TelegramOwnerIDs, &req.DefaultModel, &req.Host)
	if req.ComponentName == "" {
		req.ComponentName = "openclaw"
	}
	if req.DefaultModel == "" {
		req.DefaultModel = "openai-codex/gpt-5.4"
	}
	if req.Host == "" {
		req.Host = defaultOpenClawHost(req.TeamName, req.ComponentName)
	}

	ownerIDs, _, err := parseTelegramOwnerIDs(req.TelegramOwnerIDs, req.TelegramOwnerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
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
		"telegramOwnerIDs":  ownerIDs,
		"defaultModel":      req.DefaultModel,
		"dashboardURL":      "https://" + req.Host + "/",
		"botTokenIntakeURL": intakeURL,
		"nextStep":          "Open the intake URL, save the Telegram bot token there, then call resume-openclaw-deploy.",
		"startupProfile":    openClawProfiles["startup"],
		"quotaFloor":        openClawStartupQuotaFloor,
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
	normalizeOpenClawRequest(&req.TeamName, &req.ComponentName, &req.TelegramOwnerID, &req.TelegramOwnerIDs, &req.DefaultModel, &req.Host)
	if req.ComponentName == "" {
		req.ComponentName = "openclaw"
	}
	if req.DefaultModel == "" {
		req.DefaultModel = "openai-codex/gpt-5.4"
	}
	if req.Host == "" {
		req.Host = defaultOpenClawHost(req.TeamName, req.ComponentName)
	}

	ownerIDs, ownerIDsJSON, parseErr := parseTelegramOwnerIDs(req.TelegramOwnerIDs, req.TelegramOwnerID)
	if parseErr != nil {
		writeError(w, http.StatusBadRequest, parseErr.Error())
		return
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

	provisionOp, ok := h.opts.Registry.Get("provision-database")
	if !ok {
		writeError(w, http.StatusInternalServerError, "provision-database operation is not registered")
		return
	}
	provisionParams := map[string]string{
		"team_name": req.TeamName,
		"app_name":  req.ComponentName,
	}
	provisionParams = h.opts.Registry.ApplyDefaults(provisionOp, provisionParams)
	if errs := h.opts.Registry.ValidateInput(provisionOp, provisionParams); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":            "database validation failed",
			"validationErrors": errs,
		})
		return
	}
	dbResult, err := h.opts.Executor.Submit(r.Context(), provisionOp, provisionParams, user.ID, req.TeamName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to submit database workflow: "+err.Error())
		return
	}

	op, ok := h.opts.Registry.Get("deploy-service")
	if !ok {
		writeError(w, http.StatusInternalServerError, "deploy-service operation is not registered")
		return
	}
	params := map[string]string{
		"action":                  "onboard",
		"team_name":               req.TeamName,
		"component_name":          req.ComponentName,
		"component_type":          "base-service",
		"dockerfile_repo":         "mctlhq/mctl-openclaw",
		"service_template":        "openclaw",
		"host":                    req.Host,
		"port":                    "18789",
		"default_model":           req.DefaultModel,
		"telegram_owner_id":       ownerIDs[0], // deprecated: kept for backward-compat with older tpl-git-commit
		"telegram_owner_ids_json": ownerIDsJSON,
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
		"workflow":         result,
		"databaseWorkflow": dbResult,
		"dashboardURL":     "https://" + req.Host + "/",
		"message":          "OpenClaw onboarding submitted. Database provisioning was started first, then the service deploy.",
		"nextSteps": []string{
			"Open the dashboard after rollout.",
			"To connect Codex, use Overview -> Connect OpenAI Codex.",
			"Or in the OpenClaw chat, type: /connect codex",
		},
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
	if q := tenant.Quotas["requests.cpu"]; q != "" && quantityLessThan(q, openClawStartupQuotaFloor["requests.cpu"]) {
		issues = append(issues, map[string]string{"field": "requests.cpu", "required": openClawStartupQuotaFloor["requests.cpu"], "actual": q})
	}
	if q := tenant.Quotas["requests.memory"]; q != "" && quantityLessThan(q, openClawStartupQuotaFloor["requests.memory"]) {
		issues = append(issues, map[string]string{"field": "requests.memory", "required": openClawStartupQuotaFloor["requests.memory"], "actual": q})
	}
	if q := tenant.Quotas["limits.cpu"]; q != "" && quantityLessThan(q, openClawStartupQuotaFloor["limits.cpu"]) {
		issues = append(issues, map[string]string{"field": "limits.cpu", "required": openClawStartupQuotaFloor["limits.cpu"], "actual": q})
	}
	if q := tenant.Quotas["limits.memory"]; q != "" && quantityLessThan(q, openClawStartupQuotaFloor["limits.memory"]) {
		issues = append(issues, map[string]string{"field": "limits.memory", "required": openClawStartupQuotaFloor["limits.memory"], "actual": q})
	}
	if tenant.Networking != nil && !tenant.Networking["allowInternetEgress"] {
		issues = append(issues, map[string]string{"field": "networking.allowInternetEgress", "required": openClawStartupQuotaFloor["networking.allowInternetEgress"], "actual": "false"})
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

// validateOpenClawSkillName returns nil when name is a safe kebab-case identifier.
func validateOpenClawSkillName(name string) error {
	if name == "" {
		return errors.New("skill name is required")
	}
	if !openClawSkillNamePattern.MatchString(name) {
		return errors.New("skill name must be 1-64 chars, kebab-case (lowercase letters, digits, hyphens), starting and ending with an alphanumeric")
	}
	return nil
}

type openClawSkillSaveRequest struct {
	SkillName string `json:"skill_name"`
	Content   string `json:"content"`
}

// ListOpenClawSkills returns the set of skills backed up in gitops for a team.
// GET /api/v1/openclaw/{team}/skills
func (h *Handlers) ListOpenClawSkills(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	skills, err := h.opts.GitReader.ListOpenClawSkills(team)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list skills: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"team":   team,
		"skills": skills,
	})
}

// GetOpenClawSkill returns the raw content of a single SKILL.md backed up in gitops.
// GET /api/v1/openclaw/{team}/skills/{name}
func (h *Handlers) GetOpenClawSkill(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if err := validateOpenClawSkillName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	content, err := h.opts.GitReader.ReadOpenClawSkill(team, name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "skill not found: "+name)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read skill: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"team":    team,
		"name":    name,
		"content": content,
	})
}

// SaveOpenClawSkill submits the openclaw-skill-save workflow which writes the
// SKILL.md file to the gitops repo as a durable backup.
// POST /api/v1/openclaw/{team}/skills (body: {skill_name, content})
func (h *Handlers) SaveOpenClawSkill(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))

	// Gate on ownership before any body parsing or validation so unauthorized
	// callers don't get to probe payload-size or name-format behavior.
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	perSkillCap := h.openClawQuota.MaxPerSkillBytes
	r.Body = http.MaxBytesReader(w, r.Body, int64(perSkillCap)+4*1024)
	var req openClawSkillSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", perSkillCap))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.SkillName = strings.TrimSpace(req.SkillName)
	if err := validateOpenClawSkillName(req.SkillName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "content must not be empty")
		return
	}
	if len(req.Content) > perSkillCap {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("content exceeds %d bytes", perSkillCap))
		return
	}

	// Secret-pattern scan happens before any gitops lookup / workflow submit
	// so a leaked credential never reaches the commit actor's git log.
	if pattern, found := secretscan.Scan([]byte(req.Content)); found {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("content appears to contain a secret (matched pattern: %s); skills/identity files must not embed credentials — use mctl_* runtime tools instead", pattern))
		return
	}

	// Enforce tenant-wide caps before spending a workflow submission.
	// Sum + count existing skills via the cached gitops reader (cheap).
	existing, listErr := h.opts.GitReader.ListOpenClawSkills(team)
	if listErr != nil {
		writeError(w, http.StatusInternalServerError, "failed to read existing skills for quota check: "+listErr.Error())
		return
	}
	var existingBytes int
	var updatingExisting bool
	for _, s := range existing {
		if s.Name == req.SkillName {
			updatingExisting = true
			continue // exclude from existing total — this save will replace it
		}
		existingBytes += int(s.Size)
	}
	if !updatingExisting && len(existing) >= h.openClawQuota.MaxSkillsPerTenant {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("skill count limit reached (%d of %d used for team %q); delete an unused skill with mctl_delete_openclaw_skill before saving a new one", len(existing), h.openClawQuota.MaxSkillsPerTenant, team))
		return
	}
	projected := existingBytes + len(req.Content) + len(req.SkillName)
	if projected > h.openClawQuota.MaxSkillsTotalBytes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("per-tenant skill ConfigMap size limit would be exceeded (current %d bytes + new %d bytes > cap %d bytes for team %q)", existingBytes, len(req.Content)+len(req.SkillName), h.openClawQuota.MaxSkillsTotalBytes, team))
		return
	}

	// Rate limit applies per (team, actor) and is shared with identity writes.
	rateKey := openClawRateKey(team, user.ID)
	if allowed, retryAfter := h.openClawRateLimiter.Allow(rateKey); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("save rate limit exceeded for team %q (cap: %d writes/hour per user across skill + identity)", team, h.openClawQuota.SaveRatePerHour))
		return
	}

	op, ok := h.opts.Registry.Get("openclaw-skill-save")
	if !ok {
		writeError(w, http.StatusInternalServerError, "openclaw-skill-save operation is not registered")
		return
	}
	params := map[string]string{
		"team_name":   team,
		"skill_name":  req.SkillName,
		"content_b64": base64.StdEncoding.EncodeToString([]byte(req.Content)),
		"actor":       user.ID,
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
		"team":     team,
		"name":     req.SkillName,
		"message":  "Skill save submitted. Wait for the workflow to succeed before the commit lands in gitops.",
	})
}

// openClawRateKey builds the composite rate-limit key used by both skill and
// identity save/delete handlers — callers share a single budget so a user
// can't double it by alternating between write paths.
func openClawRateKey(team, userID string) string {
	return team + "|" + userID
}

// DeleteOpenClawSkill submits the openclaw-skill-delete workflow which removes
// the SKILL.md file from the gitops backup.
// DELETE /api/v1/openclaw/{team}/skills/{name}
func (h *Handlers) DeleteOpenClawSkill(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	team := strings.TrimSpace(chi.URLParam(r, "team"))
	if _, denied := h.requireOpenClawOwner(w, r, user, team); denied {
		return
	}

	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if err := validateOpenClawSkillName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	op, ok := h.opts.Registry.Get("openclaw-skill-delete")
	if !ok {
		writeError(w, http.StatusInternalServerError, "openclaw-skill-delete operation is not registered")
		return
	}
	params := map[string]string{
		"team_name":  team,
		"skill_name": name,
		"actor":      user.ID,
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
		"team":     team,
		"name":     name,
		"message":  "Skill delete submitted.",
	})
}
