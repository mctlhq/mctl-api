package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/secretscan"
)

var platformSkillNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

type platformSkillPublishRequest struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Visibility  string   `json:"visibility"`
	Status      string   `json:"status"`
	Owner       string   `json:"owner"`
	Runtimes    []string `json:"runtimes"`
	Content     string   `json:"content"`
}

type platformSkillTenantBindingRequest struct {
	Tenant string `json:"tenant"`
	Skill  string `json:"skill"`
}

// ListPlatformSkills returns the platform-wide skill catalog filtered to the caller.
func (h *Handlers) ListPlatformSkills(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	skills, err := h.opts.GitReader.ListPlatformSkills()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list platform skills: "+err.Error())
		return
	}
	tenantBindings, err := h.opts.GitReader.ListPlatformTenantBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenant skill bindings: "+err.Error())
		return
	}
	roleBindings, err := h.opts.GitReader.ListPlatformRoleBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list role skill bindings: "+err.Error())
		return
	}
	access := platformSkillAccess{user: user, tenantBindings: tenantBindings, roleBindings: roleBindings}
	items := make([]gitops.PlatformSkill, 0, len(skills))
	for i := range skills {
		if access.canList(skills[i]) {
			items = append(items, skills[i])
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"count": len(items),
	})
}

// ReadPlatformSkill returns metadata plus SKILL.md content if the caller can access it.
func (h *Handlers) ReadPlatformSkill(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if !platformSkillNamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid skill name")
		return
	}
	skill, content, err := h.opts.GitReader.GetPlatformSkill(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "platform skill not found: "+name)
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to read platform skill: "+err.Error())
		return
	}
	tenantBindings, err := h.opts.GitReader.ListPlatformTenantBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenant skill bindings: "+err.Error())
		return
	}
	roleBindings, err := h.opts.GitReader.ListPlatformRoleBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list role skill bindings: "+err.Error())
		return
	}
	access := platformSkillAccess{user: user, tenantBindings: tenantBindings, roleBindings: roleBindings}
	if !access.canRead(*skill) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"metadata": skill.Metadata,
		"content":  content,
	})
}

// ListTenantSkillBindings returns tenant bindings. Admins see all; tenant members see their own.
func (h *Handlers) ListTenantSkillBindings(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	bindings, err := h.opts.GitReader.ListPlatformTenantBindings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenant skill bindings: "+err.Error())
		return
	}
	items := make([]gitops.PlatformSkillBinding, 0, len(bindings))
	for _, binding := range bindings {
		if user.IsAdmin() || user.HasTenantAccess(binding.Tenant) {
			items = append(items, binding)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "count": len(items)})
}

// EnableTenantSkill submits a workflow to add a tenant binding in mctl-gitops.
func (h *Handlers) EnableTenantSkill(w http.ResponseWriter, r *http.Request) {
	h.submitTenantSkillBindingChange(w, r, "platform-skill-enable")
}

// DisableTenantSkill submits a workflow to remove a tenant binding in mctl-gitops.
func (h *Handlers) DisableTenantSkill(w http.ResponseWriter, r *http.Request) {
	h.submitTenantSkillBindingChange(w, r, "platform-skill-disable")
}

func (h *Handlers) submitTenantSkillBindingChange(w http.ResponseWriter, r *http.Request, opName string) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req platformSkillTenantBindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.Tenant = strings.TrimSpace(req.Tenant)
	req.Skill = strings.TrimSpace(req.Skill)
	if !platformSkillNamePattern.MatchString(req.Tenant) || !platformSkillNamePattern.MatchString(req.Skill) {
		writeError(w, http.StatusBadRequest, "tenant and skill must be kebab-case")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "operation requires admin group membership")
		return
	}
	if _, err := h.opts.GitReader.GetTenant(req.Tenant); err != nil {
		writeError(w, http.StatusNotFound, "tenant not found: "+req.Tenant)
		return
	}
	if opName == "platform-skill-enable" {
		skill, _, err := h.opts.GitReader.GetPlatformSkill(req.Skill)
		if err != nil {
			writeError(w, http.StatusNotFound, "platform skill not found: "+req.Skill)
			return
		}
		if err := h.validateTenantSkillEnable(req.Tenant, *skill); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	op, ok := h.opts.Registry.Get(opName)
	if !ok {
		writeError(w, http.StatusInternalServerError, opName+" operation is not registered")
		return
	}
	params := h.opts.Registry.ApplyDefaults(op, map[string]string{
		"tenant_name": req.Tenant,
		"skill_name":  req.Skill,
		"actor":       user.ID,
	})
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "validation failed", "validationErrors": errs})
		return
	}
	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, "platform")
	if err != nil {
		h.opts.AuditLog.Log(audit.Entry{
			UserID:     user.ID,
			Operation:  opName,
			Parameters: params,
			Status:     "failed",
			RiskLevel:  string(op.RiskLevel),
			Message:    "submit failed: " + err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}
	h.opts.AuditLog.Log(audit.Entry{
		UserID:       user.ID,
		Operation:    opName,
		Parameters:   params,
		WorkflowName: result.WorkflowName,
		Status:       "submitted",
		RiskLevel:    string(op.RiskLevel),
	})
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"operation": opName, "workflow": result})
}

// PublishPlatformSkill submits a workflow to create or update a catalog skill.
func (h *Handlers) PublishPlatformSkill(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "operation requires admin group membership")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var req platformSkillPublishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !platformSkillNamePattern.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "invalid skill name")
		return
	}
	if req.Status == "" {
		req.Status = "active"
	}
	if req.Visibility == "" {
		req.Visibility = "tenant"
	}
	meta := gitops.PlatformSkillMetadata{
		Name: req.Name, Title: req.Title, Description: req.Description,
		Visibility: req.Visibility, Status: req.Status, Owner: req.Owner, Runtimes: req.Runtimes,
	}
	if err := validatePlatformSkillForPublish(meta); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeError(w, http.StatusBadRequest, "content must not be empty")
		return
	}
	if pattern, found := secretscan.Scan([]byte(req.Content)); found {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("content appears to contain a secret (matched pattern: %s)", pattern))
		return
	}
	metadata, err := json.Marshal(meta)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode metadata")
		return
	}
	op, ok := h.opts.Registry.Get("platform-skill-publish")
	if !ok {
		writeError(w, http.StatusInternalServerError, "platform-skill-publish operation is not registered")
		return
	}
	params := h.opts.Registry.ApplyDefaults(op, map[string]string{
		"skill_name":   req.Name,
		"metadata_b64": base64.StdEncoding.EncodeToString(metadata),
		"content_b64":  base64.StdEncoding.EncodeToString([]byte(req.Content)),
		"actor":        user.ID,
	})
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "validation failed", "validationErrors": errs})
		return
	}
	auditParams := map[string]string{"skill_name": req.Name, "actor": user.ID}
	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, "platform")
	if err != nil {
		h.opts.AuditLog.Log(audit.Entry{
			UserID:     user.ID,
			Operation:  "platform-skill-publish",
			Parameters: auditParams,
			Status:     "failed",
			RiskLevel:  string(op.RiskLevel),
			Message:    "submit failed: " + err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}
	h.opts.AuditLog.Log(audit.Entry{
		UserID:       user.ID,
		Operation:    "platform-skill-publish",
		Parameters:   auditParams,
		WorkflowName: result.WorkflowName,
		Status:       "submitted",
		RiskLevel:    string(op.RiskLevel),
	})
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"operation": "platform-skill-publish", "workflow": result})
}

// DeprecatePlatformSkill submits a workflow to mark a skill deprecated.
func (h *Handlers) DeprecatePlatformSkill(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "operation requires admin group membership")
		return
	}
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if !platformSkillNamePattern.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid skill name")
		return
	}
	if _, _, err := h.opts.GitReader.GetPlatformSkill(name); err != nil {
		writeError(w, http.StatusNotFound, "platform skill not found: "+name)
		return
	}
	op, ok := h.opts.Registry.Get("platform-skill-deprecate")
	if !ok {
		writeError(w, http.StatusInternalServerError, "platform-skill-deprecate operation is not registered")
		return
	}
	params := h.opts.Registry.ApplyDefaults(op, map[string]string{"skill_name": name, "actor": user.ID})
	if errs := h.opts.Registry.ValidateInput(op, params); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "validation failed", "validationErrors": errs})
		return
	}
	result, err := h.opts.Executor.Submit(r.Context(), op, params, user.ID, "platform")
	if err != nil {
		h.opts.AuditLog.Log(audit.Entry{
			UserID:     user.ID,
			Operation:  "platform-skill-deprecate",
			Parameters: params,
			Status:     "failed",
			RiskLevel:  string(op.RiskLevel),
			Message:    "submit failed: " + err.Error(),
		})
		writeError(w, http.StatusInternalServerError, "failed to submit workflow: "+err.Error())
		return
	}
	h.opts.AuditLog.Log(audit.Entry{
		UserID:       user.ID,
		Operation:    "platform-skill-deprecate",
		Parameters:   params,
		WorkflowName: result.WorkflowName,
		Status:       "submitted",
		RiskLevel:    string(op.RiskLevel),
	})
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"operation": "platform-skill-deprecate", "workflow": result})
}

func (h *Handlers) validateTenantSkillEnable(tenant string, skill gitops.PlatformSkill) error {
	if skill.Metadata.Status == "deprecated" {
		return fmt.Errorf("deprecated skill cannot be enabled for new tenants")
	}
	if skill.Metadata.Status != "active" {
		return fmt.Errorf("only active skills can be enabled")
	}
	if skill.Metadata.Visibility != "tenant" {
		return fmt.Errorf("tenant can only enable skills with tenant visibility")
	}
	policy, err := h.opts.GitReader.GetPlatformPolicy()
	if err != nil {
		return err
	}
	if denied := policy.TenantDenylist[tenant]; containsString(denied, skill.Metadata.Name) {
		return fmt.Errorf("skill %q is denied for tenant %q by policy", skill.Metadata.Name, tenant)
	}
	// An absent tenant key means unrestricted; a present key — even an empty
	// list — is an exhaustive allowlist (deny-all when empty). Must match the
	// materializer semantics in mctl-gitops/scripts/materialize-openclaw-platform-skills.py.
	if allowed, ok := policy.TenantAllowlist[tenant]; ok && !containsString(allowed, skill.Metadata.Name) {
		return fmt.Errorf("skill %q is not allowed for tenant %q by policy", skill.Metadata.Name, tenant)
	}
	return nil
}

func validatePlatformSkillForPublish(meta gitops.PlatformSkillMetadata) error {
	if strings.TrimSpace(meta.Title) == "" || strings.TrimSpace(meta.Description) == "" || strings.TrimSpace(meta.Owner) == "" {
		return fmt.Errorf("title, description, and owner are required")
	}
	if !containsString([]string{"public", "tenant", "admin", "platform-internal"}, meta.Visibility) {
		return fmt.Errorf("visibility must be one of public, tenant, admin, platform-internal")
	}
	if !containsString([]string{"draft", "active", "deprecated"}, meta.Status) {
		return fmt.Errorf("status must be one of draft, active, deprecated")
	}
	return nil
}

type platformSkillAccess struct {
	user           *auth.User
	tenantBindings []gitops.PlatformSkillBinding
	roleBindings   []gitops.PlatformSkillBinding
}

func (a platformSkillAccess) canList(skill gitops.PlatformSkill) bool {
	if skill.Metadata.Visibility == "platform-internal" {
		return false
	}
	if skill.Metadata.Status == "draft" {
		return a.user.IsAdmin()
	}
	return a.canRead(skill)
}

func (a platformSkillAccess) canRead(skill gitops.PlatformSkill) bool {
	if skill.Metadata.Visibility == "platform-internal" {
		return false
	}
	if a.user.IsAdmin() {
		return skill.Metadata.Visibility == "public" || skill.Metadata.Visibility == "admin" || skill.Metadata.Visibility == "tenant" || skill.Metadata.Status == "draft"
	}
	switch skill.Metadata.Visibility {
	case "public":
		return skill.Metadata.Status == "active" || skill.Metadata.Status == "deprecated"
	case "tenant":
		if skill.Metadata.Status != "active" && skill.Metadata.Status != "deprecated" {
			return false
		}
		return a.enabledForUserTenant(skill.Metadata.Name)
	default:
		return false
	}
}

func (a platformSkillAccess) enabledForUserTenant(skillName string) bool {
	for _, binding := range a.tenantBindings {
		if !a.user.HasTenantAccess(binding.Tenant) {
			continue
		}
		if containsString(binding.EnabledSkills, skillName) {
			return true
		}
	}
	for _, binding := range a.roleBindings {
		if !containsString(a.user.Groups, binding.Role) {
			continue
		}
		if containsString(binding.EnabledSkills, skillName) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
