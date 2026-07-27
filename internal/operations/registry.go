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

import "regexp"

// Registry holds all available platform operations mapped to Argo WorkflowTemplates.
type Registry struct {
	ops map[string]Operation
}

// RiskLevel indicates how dangerous an operation is.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// Operation defines a platform operation backed by an Argo WorkflowTemplate.
type Operation struct {
	Name             string         `json:"name"`
	DisplayName      string         `json:"displayName"`
	Description      string         `json:"description"`
	WorkflowTemplate string         `json:"workflowTemplate"` // ClusterWorkflowTemplate name
	Parameters       []ParameterDef `json:"parameters"`
	RiskLevel        RiskLevel      `json:"riskLevel"`
	RequiresConfirm  bool           `json:"requiresConfirm"`
	ModifiesPaths    []string       `json:"modifiesPaths"` // gitops paths affected
	// HandlerOnly marks operations that must only be submitted through their
	// dedicated REST handler. The generic POST /api/v1/operations/{name}/execute
	// path refuses them so they can't bypass the owner gate, quota checks,
	// secret scan, or rate limiter that only the dedicated handler enforces.
	HandlerOnly bool `json:"handlerOnly,omitempty"`
	// AdminOnly marks platform-scoped operations that require admin group
	// membership and have no team_name / tenant_name parameter. The generic
	// execute handler bypasses the tenant-access check for these and uses
	// the sentinel team "platform" when constructing the workflow.
	AdminOnly bool `json:"adminOnly,omitempty"`
}

// ParameterDef describes a single operation parameter.
type ParameterDef struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "string", "integer", "boolean"
	Required    bool     `json:"required"`
	Default     string   `json:"default,omitempty"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	Secret      bool     `json:"secret,omitempty"` // true = never echo in logs/responses
}

// NewRegistry creates the operation registry with all known operations.
func NewRegistry() *Registry {
	r := &Registry{ops: make(map[string]Operation)}
	for i := range builtinOperations {
		r.ops[builtinOperations[i].Name] = builtinOperations[i]
	}
	return r
}

// Get returns an operation by name.
func (r *Registry) Get(name string) (Operation, bool) {
	op, ok := r.ops[name]
	return op, ok
}

// List returns all registered operations.
func (r *Registry) List() []Operation {
	out := make([]Operation, 0, len(r.ops))
	for k := range r.ops {
		out = append(out, r.ops[k])
	}
	return out
}

// ValidateInput checks that all required parameters are present and valid.
func (r *Registry) ValidateInput(op Operation, input map[string]string) []string {
	var errors []string
	for _, p := range op.Parameters {
		val, exists := input[p.Name]
		if p.Required && (!exists || val == "") {
			errors = append(errors, "missing required parameter: "+p.Name)
			continue
		}
		if !exists || val == "" {
			continue
		}
		if len(p.Enum) > 0 {
			found := false
			for _, e := range p.Enum {
				if val == e {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, p.Name+": must be one of "+joinStrings(p.Enum))
			}
		}
		if p.Pattern != "" {
			if !regexp.MustCompile(p.Pattern).MatchString(val) {
				errors = append(errors, p.Name+": must match pattern "+p.Pattern)
			}
		}
	}
	return errors
}

// ApplyDefaults fills in default values for missing parameters.
func (r *Registry) ApplyDefaults(op Operation, input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for k, v := range input {
		result[k] = v
	}
	for _, p := range op.Parameters {
		if _, exists := result[p.Name]; !exists {
			result[p.Name] = p.Default
		}
	}
	return result
}

func joinStrings(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

var builtinOperations = []Operation{
	{
		Name:             "deploy-service",
		DisplayName:      "Release Service",
		Description:      "Deploy a new service or update an existing one. Builds Docker image from source, stores secrets in Vault, commits Helm values to the GitOps repo, and triggers ArgoCD sync. Repo MUST contain a Dockerfile at the configured `dockerfile_path`. For first-time onboarding of a brand-new repo, see https://docs.mctl.ai/guides/scaffolding for Node/Python/Go/static templates and the canonical CI auto-deploy job.",
		WorkflowTemplate: "deploy-service",
		RiskLevel:        RiskMedium,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/{component_name}/"},
		Parameters: []ParameterDef{
			{Name: "action", Type: "string", Required: true, Description: "Operation type", Enum: []string{"onboard", "deploy", "update-config"}},
			{Name: "team_name", Type: "string", Required: true, Description: "Team (workspace) name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_name", Type: "string", Required: true, Description: "Service name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_type", Type: "string", Default: "base-service", Description: "Chart type", Enum: []string{"base-service", "worker-service"}},
			{Name: "dockerfile_repo", Type: "string", Description: "GitHub repo (owner/name) containing the Dockerfile"},
			{Name: "git_tag", Type: "string", Description: "Git tag to build (e.g. v1.0.0)"},
			{Name: "port", Type: "string", Default: "8080", Description: "Service port"},
			{Name: "host", Type: "string", Description: "Ingress hostname (e.g. my-app.example.com). Omit for background workers."},
			{Name: "env_vars", Type: "string", Description: "Plaintext environment variables, newline-separated KEY=value"},
			{Name: "secret_env_vars", Type: "string", Description: "Secret environment variables stored in Vault, newline-separated KEY=value", Secret: true},
			{Name: "clear_env", Type: "string", Default: "false", Description: "Clear existing plaintext environment variables", Enum: []string{"true", "false"}},
			{Name: "clear_secrets", Type: "string", Default: "false", Description: "Clear existing secret environment variables", Enum: []string{"true", "false"}},
			{Name: "provision_database", Type: "string", Default: "false", Description: "Also provision a PostgreSQL database", Enum: []string{"true", "false"}},
			{Name: "skip_health_check", Type: "string", Default: "false", Description: "Skip post-deploy health check", Enum: []string{"true", "false"}},
			{Name: "health_check_path", Type: "string", Default: "", Description: "Override the liveness/readiness probe HTTP path (default: chart default /healthz + /readyz). Empty = unchanged."},
			{Name: "dockerfile_path", Type: "string", Default: "Dockerfile", Description: "Path to Dockerfile in the repo"},
			{Name: "image_tag", Type: "string", Description: "Explicit image tag override (default: derived from git_tag)"},
			{Name: "autoscaling_enabled", Type: "string", Default: "false", Description: "Enable HPA autoscaling", Enum: []string{"true", "false"}},
			{Name: "min_replicas", Type: "string", Default: "1", Description: "Minimum replica count (autoscaling)"},
			{Name: "max_replicas", Type: "string", Default: "5", Description: "Maximum replica count (autoscaling)"},
			{Name: "cpu_threshold", Type: "string", Default: "80", Description: "CPU utilization % to trigger scale-up"},
			{Name: "service_template", Type: "string", Default: "default", Description: "Service template preset. Any template name from service-templates/ in mctl-gitops. Unknown names fall back to 'default'."},
		},
	},
	{
		Name:             "create-tenant",
		DisplayName:      "Create Workspace",
		Description:      "Create a new team workspace with Kubernetes namespace, resource quotas, network policies, Vault secret scope, and ArgoCD RBAC. ArgoCD ApplicationSet automatically provisions the namespace.",
		WorkflowTemplate: "create-tenant",
		RiskLevel:        RiskMedium,
		RequiresConfirm:  true,
		ModifiesPaths:    []string{"platform-gitops/tenants/{tenant_name}/", "platform-gitops/argocd/values.yaml"},
		Parameters: []ParameterDef{
			{Name: "tenant_name", Type: "string", Required: true, Description: "Workspace name (DNS-safe, lowercase)", Pattern: "^[a-z0-9][a-z0-9-]{1,62}$"},
			{Name: "display_name", Type: "string", Description: "Human-readable team name"},
			{Name: "description", Type: "string", Description: "Team description"},
			{Name: "quota_cpu_req", Type: "string", Default: "500m", Description: "CPU request quota"},
			{Name: "quota_cpu_lim", Type: "string", Default: "3", Description: "CPU limit quota"},
			{Name: "quota_memory_req", Type: "string", Default: "1280Mi", Description: "Memory request quota"},
			{Name: "quota_memory_lim", Type: "string", Default: "4Gi", Description: "Memory limit quota"},
			{Name: "quota_pods", Type: "string", Default: "10", Description: "Maximum pods"},
			{Name: "allow_internet_egress", Type: "string", Default: "true", Description: "Allow outbound internet", Enum: []string{"true", "false"}},
			{Name: "contact_email", Type: "string", Description: "Team contact email"},
			{Name: "creator_user_id", Type: "string", Description: "GitHub user ID of the workspace creator"},
		},
	},
	{
		Name:             "provision-database",
		DisplayName:      "Provision Database",
		Description:      "Create a PostgreSQL database on the shared CNPG cluster. Generates credentials, stores them in Vault, creates CNPG Database resource, and links to the service via ExternalSecret.",
		WorkflowTemplate: "provision-database",
		RiskLevel:        RiskMedium,
		RequiresConfirm:  true,
		ModifiesPaths:    []string{"platform-gitops/cnpg-clusters/shared/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "app_name", Type: "string", Required: true, Description: "Application name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
		},
	},
	{
		Name:             "retire-service",
		DisplayName:      "Retire Service",
		Description:      "Remove a service from the platform. Deletes GitOps manifests, Vault secrets, ArgoCD Application, and Kubernetes resources. This action is irreversible.",
		WorkflowTemplate: "retire-service",
		RiskLevel:        RiskHigh,
		RequiresConfirm:  true,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/{component_name}/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_name", Type: "string", Required: true, Description: "Service name to retire", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_type", Type: "string", Required: false, Default: "base-service", Description: "Chart type: base-service or worker-service", Enum: []string{"base-service", "worker-service"}},
			{Name: "delete_vault_secrets", Type: "string", Required: false, Default: "true", Description: "Delete Vault secrets for the service", Enum: []string{"true", "false"}},
		},
	},
	{
		Name:             "delete-tenant",
		DisplayName:      "Delete Workspace",
		Description:      "Safely delete a team workspace and all its resources. Retires all services first, then removes namespace, ArgoCD RBAC, and Vault policy.",
		WorkflowTemplate: "delete-tenant-safe",
		RiskLevel:        RiskHigh,
		RequiresConfirm:  true,
		ModifiesPaths:    []string{"platform-gitops/tenants/{tenant_name}/", "platform-gitops/argocd/values.yaml"},
		Parameters: []ParameterDef{
			{Name: "tenant_name", Type: "string", Required: true, Description: "Workspace name to delete", Pattern: "^[a-z0-9][a-z0-9-]{1,62}$"},
		},
	},
	{
		Name:             "rollback-service",
		DisplayName:      "Rollback Service",
		Description:      "Roll back a service to a previously deployed image tag. Updates the image.tag in the GitOps values.yaml and triggers ArgoCD sync. Use mctl_get_service_config to find the current tag before calling this.",
		WorkflowTemplate: "rollback-service",
		RiskLevel:        RiskMedium,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/{component_name}/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_name", Type: "string", Required: true, Description: "Service name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "target_tag", Type: "string", Required: true, Description: "Image tag to roll back to (e.g. '1.2.3')"},
		},
	},
	{
		Name:             "preview-deploy",
		DisplayName:      "Deploy Preview Environment",
		Description:      "Deploy an ephemeral preview copy of a service. Supports two modes: (1) existing image — pass image_tag directly; (2) build from branch — pass git_ref + dockerfile_repo and the platform builds the image first. Preview is accessible at {app}-{id}.{platform_domain} and auto-deleted after the TTL.",
		WorkflowTemplate: "preview-deploy",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_name", Type: "string", Required: true, Description: "Service name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "image_tag", Type: "string", Description: "Image tag to deploy. Required unless git_ref is set — PreparePreviewDeployInput then auto-generates it."},
			{Name: "ttl_hours", Type: "string", Default: "24", Description: "Preview lifetime in hours (default: 24)"},
			{Name: "git_ref", Type: "string", Default: "", Pattern: `^[A-Za-z0-9._/-]+$`, Description: "Branch, SHA, or tag to build from. Leave empty to deploy an existing image_tag."},
			{Name: "dockerfile_repo", Type: "string", Default: "", Pattern: `^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`, Description: "Source repo in org/repo format. Required when git_ref is set."},
			{Name: "dockerfile_path", Type: "string", Default: "Dockerfile", Pattern: `^[A-Za-z0-9][A-Za-z0-9._/-]*$`, Description: "Path to Dockerfile inside dockerfile_repo (default: Dockerfile)"},
		},
	},
	{
		Name:             "preview-delete",
		DisplayName:      "Delete Preview Environment",
		Description:      "Remove a preview environment and all its Kubernetes resources.",
		WorkflowTemplate: "preview-delete",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "component_name", Type: "string", Required: true, Description: "Service name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "preview_id", Type: "string", Required: true, Description: "Preview ID returned by preview-deploy"},
		},
	},
	{
		Name:             "smoke-test",
		DisplayName:      "Platform Smoke Test",
		Description:      "End-to-end smoke test: onboard → verify pod → deploy with env+secret → verify Vault/ExternalSecret/pod env → provision DB → verify DB secret → update-config → verify env → retire. Runs in the tests team. onExit handler always retires on failure.",
		WorkflowTemplate: "smoke-test",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{},
		Parameters:       []ParameterDef{},
	},
	{
		Name:             "add-custom-domain",
		DisplayName:      "Add Custom Domain",
		Description:      "Add a verified custom domain to a service. Validates DNS (CNAME must point to the auto-generated domain), updates ingress configuration, and provisions TLS certificate via HTTP-01 challenge.",
		WorkflowTemplate: "add-custom-domain",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/{service_name}/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "service_name", Type: "string", Required: true, Description: "Service name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "domain", Type: "string", Required: true, Description: "Custom domain to add (e.g. api.mycompany.com)"},
		},
	},
	{
		Name:             "remove-custom-domain",
		DisplayName:      "Remove Custom Domain",
		Description:      "Remove a custom domain from a service. Cleans up ingress hosts and TLS configuration.",
		WorkflowTemplate: "remove-custom-domain",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/{service_name}/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "service_name", Type: "string", Required: true, Description: "Service name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "domain", Type: "string", Required: true, Description: "Custom domain to remove"},
		},
	},
	{
		Name:             "openclaw-skill-save",
		DisplayName:      "Save OpenClaw Skill to GitOps",
		Description:      "Back up a single OpenClaw SKILL.md file to the gitops repo. Writes platform-gitops/services/{team}/openclaw/skills/{skill_name}.md from a base64-encoded payload. Overwrites an existing file. Commits with the triggering user recorded in the commit body.",
		WorkflowTemplate: "openclaw-skill-save",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/openclaw/skills/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "skill_name", Type: "string", Required: true, Description: "Skill name (kebab-case, 1-64 chars)", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "content_b64", Type: "string", Required: true, Description: "Base64-encoded SKILL.md content"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator (recorded in the commit body)"},
		},
	},
	{
		Name:             "openclaw-skill-delete",
		DisplayName:      "Remove OpenClaw Skill from GitOps",
		Description:      "Remove a single SKILL.md file from the gitops backup. Idempotent — succeeds with a no-op if the file is already absent. Does not touch the tenant's runtime workspace.",
		WorkflowTemplate: "openclaw-skill-delete",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/openclaw/skills/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "skill_name", Type: "string", Required: true, Description: "Skill name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator (recorded in the commit body)"},
		},
	},
	{
		Name:             "openclaw-identity-save",
		DisplayName:      "Save OpenClaw Identity File to GitOps",
		Description:      "Back up a single OpenClaw identity override (AGENTS.md / SOUL.md / IDENTITY.md / USER.md / TOOLS.md) to the gitops repo. Writes platform-gitops/services/{team}/openclaw/identity/{file_name} from a base64-encoded payload. Overwrites an existing file. Commits with the triggering user recorded in the commit body.",
		WorkflowTemplate: "openclaw-identity-save",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/openclaw/identity/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "file_name", Type: "string", Required: true, Description: "Identity file name (one of AGENTS.md, SOUL.md, IDENTITY.md, USER.md, TOOLS.md)", Enum: []string{"AGENTS.md", "SOUL.md", "IDENTITY.md", "USER.md", "TOOLS.md"}},
			{Name: "content_b64", Type: "string", Required: true, Description: "Base64-encoded identity file content"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator (recorded in the commit body)"},
		},
	},
	{
		Name:             "platform-skill-publish",
		DisplayName:      "Publish Platform Skill",
		Description:      "Create or update a platform-wide skill under platform-gitops/platform-skills/catalog/{skill_name}/. Admin-only. Writes metadata.yaml and SKILL.md through a GitOps workflow.",
		WorkflowTemplate: "platform-skill-publish",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/platform-skills/catalog/{skill_name}/"},
		Parameters: []ParameterDef{
			{Name: "skill_name", Type: "string", Required: true, Description: "Skill name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "metadata_b64", Type: "string", Required: true, Description: "Base64-encoded metadata JSON"},
			{Name: "content_b64", Type: "string", Required: true, Description: "Base64-encoded SKILL.md content"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator"},
		},
	},
	{
		Name:             "platform-skill-deprecate",
		DisplayName:      "Deprecate Platform Skill",
		Description:      "Mark a platform-wide skill status as deprecated in metadata.yaml. Admin-only.",
		WorkflowTemplate: "platform-skill-deprecate",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/platform-skills/catalog/{skill_name}/metadata.yaml"},
		Parameters: []ParameterDef{
			{Name: "skill_name", Type: "string", Required: true, Description: "Skill name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator"},
		},
	},
	{
		Name:             "platform-skill-enable",
		DisplayName:      "Enable Platform Skill for Tenant",
		Description:      "Enable an active tenant-visible platform skill in platform-gitops/platform-skills/bindings/tenants/{tenant}.yaml. Admin-only.",
		WorkflowTemplate: "platform-skill-enable",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/platform-skills/bindings/tenants/{tenant_name}.yaml"},
		Parameters: []ParameterDef{
			{Name: "tenant_name", Type: "string", Required: true, Description: "Tenant name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "skill_name", Type: "string", Required: true, Description: "Skill name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator"},
		},
	},
	{
		Name:             "platform-skill-disable",
		DisplayName:      "Disable Platform Skill for Tenant",
		Description:      "Remove a platform skill from platform-gitops/platform-skills/bindings/tenants/{tenant}.yaml. Admin-only.",
		WorkflowTemplate: "platform-skill-disable",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/platform-skills/bindings/tenants/{tenant_name}.yaml"},
		Parameters: []ParameterDef{
			{Name: "tenant_name", Type: "string", Required: true, Description: "Tenant name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "skill_name", Type: "string", Required: true, Description: "Skill name", Pattern: "^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator"},
		},
	},
	// ─── mctl-agents triggers ─────────────────────────────────────────────
	// Six platform-scoped (AdminOnly) operations that submit Workflows in
	// the argo-workflows namespace (mctl-gitops repo holds the CWFTs):
	//   - mctl-agents-run / mctl-agents-mentor-only / mctl-agents-single-service /
	//     mctl-agents-incidents all reference the SAME `mctl-agents-run`
	//     ClusterWorkflowTemplate; only the `mode` (and optional `service`)
	//     parameter changes.
	//   - mctl-agents-implement (Tier 2) references its own
	//     `mctl-agents-implement` ClusterWorkflowTemplate — it opens PRs in
	//     sibling repos, so it carries RiskMedium instead of RiskLow.
	//   - mctl-agents-shepherd (Tier 3) references its own
	//     `mctl-agents-shepherd` ClusterWorkflowTemplate — it drives existing
	//     implementer-PRs through codex review fix loops to merge, so it
	//     carries RiskMedium (merging is irreversible per-PR but reviewable
	//     before the fact).
	// Cost / duration estimates in the Description so the LLM caller can warn
	// the user before triggering.
	{
		Name:             "mctl-agents-run",
		DisplayName:      "Run mctl-agents (full pipeline)",
		Description:      "Trigger the full mctl-agents pipeline: every service-agent (researcher → analyst → spec-writer in parallel) followed by the mentor weekly digest. Same as the daily 06:00 UTC cron. Cost: ~$10 (subscription quota). Duration: ~15 min. Result lands as a chore(agents) commit in mctl-gitops main under platform-gitops/agents-state/.",
		WorkflowTemplate: "mctl-agents-run",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/"},
		Parameters: []ParameterDef{
			{Name: "mode", Type: "string", Required: false, Default: "full", Description: "Run mode (locked to 'full' for this operation)", Enum: []string{"full"}},
			{Name: "service", Type: "string", Required: false, Default: "", Description: "Unused for full mode"},
		},
	},
	{
		Name:             "mctl-agents-mentor-only",
		DisplayName:      "Run mctl-agents (mentor only)",
		Description:      "Trigger mentor only — re-aggregates existing proposals across all services into a fresh weekly digest. Skips the expensive service-agent runs. Useful after manually triaging proposals. Cost: ~$1. Duration: ~2 min. Updates _mentor/digest/ in mctl-gitops main.",
		WorkflowTemplate: "mctl-agents-run",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/_mentor/digest/"},
		Parameters: []ParameterDef{
			{Name: "mode", Type: "string", Required: false, Default: "mentor-only", Description: "Run mode (locked to 'mentor-only')", Enum: []string{"mentor-only"}},
			{Name: "service", Type: "string", Required: false, Default: "", Description: "Unused for mentor-only mode"},
		},
	},
	{
		Name:             "mctl-agents-single-service",
		DisplayName:      "Run mctl-agents (single service)",
		Description:      "Trigger one service-agent only (no mentor). Useful after large changes in a specific repo when you want fresh proposals without paying for a full run. Cost: ~$1.50. Duration: ~7 min. Updates only that service's inbox/ and proposals/ in mctl-gitops main.",
		WorkflowTemplate: "mctl-agents-run",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/{service}/"},
		Parameters: []ParameterDef{
			{Name: "mode", Type: "string", Required: false, Default: "single-service", Description: "Run mode (locked to 'single-service')", Enum: []string{"single-service"}},
			{Name: "service", Type: "string", Required: true, Description: "Which service-agent to run", Enum: []string{"mctl-web", "mctl-openclaw", "mctl-docs", "mctl-api", "mctl-portal", "mctl-agent", "mctl-gitops", "mctl-agents"}},
		},
	},
	{
		// Incident responder — same `mctl-agents-run` CWFT, mode=incident-responder.
		// Lists mctl incidents with status=analyzing, filters to TypeGeneric ones
		// older than 30 min (up to 5 per run), diagnoses each via logs, writes an
		// auto-accepted proposal to agents-state/<service>/proposals/incident-<id[:8]>/,
		// and resolves the incident. RiskLow — it writes proposals and resolves
		// incidents, it never opens PRs itself (Tier 2 implementer does, on its
		// own run). Admin-only, same as the sibling mctl-agents triggers.
		Name:             "mctl-agents-incidents",
		DisplayName:      "Run mctl-agents incident responder",
		Description:      "Trigger the incident responder: diagnose TypeGeneric incidents stuck in status=analyzing (older than 30 min) and write auto-accepted proposals for the Tier 2 implementer, then resolve the incident. Same as the every-30-minute cron (15,45 * * * * UTC), on demand. Cost: ~$2 (subscription quota), max 5 incidents per run. Duration: variable, up to ~10 min. Result: proposal directories land in mctl-gitops main under platform-gitops/agents-state/<service>/proposals/incident-<id>/, and matched incidents are resolved.",
		WorkflowTemplate: "mctl-agents-run",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/{service}/proposals/incident-{id}/"},
		Parameters: []ParameterDef{
			{Name: "mode", Type: "string", Required: false, Default: "incident-responder", Description: "Run mode (locked to 'incident-responder')", Enum: []string{"incident-responder"}},
			{Name: "service", Type: "string", Required: false, Default: "", Description: "Unused for incident-responder mode"},
		},
	},
	{
		// Tier 2 implementer — turns accepted proposals into PRs in sibling
		// repos. Risk classified as medium (it OPENS PRs as the bot user;
		// PRs themselves are reviewable, so no human-irreversible side
		// effects, but the action is more consequential than the read-only
		// service-agent runs above). Admin-only.
		Name:             "mctl-agents-implement",
		DisplayName:      "Run mctl-agents Tier 2 implementer",
		Description:      "Tier 2 implementer: take accepted proposals (those with .status.yaml status=accepted) and open PRs in the matching sibling repos under mctlhq/. Optionally filter by service or slug. Admin-only. Cost: ~$3 per proposal (subscription quota). Duration: variable (1–10 min per proposal). Updates .status.yaml in mctl-gitops main and opens one PR per implemented proposal.",
		WorkflowTemplate: "mctl-agents-implement",
		RiskLevel:        RiskMedium,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/{service}/proposals/{slug}/.status.yaml", "mctlhq/{service}/<feat-branch>"},
		Parameters: []ParameterDef{
			{Name: "service", Type: "string", Required: false, Default: "", Description: "Optional. Filter to one service. Leave empty to consider all services.", Enum: []string{"", "mctl-web", "mctl-openclaw", "mctl-docs", "mctl-api", "mctl-portal", "mctl-agent", "mctl-gitops", "mctl-agents"}},
			{Name: "slug", Type: "string", Required: false, Default: "", Description: "Optional. Filter to one proposal slug (across services unless service is also set)."},
			{Name: "force", Type: "string", Required: false, Default: "false", Description: "Set to 'true' to retry a proposal stuck in `in-progress` (previous attempt may have crashed). Default 'false' (skip such proposals).", Enum: []string{"true", "false"}},
		},
	},
	{
		// Tier 3 PR shepherd — drives existing implementer-PRs through codex
		// review fix loops to merge. Reads .status.yaml entries with status in
		// {implementing, review-fixing}, evaluates decide() against the linked
		// PR's codex review state, and may invoke the implementer with
		// --review-feedback or merge the PR with --match-head-commit. Risk
		// classified as medium (it MERGES PRs as the bot user — irreversible
		// per-PR, but each merge is gated by an upfront codex review and the
		// human-set acceptance gate, so no unsupervised destructive action).
		// Admin-only.
		Name:             "mctl-agents-shepherd",
		DisplayName:      "Run mctl-agents Tier 3 PR shepherd",
		Description:      "Tier 3 PR shepherd: drive existing implementer-PRs through codex review fix loops to merge. Reads .status.yaml entries with status in {implementing, review-fixing} and, per the decide() policy, either invokes the implementer with --review-feedback to push a follow-up commit (review-fixing transition) or merges the PR with --match-head-commit (status=merged). Optionally filter by service or slug; dry_run=true prints decisions without acting. Admin-only. Cost: ~$1–5 per proposal (subscription quota). Duration: 1–10 min per proposal. Updates .status.yaml in mctl-gitops main and may merge PRs in mctlhq/<service>.",
		WorkflowTemplate: "mctl-agents-shepherd",
		RiskLevel:        RiskMedium,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/{service}/proposals/{slug}/.status.yaml", "mctlhq/{service}/<feat-branch> (follow-up commits or merge)"},
		Parameters: []ParameterDef{
			// `mctl-agents` is intentionally INCLUDED in the shepherd's service
			// enum (and the matching MCP tool enum), aligned with the Tier 2
			// implementer which added `mctl-agents` to its allowlist in
			// mctlhq/mctl-agents PR #11. The implementer's self-improvement
			// pipeline produces PRs in the agents repo itself (e.g. the
			// tier3-shepherd PRs landing now); the shepherd must drive those
			// to merge too. If the implementer's allowlist ever changes,
			// mirror the change here.
			{Name: "service", Type: "string", Required: false, Default: "", Description: "Optional. Filter to one service. Leave empty to consider all services.", Enum: []string{"", "mctl-web", "mctl-openclaw", "mctl-docs", "mctl-api", "mctl-portal", "mctl-agent", "mctl-gitops", "mctl-agents"}},
			{Name: "slug", Type: "string", Required: false, Default: "", Description: "Optional. Filter to one proposal slug (across services unless service is also set)."},
			{Name: "dry_run", Type: "string", Required: false, Default: "false", Description: "Set to 'true' to evaluate decide() for every matched proposal and print the decision WITHOUT calling the implementer or merging anything. Default 'false'.", Enum: []string{"true", "false"}},
		},
	},
	{
		// Issue-investigator — the issue-driven entry point. Reads a GitHub
		// issue, investigates the target repo, and writes a spec-driven
		// proposal (requirements/design/tasks.md + .status.yaml) under
		// agents-state/. It stops at status=proposed for human approval, so
		// it opens no PR and merges nothing — RiskLow. Admin-only, same as
		// the other mctl-agents triggers. References its own
		// `mctl-agents-investigate` ClusterWorkflowTemplate.
		Name:             "mctl-agents-investigate",
		DisplayName:      "Run mctl-agents issue-investigator",
		Description:      "Issue-driven entry point: take a GitHub issue URL and turn it into a spec-driven proposal (requirements/design/tasks.md) under platform-gitops/agents-state/<service>/proposals/<slug>/ with .status.yaml status=proposed. The investigator reads the issue, clones the target repo read-only to ground the design in real code, and comments the proposal link back on the issue. The proposal then awaits human approval (flip .status.yaml to accepted) before the Tier 2 implementer picks it up. Admin-only. Cost: ~$3 (subscription quota). Duration: ~5-10 min. Updates mctl-gitops main with the new proposal directory.",
		WorkflowTemplate: "mctl-agents-investigate",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		AdminOnly:        true,
		ModifiesPaths:    []string{"platform-gitops/agents-state/{service}/proposals/{slug}/"},
		Parameters: []ParameterDef{
			{Name: "issue_url", Type: "string", Required: true, Description: "Full GitHub issue URL under the mctlhq org, e.g. https://github.com/mctlhq/mctl-telegram/issues/123", Pattern: `^https://github\.com/mctlhq/[A-Za-z0-9_.-]+/issues/[0-9]+$`},
		},
	},
	{
		Name:             "openclaw-identity-delete",
		DisplayName:      "Remove OpenClaw Identity File from GitOps",
		Description:      "Remove a single identity override (AGENTS.md / SOUL.md / IDENTITY.md / USER.md / TOOLS.md) from the gitops backup. Idempotent — succeeds with a no-op if the file is already absent. The tenant reverts to the image-shipped default at the next sidecar reconcile.",
		WorkflowTemplate: "openclaw-identity-delete",
		RiskLevel:        RiskLow,
		RequiresConfirm:  false,
		HandlerOnly:      true,
		ModifiesPaths:    []string{"platform-gitops/services/{team_name}/openclaw/identity/"},
		Parameters: []ParameterDef{
			{Name: "team_name", Type: "string", Required: true, Description: "Team name", Pattern: "^[a-z0-9][a-z0-9-]{0,30}$"},
			{Name: "file_name", Type: "string", Required: true, Description: "Identity file name (one of AGENTS.md, SOUL.md, IDENTITY.md, USER.md, TOOLS.md)", Enum: []string{"AGENTS.md", "SOUL.md", "IDENTITY.md", "USER.md", "TOOLS.md"}},
			{Name: "actor", Type: "string", Required: false, Default: "unknown", Description: "User ID of the triggering operator (recorded in the commit body)"},
		},
	},
}
