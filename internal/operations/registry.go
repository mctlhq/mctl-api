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
		Description:      "Deploy a new service or update an existing one. Builds Docker image from source, stores secrets in Vault, commits Helm values to the GitOps repo, and triggers ArgoCD sync.",
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
			{Name: "host", Type: "string", Description: "Ingress hostname (e.g. my-app.mctl.ai). Omit for background workers."},
			{Name: "env_vars", Type: "string", Description: "Plaintext environment variables, newline-separated KEY=value"},
			{Name: "secret_env_vars", Type: "string", Description: "Secret environment variables stored in Vault, newline-separated KEY=value", Secret: true},
			{Name: "provision_database", Type: "string", Default: "false", Description: "Also provision a PostgreSQL database", Enum: []string{"true", "false"}},
			{Name: "skip_health_check", Type: "string", Default: "false", Description: "Skip post-deploy health check", Enum: []string{"true", "false"}},
			{Name: "dockerfile_path", Type: "string", Default: "Dockerfile", Description: "Path to Dockerfile in the repo"},
			{Name: "image_tag", Type: "string", Description: "Explicit image tag override (default: derived from git_tag)"},
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
			{Name: "quota_cpu_req", Type: "string", Default: "1", Description: "CPU request quota"},
			{Name: "quota_cpu_lim", Type: "string", Default: "2", Description: "CPU limit quota"},
			{Name: "quota_memory_req", Type: "string", Default: "2Gi", Description: "Memory request quota"},
			{Name: "quota_memory_lim", Type: "string", Default: "3Gi", Description: "Memory limit quota"},
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
		},
	},
	{
		Name:             "delete-tenant",
		DisplayName:      "Delete Workspace",
		Description:      "Delete a team workspace and all its resources. Removes namespace, ArgoCD RBAC, Vault policy. All services in the workspace must be retired first.",
		WorkflowTemplate: "delete-tenant",
		RiskLevel:        RiskHigh,
		RequiresConfirm:  true,
		ModifiesPaths:    []string{"platform-gitops/tenants/{tenant_name}/", "platform-gitops/argocd/values.yaml"},
		Parameters: []ParameterDef{
			{Name: "tenant_name", Type: "string", Required: true, Description: "Workspace name to delete", Pattern: "^[a-z0-9][a-z0-9-]{1,62}$"},
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
}
