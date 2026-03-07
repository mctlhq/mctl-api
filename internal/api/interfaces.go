package api

import (
	"context"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// GitReader is the subset of gitops.Reader used by API handlers.
type GitReader interface {
	ListTenants() ([]gitops.Tenant, error)
	GetTenant(name string) (*gitops.Tenant, error)
	ListServices(teamFilter string) ([]gitops.Service, error)
	GetService(team, app string) (*gitops.Service, error)
}

// ArgoStatusClient is the subset of argocd.Client used by API handlers.
type ArgoStatusClient interface {
	GetAppStatus(name string) (*argocd.AppStatus, error)
}

// WorkflowExecutor is the subset of operations.Executor used by API handlers.
type WorkflowExecutor interface {
	Submit(ctx context.Context, op operations.Operation, params map[string]string, userID string, namespace string) (*operations.SubmitResult, error)
}

// AuditLog is the subset of audit.Logger used by API handlers.
type AuditLog interface {
	Log(entry audit.Entry)
	List(limit int) []audit.Entry
	GetByWorkflow(name string) *audit.Entry
}
