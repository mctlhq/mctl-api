package api

import (
	"context"
	"time"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/loki"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// QuotaReader fetches live Kubernetes ResourceQuota usage for a namespace.
type QuotaReader interface {
	GetNamespaceUsage(ctx context.Context, namespace string) (used, hard map[string]string, err error)
}

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

// AuditLog is the interface for recording and querying audit events.
// Implemented by audit.Logger (in-memory) and audit.PostgresLogger (persistent).
type AuditLog = audit.Log

// LogQuerier fetches log lines from Loki for a given namespace/app.
type LogQuerier interface {
	QueryRange(ctx context.Context, namespace, app string, lines int, since time.Duration) ([]loki.LogLine, error)
}
