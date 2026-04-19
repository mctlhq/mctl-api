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
	ListOpenClawSkills(team string) ([]gitops.OpenClawSkill, error)
	ReadOpenClawSkill(team, name string) (string, error)
}

// ArgoStatusClient is the subset of argocd.Client used by API handlers.
type ArgoStatusClient interface {
	GetAppStatus(name string) (*argocd.AppStatus, error)
	ListApps(project string) ([]argocd.AppStatus, error)
}

// WorkflowExecutor is the subset of operations.Executor used by API handlers.
type WorkflowExecutor interface {
	Submit(ctx context.Context, op operations.Operation, params map[string]string, userID string, namespace string) (*operations.SubmitResult, error)
	GetWorkflowStatus(ctx context.Context, namespace, name string) (map[string]interface{}, error)
}

// AuditLog is the interface for recording and querying audit events.
// Implemented by audit.Logger (in-memory) and audit.PostgresLogger (persistent).
type AuditLog = audit.Log

// LogQuerier fetches log lines from Loki for a given namespace/app.
type LogQuerier interface {
	QueryRange(ctx context.Context, namespace, app string, lines int, since time.Duration) ([]loki.LogLine, error)
}

// VaultReader exposes the subset of Vault reads needed by onboarding flows.
type VaultReader interface {
	ReadKV(ctx context.Context, path string) (map[string]string, error)
}

// MetricsQuerier fetches historical container usage stats for right-sizing decisions.
type MetricsQuerier interface {
	GetContainerUsage(ctx context.Context, namespace, app, container string, lookback time.Duration) (ContainerUsageStats, error)
}

// ContainerUsageStats summarizes recent runtime consumption for a single container.
type ContainerUsageStats struct {
	MemoryMaxBytes float64 `json:"memoryMaxBytes"`
	MemoryP95Bytes float64 `json:"memoryP95Bytes"`
	CPUMaxCores    float64 `json:"cpuMaxCores"`
	CPUP95Cores    float64 `json:"cpuP95Cores"`
	SampleCount    int     `json:"sampleCount"`
}
