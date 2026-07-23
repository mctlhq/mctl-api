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

package alerts

import "time"

// Alert sources.
const (
	SourceAlertManager  = "alertmanager"
	SourcePolling       = "polling"
	SourceGitHubWebhook = "github_webhook"
	SourceManual        = "manual"
)

// Alert statuses.
const (
	StatusOpen         = "open"
	StatusAnalyzing    = "analyzing"
	StatusFixProposed  = "fix_proposed"
	StatusResolved     = "resolved"
	StatusSuppressed   = "suppressed"
	StatusAcknowledged = "acknowledged"

	// StatusActive is a virtual filter value meaning "any non-terminal" —
	// open, analyzing, fix_proposed, or acknowledged. Used as the default
	// for list endpoints so operators see everything that might still need
	// attention without having to enumerate intermediate states. Resolved
	// and suppressed are excluded.
	StatusActive = "active"
)

// Severity levels.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Alert is the central incident record stored by mctl-api.
type Alert struct {
	ID             string     `json:"id"`
	Source         string     `json:"source"`
	Type           string     `json:"type"`
	Tenant         string     `json:"tenant"`
	Service        string     `json:"service"`
	Summary        string     `json:"summary"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Analysis       string     `json:"analysis"`
	ProposedFix    string     `json:"proposed_fix"`
	PRURL          string     `json:"pr_url"`
	PRNumber       int        `json:"pr_number"`
	Confidence     string     `json:"confidence"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	// Fingerprint identifies the underlying failure class for dedup purposes.
	// Empty (the default) opts an alert out of dedup entirely — see the
	// partial unique index on (tenant, fingerprint) in alertSchema.
	Fingerprint     string     `json:"fingerprint,omitempty"`
	OccurrenceCount int        `json:"occurrence_count,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	Evidence        []Evidence `json:"evidence,omitempty"`
}

// Evidence attached to an alert.
type Evidence struct {
	ID          int       `json:"id"`
	AlertID     string    `json:"alert_id"`
	Type        string    `json:"type"`
	Content     string    `json:"content"`
	CollectedAt time.Time `json:"collected_at"`
}

// ListFilter holds query parameters for listing alerts.
type ListFilter struct {
	Status   string
	Tenant   string
	Service  string
	Type     string
	Severity string
	Limit    int
	Since    time.Time
}

// Summary holds aggregate counts.
type Summary struct {
	ByStatus   map[string]int `json:"by_status"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
	Total      int            `json:"total"`
}
