// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package operations

import "testing"

func TestWorkflowNamespace(t *testing.T) {
	tests := []struct {
		name             string
		workflowTemplate string
		team             string
		want             string
	}{
		{"tenant lifecycle create", "create-tenant", "acme", "argo-workflows"},
		{"tenant lifecycle delete (direct)", "delete-tenant", "acme", "argo-workflows"},
		{"tenant lifecycle delete (safe)", "delete-tenant-safe", "acme", "argo-workflows"},
		{"skill save runs centrally", "openclaw-skill-save", "acme", "argo-workflows"},
		{"skill delete runs centrally", "openclaw-skill-delete", "acme", "argo-workflows"},
		{"mctl-agents-run runs centrally", "mctl-agents-run", "acme", "argo-workflows"},
		{"mctl-agents-implement runs centrally", "mctl-agents-implement", "acme", "argo-workflows"},
		{"service deploy runs in team ns", "deploy-service", "acme", "acme"},
		{"retire service runs in team ns", "retire-service", "acme", "acme"},
		{"unknown template falls back to team ns", "anything-else", "acme", "acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WorkflowNamespace(tt.workflowTemplate, tt.team)
			if got != tt.want {
				t.Errorf("WorkflowNamespace(%q, %q) = %q, want %q", tt.workflowTemplate, tt.team, got, tt.want)
			}
		})
	}
}
