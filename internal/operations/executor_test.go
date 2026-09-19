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
		{"add custom domain runs centrally", "add-custom-domain", "acme", "argo-workflows"},
		{"remove custom domain runs centrally", "remove-custom-domain", "acme", "argo-workflows"},
		{"skill save runs centrally", "openclaw-skill-save", "acme", "argo-workflows"},
		{"skill delete runs centrally", "openclaw-skill-delete", "acme", "argo-workflows"},
		{"mctl-agents-run runs centrally", "mctl-agents-run", "acme", "argo-workflows"},
		{"mctl-agents-implement runs centrally", "mctl-agents-implement", "acme", "argo-workflows"},
		{"mctl-agents-shepherd runs centrally", "mctl-agents-shepherd", "acme", "argo-workflows"},
		{"mctl-agents-approve runs centrally", "mctl-agents-approve", "acme", "argo-workflows"},
		{"mctl-agents-reconcile runs centrally", "mctl-agents-reconcile", "acme", "argo-workflows"},
		// The real caller is AdminOnly with no team_name, so the handler
		// passes the "platform" sentinel. Returning it verbatim would send
		// the submit to a namespace that does not exist.
		{"mctl-agents-reconcile ignores the platform sentinel", "mctl-agents-reconcile", "platform", "argo-workflows"},
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

// The shape that matters to mctl-agents' implement-outcome taxonomy: two
// Pod nodes, both Failed, distinguishable ONLY by hostNodeName — one ran
// and exited non-zero, the other never reached a kubelet because it sat on
// a synchronization lock until a deadline killed it. If the projection
// drops that field the two collapse into one, every failed implementer
// reads as "never started", and the caller requeues work that may already
// be committed (mctl-agents#395).
func TestTrimWorkflowStatusKeepsHostNodeNameAndTemplateRef(t *testing.T) {
	obj := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "wf", "namespace": "argo-workflows", "managedFields": []interface{}{"dropped"}},
		"spec":     map[string]interface{}{"templates": []interface{}{"dropped"}},
		"status": map[string]interface{}{
			"phase": "Failed",
			"nodes": map[string]interface{}{
				"ran": map[string]interface{}{
					"displayName":  "implement",
					"type":         "Pod",
					"phase":        "Failed",
					"templateName": "run-implementer",
					"hostNodeName": "worker-1",
					"outputs":      map[string]interface{}{"exitCode": "1", "artifacts": []interface{}{"big"}},
				},
				"never-started": map[string]interface{}{
					"displayName": "implement",
					"type":        "Pod",
					"phase":       "Failed",
					"templateRef": map[string]interface{}{"name": "cwft-mctl-agents-implement", "template": "run-implementer"},
					"message":     "Step exceeded its deadline",
				},
			},
		},
	}

	trimmed := trimWorkflowStatus(obj)

	status, ok := trimmed["status"].(map[string]interface{})
	if !ok {
		t.Fatalf("status missing from trimmed object: %#v", trimmed)
	}
	nodes, ok := status["nodes"].(map[string]interface{})
	if !ok {
		t.Fatalf("nodes missing from trimmed status: %#v", status)
	}

	ran, ok := nodes["ran"].(map[string]interface{})
	if !ok {
		t.Fatalf("node %q missing: %#v", "ran", nodes)
	}
	if ran["hostNodeName"] != "worker-1" {
		t.Errorf("hostNodeName dropped from a node that ran: %#v", ran)
	}
	if _, present := ran["outputs"]; present {
		t.Errorf("outputs should stay excluded — it carries artifacts and parameters: %#v", ran)
	}

	neverStarted, ok := nodes["never-started"].(map[string]interface{})
	if !ok {
		t.Fatalf("node %q missing: %#v", "never-started", nodes)
	}
	if _, present := neverStarted["hostNodeName"]; present {
		t.Errorf("hostNodeName invented on a node that never ran: %#v", neverStarted)
	}
	ref, ok := neverStarted["templateRef"].(map[string]interface{})
	if !ok {
		t.Fatalf("templateRef dropped, so the node's template is unknowable: %#v", neverStarted)
	}
	if ref["template"] != "run-implementer" {
		t.Errorf("templateRef.template not preserved: %#v", ref)
	}

	// The trimming this function exists for still happens.
	meta, ok := trimmed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata missing: %#v", trimmed)
	}
	if _, present := meta["managedFields"]; present {
		t.Errorf("managedFields should be dropped: %#v", meta)
	}
	if _, present := trimmed["spec"]; present {
		t.Errorf("spec should be dropped: %#v", trimmed)
	}
}
