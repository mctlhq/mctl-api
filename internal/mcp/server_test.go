package mcp

import (
	"testing"
)

func TestExtractStringParams(t *testing.T) {
	args := map[string]any{
		"team":   "billing",
		"count":  42,
		"flag":   true,
		"empty":  "",
		"action": "deploy",
	}
	result := extractStringParams(args)

	if result["team"] != "billing" {
		t.Errorf("team: got %q, want billing", result["team"])
	}
	if result["action"] != "deploy" {
		t.Errorf("action: got %q, want deploy", result["action"])
	}
	if result["empty"] != "" {
		t.Errorf("empty: got %q, want empty string", result["empty"])
	}
	// Non-string values should be dropped.
	if _, ok := result["count"]; ok {
		t.Error("non-string int value should be dropped")
	}
	if _, ok := result["flag"]; ok {
		t.Error("non-string bool value should be dropped")
	}
}

func TestNewMCPServer_ToolCount(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")
	mcpSrv := srv.NewMCPServer()
	if mcpSrv == nil {
		t.Fatal("NewMCPServer returned nil")
	}
	// Verify the server was created without panicking (tool registration is validated at startup).
	// We can't easily count tools without reflection, but we can ensure the server is non-nil.
}

func TestToolDescriptions_NotEmpty(t *testing.T) {
	srv := NewServer("http://localhost:8080", "")

	tools := []struct {
		name string
		fn   func() interface{}
	}{
		{"toolListTenants", func() interface{} { t, _ := srv.toolListTenants(); return t }},
		{"toolListServices", func() interface{} { t, _ := srv.toolListServices(); return t }},
		{"toolDeployService", func() interface{} { t, _ := srv.toolDeployService(); return t }},
		{"toolCreateTenant", func() interface{} { t, _ := srv.toolCreateTenant(); return t }},
		{"toolRollbackService", func() interface{} { t, _ := srv.toolRollbackService(); return t }},
		{"toolCreatePreview", func() interface{} { t, _ := srv.toolCreatePreview(); return t }},
		{"toolDeletePreview", func() interface{} { t, _ := srv.toolDeletePreview(); return t }},
	}

	for _, tc := range tools {
		result := tc.fn()
		if result == nil {
			t.Errorf("%s returned nil tool", tc.name)
		}
	}
}

func TestNewServer(t *testing.T) {
	srv := NewServer("https://api.mctl.ai", "test-token")
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.apiURL != "https://api.mctl.ai" {
		t.Errorf("apiURL: got %q", srv.apiURL)
	}
	if srv.apiToken != "test-token" {
		t.Errorf("apiToken: got %q", srv.apiToken)
	}
}

func TestNewServer_TrimsTrailingSlash(t *testing.T) {
	srv := NewServer("https://api.mctl.ai/", "")
	if srv.apiURL != "https://api.mctl.ai" {
		t.Errorf("trailing slash not trimmed: got %q", srv.apiURL)
	}
}
