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

package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMCP_PromptsAndResources(t *testing.T) {
	srv := NewServer("http://localhost:8080", "test-token")
	mcpSrv := srv.NewMCPServer()

	// 1. Test prompts/list
	req := json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	resp := mcpSrv.HandleMessage(context.Background(), req)

	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal prompts/list response: %v", err)
	}

	var promptResp struct {
		Result struct {
			Prompts []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"prompts"`
		} `json:"result"`
	}

	if err := json.Unmarshal(raw, &promptResp); err != nil {
		t.Fatalf("failed to unmarshal prompts/list response: %v", err)
	}

	promptNames := make(map[string]bool)
	for _, p := range promptResp.Result.Prompts {
		promptNames[p.Name] = true
	}

	expectedPrompts := []string{"onboard_service", "troubleshoot_incident", "deploy_service", "platform-skill"}
	for _, expected := range expectedPrompts {
		if !promptNames[expected] {
			t.Errorf("expected prompt %q in prompts/list", expected)
		}
	}

	// 2. Test resources/list
	resReq := json.RawMessage(`{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	resResp := mcpSrv.HandleMessage(context.Background(), resReq)

	resRaw, err := json.Marshal(resResp)
	if err != nil {
		t.Fatalf("failed to marshal resources/list response: %v", err)
	}

	var resourceResp struct {
		Result struct {
			Resources []struct {
				URI  string `json:"uri"`
				Name string `json:"name"`
			} `json:"resources"`
		} `json:"result"`
	}

	if err := json.Unmarshal(resRaw, &resourceResp); err != nil {
		t.Fatalf("failed to unmarshal resources/list response: %v", err)
	}

	resourceURIs := make(map[string]bool)
	for _, r := range resourceResp.Result.Resources {
		resourceURIs[r.URI] = true
	}

	expectedResources := []string{"mctl://platform/overview", "mctl://operations/catalog"}
	for _, expected := range expectedResources {
		if !resourceURIs[expected] {
			t.Errorf("expected resource %q in resources/list", expected)
		}
	}
}
