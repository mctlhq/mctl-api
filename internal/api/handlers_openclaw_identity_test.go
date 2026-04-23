// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

func TestOpenClawIdentity_List(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("non-owner gets 403", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := getAs(t, router, "/api/v1/openclaw/tests/identity", outsider)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("owner sees empty list when tenant has no overrides", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/identity", ownerUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["team"] != "tests" {
			t.Fatalf("expected team=tests, got %v", body["team"])
		}
		files, ok := body["identity"].([]interface{})
		if !ok {
			t.Fatalf("expected identity to be a list, got %T", body["identity"])
		}
		if len(files) != 0 {
			t.Fatalf("expected empty identity list, got %d items", len(files))
		}
	})
}

func TestOpenClawIdentity_Read_Allowlist(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("disallowed filename rejected with 400", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/identity/ROGUE.md", ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("missing allowed file returns 404", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/identity/AGENTS.md", ownerUser)
		assertStatus(t, w, http.StatusNotFound)
	})

	t.Run("non-owner gets 403 before any allowlist check", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := getAs(t, router, "/api/v1/openclaw/tests/identity/ROGUE.md", outsider)
		assertStatus(t, w, http.StatusForbidden)
	})
}

func TestOpenClawIdentity_Save(t *testing.T) {
	router, exec := newTestRouter(t)

	payload := func(name, content string) map[string]string {
		return map[string]string{"file_name": name, "content": content}
	}

	t.Run("non-owner gets 403", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := postAs(t, router, "/api/v1/openclaw/tests/identity", payload("AGENTS.md", "hello"), outsider)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("disallowed filename rejected with 400", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/tests/identity", payload("ROGUE.md", "hello"), ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("empty content rejected", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/tests/identity", payload("AGENTS.md", "   "), ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("content with secret pattern rejected", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/tests/identity", payload("AGENTS.md", "use ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12 for access"), ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
		if !strings.Contains(w.Body.String(), "github-pat") {
			t.Fatalf("expected error to mention matched pattern github-pat, got: %s", w.Body.String())
		}
		// Must NOT echo the secret back.
		if strings.Contains(w.Body.String(), "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12") {
			t.Fatalf("secret echoed in error response: %s", w.Body.String())
		}
	})

	t.Run("owner save submits openclaw-identity-save workflow", func(t *testing.T) {
		before := len(exec.submitted)
		w := postAs(t, router, "/api/v1/openclaw/tests/identity", payload("AGENTS.md", "# Agent identity\n"), ownerUser)
		assertStatus(t, w, http.StatusAccepted)
		if len(exec.submitted) != before+1 {
			t.Fatalf("expected 1 new workflow submission, got %d", len(exec.submitted)-before)
		}
		if exec.submitted[len(exec.submitted)-1] != "openclaw-identity-save" {
			t.Fatalf("expected openclaw-identity-save, got %q", exec.submitted[len(exec.submitted)-1])
		}
		params := exec.submittedParams[len(exec.submittedParams)-1]
		if params["team_name"] != "tests" || params["file_name"] != "AGENTS.md" {
			t.Fatalf("unexpected params: %#v", params)
		}
		if params["content_b64"] == "" {
			t.Fatal("expected content_b64 to be set")
		}
		if params["actor"] != ownerUser.ID {
			t.Fatalf("expected actor=%s, got %q", ownerUser.ID, params["actor"])
		}
	})
}

func TestOpenClawIdentity_Delete(t *testing.T) {
	router, exec := newTestRouter(t)

	t.Run("non-owner gets 403", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := deleteAs(t, router, "/api/v1/openclaw/tests/identity/AGENTS.md", outsider)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("disallowed filename rejected with 400", func(t *testing.T) {
		w := deleteAs(t, router, "/api/v1/openclaw/tests/identity/ROGUE.md", ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("owner delete submits openclaw-identity-delete workflow", func(t *testing.T) {
		before := len(exec.submitted)
		w := deleteAs(t, router, "/api/v1/openclaw/tests/identity/AGENTS.md", ownerUser)
		assertStatus(t, w, http.StatusAccepted)
		if len(exec.submitted) != before+1 {
			t.Fatalf("expected 1 new workflow submission, got %d", len(exec.submitted)-before)
		}
		if exec.submitted[len(exec.submitted)-1] != "openclaw-identity-delete" {
			t.Fatalf("expected openclaw-identity-delete, got %q", exec.submitted[len(exec.submitted)-1])
		}
		params := exec.submittedParams[len(exec.submittedParams)-1]
		if params["team_name"] != "tests" || params["file_name"] != "AGENTS.md" {
			t.Fatalf("unexpected params: %#v", params)
		}
		if params["actor"] != ownerUser.ID {
			t.Fatalf("expected actor=%s, got %q", ownerUser.ID, params["actor"])
		}
	})
}
