// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
)

// deleteAs sends DELETE with a user injected into the request context.
func deleteAs(t *testing.T, router http.Handler, path string, user *auth.User) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req = req.WithContext(auth.WithUser(req.Context(), user))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestOpenClawSkills_List(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("non-owner gets 403", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := getAs(t, router, "/api/v1/openclaw/tests/skills", outsider)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("owner gets empty list when no skills backed up", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/skills", ownerUser)
		assertStatus(t, w, http.StatusOK)
		body := decodeJSON(t, w)
		if body["team"] != "tests" {
			t.Fatalf("expected team=tests, got %v", body["team"])
		}
		skills, ok := body["skills"].([]interface{})
		if !ok {
			t.Fatalf("expected skills to be a list, got %T", body["skills"])
		}
		if len(skills) != 0 {
			t.Fatalf("expected empty skills list, got %d items", len(skills))
		}
	})

	t.Run("admin can list any team's skills", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/skills", adminUser)
		assertStatus(t, w, http.StatusOK)
	})
}

func TestOpenClawSkills_Read_ValidationAndNotFound(t *testing.T) {
	router, _ := newTestRouter(t)

	t.Run("invalid skill name rejected", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/skills/UPPER", ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		// chi normalizes the path before reaching our handler; just ensure a
		// skill name containing a dot segment is rejected at validation.
		w := getAs(t, router, "/api/v1/openclaw/tests/skills/evil..skill", ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("missing skill returns 404", func(t *testing.T) {
		w := getAs(t, router, "/api/v1/openclaw/tests/skills/nothing-here", ownerUser)
		assertStatus(t, w, http.StatusNotFound)
	})

	t.Run("non-owner gets 403 before 404", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := getAs(t, router, "/api/v1/openclaw/tests/skills/anything", outsider)
		assertStatus(t, w, http.StatusForbidden)
	})
}

func TestOpenClawSkills_Save(t *testing.T) {
	router, exec := newTestRouter(t)

	payload := func(name, content string) map[string]string {
		return map[string]string{"skill_name": name, "content": content}
	}

	t.Run("non-owner gets 403", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := postAs(t, router, "/api/v1/openclaw/tests/skills", payload("my-skill", "---\nname: my-skill\n---\n"), outsider)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("invalid skill name rejected", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/tests/skills", payload("BadName", "body"), ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("empty content rejected", func(t *testing.T) {
		w := postAs(t, router, "/api/v1/openclaw/tests/skills", payload("my-skill", "   "), ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("content larger than 100 KB rejected", func(t *testing.T) {
		huge := strings.Repeat("x", 100*1024+1)
		w := postAs(t, router, "/api/v1/openclaw/tests/skills", payload("my-skill", huge), ownerUser)
		assertStatus(t, w, http.StatusRequestEntityTooLarge)
	})

	t.Run("owner save submits openclaw-skill-save workflow", func(t *testing.T) {
		before := len(exec.submitted)
		w := postAs(t, router, "/api/v1/openclaw/tests/skills", payload("my-skill", "---\nname: my-skill\ndescription: test\n---\n# body"), ownerUser)
		assertStatus(t, w, http.StatusAccepted)
		if len(exec.submitted) != before+1 {
			t.Fatalf("expected 1 new workflow submission, got %d", len(exec.submitted)-before)
		}
		if exec.submitted[len(exec.submitted)-1] != "openclaw-skill-save" {
			t.Fatalf("expected last submission to be openclaw-skill-save, got %q", exec.submitted[len(exec.submitted)-1])
		}
		params := exec.submittedParams[len(exec.submittedParams)-1]
		if params["team_name"] != "tests" || params["skill_name"] != "my-skill" {
			t.Fatalf("unexpected params: %#v", params)
		}
		if params["content_b64"] == "" {
			t.Fatal("expected content_b64 to be set")
		}
		if params["actor"] != ownerUser.ID {
			t.Fatalf("expected actor=%s, got %q", ownerUser.ID, params["actor"])
		}
	})

	t.Run("invalid JSON body rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/openclaw/tests/skills", bytes.NewReader([]byte("{not json")))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.WithUser(req.Context(), ownerUser))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assertStatus(t, w, http.StatusBadRequest)
	})
}

func TestOpenClawSkills_Delete(t *testing.T) {
	router, exec := newTestRouter(t)

	t.Run("non-owner gets 403", func(t *testing.T) {
		outsider := &auth.User{ID: "someone-else", Groups: []string{"other"}}
		w := deleteAs(t, router, "/api/v1/openclaw/tests/skills/my-skill", outsider)
		assertStatus(t, w, http.StatusForbidden)
	})

	t.Run("invalid skill name rejected", func(t *testing.T) {
		w := deleteAs(t, router, "/api/v1/openclaw/tests/skills/BAD", ownerUser)
		assertStatus(t, w, http.StatusBadRequest)
	})

	t.Run("owner delete submits openclaw-skill-delete workflow", func(t *testing.T) {
		before := len(exec.submitted)
		w := deleteAs(t, router, "/api/v1/openclaw/tests/skills/my-skill", ownerUser)
		assertStatus(t, w, http.StatusAccepted)
		if len(exec.submitted) != before+1 {
			t.Fatalf("expected 1 new workflow submission, got %d", len(exec.submitted)-before)
		}
		if exec.submitted[len(exec.submitted)-1] != "openclaw-skill-delete" {
			t.Fatalf("expected last submission to be openclaw-skill-delete, got %q", exec.submitted[len(exec.submitted)-1])
		}
		params := exec.submittedParams[len(exec.submittedParams)-1]
		if params["team_name"] != "tests" || params["skill_name"] != "my-skill" {
			t.Fatalf("unexpected params: %#v", params)
		}
		if params["actor"] != ownerUser.ID {
			t.Fatalf("expected actor=%s, got %q", ownerUser.ID, params["actor"])
		}
	})
}
