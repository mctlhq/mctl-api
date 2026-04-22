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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mctlapi "github.com/mctlhq/mctl-api/internal/api"
	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// newQuotaTestRouter builds a router whose fakeGitReader is pre-seeded with
// `existingSkills` skills for team "tests" and whose OpenClaw quota config
// can be overridden for cap / rate-limit testing. Unlike newTestRouter the
// skill map is writable so tests can probe counts without fighting the
// shared fixture.
func newQuotaTestRouter(t *testing.T, existingSkills map[string]string, quota mctlapi.OpenClawQuotaConfig) (http.Handler, *fakeExecutor) {
	t.Helper()
	// Force dev mode — the authenticated-route middleware is pulled in by
	// NewRouter but AUTH_REQUIRED=false makes it a no-op when unset callers
	// hit the handlers with a pre-injected auth.User in context.
	t.Setenv("AUTH_REQUIRED", "false")
	gitReader := &fakeGitReader{
		tenants: []gitops.Tenant{
			{Name: "tests", DisplayName: "Tests", Members: []gitops.TenantMember{{UserID: "test-owner", Role: "owner"}}},
		},
		services: []gitops.Service{
			{Team: "tests", Name: "openclaw", ImageTag: "1.0.0", ComponentType: "base-service"},
		},
		skills: map[string]map[string]string{"tests": existingSkills},
	}
	argoClient := &fakeArgoCD{apps: map[string]*argocd.AppStatus{}}
	exec := &fakeExecutor{}
	router := mctlapi.NewRouter(mctlapi.Options{
		Registry:  operations.NewRegistry(),
		GitReader: gitReader,
		ArgoCD:    argoClient,
		AuditLog:  audit.NewLogger(),
		Executor:  exec,
		OpenClaw:  quota,
	})
	return router, exec
}

// postSkillAs is a small helper for posting a skill-save payload.
func postSkillAs(t *testing.T, router http.Handler, team, name, content string, user *auth.User) *httptest.ResponseRecorder {
	t.Helper()
	payload := map[string]string{"skill_name": name, "content": content}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/openclaw/"+team+"/skills", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithUser(req.Context(), user))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestOpenClawSave_SkillCountCap(t *testing.T) {
	// Seed 3 existing skills, cap at 3 → new skill rejected, update existing
	// stays allowed.
	existing := map[string]string{
		"alpha": "body alpha", "beta": "body beta", "gamma": "body gamma",
	}
	router, _ := newQuotaTestRouter(t, existing, mctlapi.OpenClawQuotaConfig{
		MaxSkillsPerTenant: 3,
	})

	t.Run("rejected on 101st-style over cap", func(t *testing.T) {
		w := postSkillAs(t, router, "tests", "delta", "new body content", ownerUser)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for over-cap save, got %d; body: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "skill count limit reached") {
			t.Fatalf("expected error to mention count limit, got: %s", w.Body.String())
		}
	})

	t.Run("update of existing skill still accepted under cap", func(t *testing.T) {
		w := postSkillAs(t, router, "tests", "alpha", "updated body content here", ownerUser)
		if w.Code != http.StatusAccepted {
			t.Fatalf("expected 202 for update at-cap, got %d; body: %s", w.Code, w.Body.String())
		}
	})
}

func TestOpenClawSave_TotalBytesCap(t *testing.T) {
	// Single 200-byte existing skill, total cap 300, new content 200 bytes +
	// name "delta" (5) = 205 — projected 405 > 300 → rejected.
	existing := map[string]string{
		"alpha": makeContent(200),
	}
	router, _ := newQuotaTestRouter(t, existing, mctlapi.OpenClawQuotaConfig{
		MaxSkillsTotalBytes: 300,
	})

	w := postSkillAs(t, router, "tests", "delta", makeContent(200), ownerUser)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for total-bytes over cap, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "ConfigMap size limit") {
		t.Fatalf("expected error to mention ConfigMap size limit, got: %s", w.Body.String())
	}
}

func TestOpenClawSave_SecretScan(t *testing.T) {
	router, _ := newQuotaTestRouter(t, map[string]string{}, mctlapi.OpenClawQuotaConfig{})

	secret := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"
	w := postSkillAs(t, router, "tests", "leaky", "use this token: "+secret, ownerUser)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for secret-scan match, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "github-pat") {
		t.Fatalf("expected error to name matched pattern, got: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("secret was echoed back in error: %s", w.Body.String())
	}
}

func TestOpenClawSave_RateLimit(t *testing.T) {
	// Rate limit 2 per hour — third save same (team, user) is 429.
	router, _ := newQuotaTestRouter(t, map[string]string{}, mctlapi.OpenClawQuotaConfig{
		SaveRatePerHour: 2,
	})

	for i := 0; i < 2; i++ {
		w := postSkillAs(t, router, "tests", fmt.Sprintf("skill-%d", i), "body content here", ownerUser)
		if w.Code != http.StatusAccepted {
			t.Fatalf("save %d: expected 202, got %d; body: %s", i, w.Code, w.Body.String())
		}
	}

	w := postSkillAs(t, router, "tests", "skill-3", "body content here", ownerUser)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 3rd save, got %d; body: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}
}

// makeContent returns a deterministic n-byte payload that won't trigger the
// secret-scan regex (plain ascii letters, no credential-ish keywords).
func makeContent(n int) string {
	const filler = "abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = filler[i%len(filler)]
	}
	return string(out)
}

