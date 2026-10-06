package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/domains"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Tenant role gate (mctl-api#478): the decision itself, and the write
// handlers that do not go through POST /operations/{name}/execute.

func erpactRoles() *stubRoles {
	return rolesOf(
		"erpact/olga-owner=owner",
		"erpact/dan-dev=developer",
		"erpact/vic-viewer=viewer",
		"erpact/nora-norole=",
		"erpact/dup=owner", "erpact/dup=viewer",
	)
}

func erpactMember(login string) *auth.User { return auth.NewGitHubUser(login, []string{"erpact"}) }

func TestCheckTenantRole(t *testing.T) {
	telegram := auth.NewSurfaceUser("telegram")
	agent := auth.NewAgentUser("implementer", auth.AgentRun{ExecutionID: "we_1", WorkItemID: "wi_1"})

	tests := []struct {
		name       string
		user       *auth.User
		min        operations.Role
		wantStatus int // 0 = allowed
		wantAudit  string
	}{
		{"owner meets owner", erpactMember("olga-owner"), operations.RoleOwner, 0, ""},
		{"owner meets developer", erpactMember("olga-owner"), operations.RoleDeveloper, 0, ""},
		{"developer meets developer", erpactMember("dan-dev"), operations.RoleDeveloper, 0, ""},
		{"developer meets viewer", erpactMember("dan-dev"), operations.RoleViewer, 0, ""},
		{"developer below owner", erpactMember("dan-dev"), operations.RoleOwner, http.StatusForbidden, "denied"},
		{"viewer below developer", erpactMember("vic-viewer"), operations.RoleDeveloper, http.StatusForbidden, "denied"},
		{"empty role is not even a viewer", erpactMember("nora-norole"), operations.RoleViewer, http.StatusForbidden, "denied"},
		{"listed twice counts as the lesser", erpactMember("dup"), operations.RoleDeveloper, http.StatusForbidden, "denied"},
		{"not listed", erpactMember("gone"), operations.RoleViewer, http.StatusForbidden, "denied"},
		{"unproven identity", &auth.User{ID: "olga-owner", Groups: []string{"erpact"}}, operations.RoleViewer, http.StatusForbidden, "denied"},
		{"surface principal itself", telegram, operations.RoleViewer, http.StatusForbidden, "denied"},

		// A relayed or delegated session is the linked human, minus admin:
		// it holds that human's role and no more.
		{"relayed owner", auth.NewRelayedUser("olga-owner", []string{"erpact", "admins"}, telegram), operations.RoleOwner, 0, ""},
		{"relayed developer", auth.NewRelayedUser("dan-dev", []string{"erpact"}, telegram), operations.RoleOwner, http.StatusForbidden, "denied"},
		{"delegated owner", auth.NewDelegatedUser("olga-owner", []string{"erpact"}, agent), operations.RoleOwner, 0, ""},
		{"delegated developer", auth.NewDelegatedUser("dan-dev", []string{"erpact"}, agent), operations.RoleOwner, http.StatusForbidden, "denied"},

		// Admins pass everything, listed or not.
		{"admin, tenant minimum", auth.NewGitHubUser("root", []string{"admins"}), operations.RoleOwner, 0, ""},
		{"admin, admin minimum", auth.NewGitHubUser("root", []string{"admins"}), operations.RoleAdmin, 0, ""},
		{"service principal", auth.NewServiceUser(), operations.RoleOwner, 0, ""},
		{"owner is not an admin", erpactMember("olga-owner"), operations.RoleAdmin, http.StatusForbidden, "denied"},

		// A tenant write nobody set a tenant minimum for is refused, for the
		// owner too: "nobody decided" is not "anyone may".
		{"no minimum declared", erpactMember("olga-owner"), "", http.StatusInternalServerError, "error"},
		{"authenticated is not a tenant minimum", erpactMember("olga-owner"), operations.RoleAuthenticated, http.StatusInternalServerError, "error"},
		{"unknown minimum", erpactMember("olga-owner"), "superuser", http.StatusInternalServerError, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handlers{opts: Options{GitReader: erpactRoles()}}
			d := h.checkTenantRole(tt.user, "erpact", tt.min, "the action")
			if d.status != tt.wantStatus || d.auditStatus != tt.wantAudit {
				t.Fatalf("got {status %d, audit %q, %q}; want {status %d, audit %q}", d.status, d.auditStatus, d.message, tt.wantStatus, tt.wantAudit)
			}
			if d.refused() != (tt.wantStatus != 0) {
				t.Fatalf("refused() = %v with status %d", d.refused(), d.status)
			}
		})
	}
}

// A role in one tenant is not a role in another.
func TestCheckTenantRole_RoleIsPerTenant(t *testing.T) {
	h := &Handlers{opts: Options{GitReader: rolesOf("erpact/olga-owner=developer", "labs/olga-owner=owner")}}
	user := auth.NewGitHubUser("olga-owner", []string{"erpact", "labs"})
	if d := h.checkTenantRole(user, "labs", operations.RoleOwner, "x"); d.refused() {
		t.Fatalf("owner of labs refused on labs: %+v", d)
	}
	if d := h.checkTenantRole(user, "erpact", operations.RoleOwner, "x"); d.status != http.StatusForbidden {
		t.Fatalf("owner of labs passed as owner of erpact: %+v", d)
	}
}

// What could not be read is 503 and "error", whoever asks, and is never
// told apart from the outside by its cause.
func TestCheckTenantRole_UnreadableIsUnavailable(t *testing.T) {
	failing := erpactRoles()
	failing.err = errors.New("open /data/gitops/tenants/erpact/values.yaml: permission denied")
	for name, h := range map[string]*Handlers{
		"read fails":       {opts: Options{GitReader: failing}},
		"no reader at all": {opts: Options{}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, login := range []string{"olga-owner", "dan-dev", "gone"} {
				d := h.checkTenantRole(erpactMember(login), "erpact", operations.RoleViewer, "x")
				if d.status != http.StatusServiceUnavailable || d.auditStatus != "error" {
					t.Fatalf("%s: got {%d, %q}; want {503, error}", login, d.status, d.auditStatus)
				}
				if strings.Contains(d.message, "/data/gitops") || strings.Contains(d.message, "permission denied") {
					t.Fatalf("the response carries the cause: %q", d.message)
				}
				if d.detail == "" {
					t.Fatal("no detail for the audit entry")
				}
			}
		})
	}
}

func TestRequireTenantRole_AuditsEveryRefusal(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{GitReader: erpactRoles(), AuditLog: log}}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)

	rec := httptest.NewRecorder()
	if !h.requireTenantRole(rec, req, erpactMember("olga-owner"), "erpact", operations.RoleOwner, "thing", operations.RiskHigh) {
		t.Fatal("owner refused")
	}
	if n := len(log.List(10)); n != 0 || rec.Body.Len() != 0 {
		t.Fatalf("an allowed call wrote %d audit entries and %d response bytes", n, rec.Body.Len())
	}

	rec = httptest.NewRecorder()
	if h.requireTenantRole(rec, req, erpactMember("dan-dev"), "erpact", operations.RoleOwner, "thing", operations.RiskHigh) {
		t.Fatal("developer allowed")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	entries := log.List(10)
	if len(entries) != 1 {
		t.Fatalf("%d audit entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Status != "denied" || e.Operation != "thing" || e.UserID != "dan-dev" || e.RiskLevel != string(operations.RiskHigh) || e.Parameters["tenant"] != "erpact" {
		t.Fatalf("audit entry = %+v", e)
	}
	if !strings.Contains(e.Message, `"developer"`) || !strings.Contains(e.Message, `"owner"`) {
		t.Fatalf("audit message does not name both roles: %q", e.Message)
	}
}

// The registry is the one place a minimum is declared. The fallback only
// stands in where there is no registry entry at all.
func TestOperationMinRole(t *testing.T) {
	h := &Handlers{opts: Options{Registry: operations.NewRegistry()}}
	if got := h.operationMinRole("remove-custom-domain", operations.RoleViewer); got != operations.RoleOwner {
		t.Errorf("remove-custom-domain = %q, want the registry's owner, not the fallback", got)
	}
	if got := h.operationMinRole("add-custom-domain", operations.RoleOwner); got != operations.RoleDeveloper {
		t.Errorf("add-custom-domain = %q, want the registry's developer", got)
	}
	if got := h.operationMinRole("no-such-operation", operations.RoleOwner); got != operations.RoleOwner {
		t.Errorf("unknown operation = %q, want the fallback", got)
	}
	bare := &Handlers{opts: Options{}}
	if got := bare.operationMinRole("remove-custom-domain", operations.RoleOwner); got != operations.RoleOwner {
		t.Errorf("no registry = %q, want the fallback", got)
	}
}

// ── custom domains ───────────────────────────────────────────────────────────

func domainRoleHandlers(t *testing.T) (*Handlers, *domains.Store, *fakeDomainExecutor, *audit.Logger) {
	t.Helper()
	store := newTestDomainStore(t)
	exec := &fakeDomainExecutor{}
	log := audit.NewLogger()
	return &Handlers{opts: Options{
		GitReader:      erpactRoles(),
		DomainStore:    store,
		PlatformDomain: "mctl.ai",
		Executor:       exec,
		Registry:       operations.NewRegistry(),
		AuditLog:       log,
		DomainVerifier: domains.NewVerifierWithResolver(&negativeResolver{}),
	}}, store, exec, log
}

func seedDomain(t *testing.T, store *domains.Store, status string) *domains.Domain {
	t.Helper()
	d, err := store.Create(context.Background(), &domains.Domain{
		ID:                uuid.New().String(),
		Team:              "erpact",
		Service:           "web",
		Domain:            "app-" + uuid.New().String()[:8] + ".example.com",
		Status:            status,
		VerificationToken: "test-token",
		CreatedBy:         "olga-owner",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return d
}

func addDomainAs(h *Handlers, user *auth.User) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.AddDomain(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains",
		strings.NewReader(`{"team":"erpact","service":"web","domain":"new-`+uuid.New().String()[:8]+`.example.com"}`)), user))
	return rec
}

func deleteDomainAs(h *Handlers, id string, user *auth.User) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.DeleteDomain(rec, withURLParam(withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/"+id, nil), user), "id", id))
	return rec
}

func TestAddDomain_RoleGate(t *testing.T) {
	h, _, _, log := domainRoleHandlers(t)

	for _, login := range []string{"dan-dev", "olga-owner"} {
		if rec := addDomainAs(h, erpactMember(login)); rec.Code != http.StatusCreated {
			t.Fatalf("%s: status = %d, want 201; body=%q", login, rec.Code, rec.Body.String())
		}
	}
	if n := len(log.List(10)); n != 0 {
		t.Fatalf("allowed adds wrote %d denial entries", n)
	}
	for _, login := range []string{"vic-viewer", "nora-norole", "gone"} {
		rec := addDomainAs(h, erpactMember(login))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403; body=%q", login, rec.Code, rec.Body.String())
		}
		if e := log.List(1)[0]; e.Status != "denied" || e.Operation != "add-custom-domain" || e.UserID != login {
			t.Fatalf("%s: audit entry = %+v", login, e)
		}
	}
}

// DELETE /domains/{id} submits remove-custom-domain itself, so it is the
// one route that reaches that owner-only operation without the execute
// path. A developer must be stopped before the workflow and before the row
// goes.
func TestDeleteDomain_RoleGate(t *testing.T) {
	h, store, exec, log := domainRoleHandlers(t)
	d := seedDomain(t, store, domains.StatusActive)

	for _, login := range []string{"dan-dev", "vic-viewer", "dup"} {
		rec := deleteDomainAs(h, d.ID, erpactMember(login))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403; body=%q", login, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `requires role \"owner\"`) {
			t.Errorf("%s: body does not name the required role: %s", login, rec.Body.String())
		}
		if e := log.List(1)[0]; e.Status != "denied" || e.Operation != "remove-custom-domain" || e.UserID != login {
			t.Fatalf("%s: audit entry = %+v", login, e)
		}
	}
	if len(exec.submitted) != 0 {
		t.Fatalf("a refused delete submitted a workflow: %+v", exec.submitted)
	}
	if _, err := store.Get(context.Background(), d.ID); err != nil {
		t.Fatalf("a refused delete removed the row: %v", err)
	}

	if rec := deleteDomainAs(h, d.ID, erpactMember("olga-owner")); rec.Code != http.StatusOK {
		t.Fatalf("owner: status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if len(exec.submitted) != 1 {
		t.Fatalf("owner's delete submitted %d workflows, want 1", len(exec.submitted))
	}
}

func TestDeleteDomain_UnreadableRoleIsUnavailable(t *testing.T) {
	h, store, exec, log := domainRoleHandlers(t)
	d := seedDomain(t, store, domains.StatusActive)
	h.opts.GitReader.(*stubRoles).err = errors.New("checkout is stale")

	rec := deleteDomainAs(h, d.ID, erpactMember("olga-owner"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%q", rec.Code, rec.Body.String())
	}
	if e := log.List(1)[0]; e.Status != "error" {
		t.Fatalf("audit status = %q, want error", e.Status)
	}
	if len(exec.submitted) != 0 {
		t.Fatal("a workflow was submitted without a role")
	}
	if _, err := store.Get(context.Background(), d.ID); err != nil {
		t.Fatalf("the row is gone: %v", err)
	}
}

func TestVerifyDomain_RoleGate(t *testing.T) {
	h, store, _, _ := domainRoleHandlers(t)
	d := seedDomain(t, store, domains.StatusPending)

	byID := func(user *auth.User) int {
		rec := httptest.NewRecorder()
		h.VerifyDomain(rec, withURLParam(withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+d.ID+"/verify", nil), user), "id", d.ID))
		return rec.Code
	}
	byName := func(user *auth.User) int {
		rec := httptest.NewRecorder()
		h.VerifyDomainByName(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/domains/verify",
			strings.NewReader(`{"team":"erpact","service":"web","domain":"`+d.Domain+`"}`)), user))
		return rec.Code
	}
	for name, call := range map[string]func(*auth.User) int{"by id": byID, "by name": byName} {
		if code := call(erpactMember("vic-viewer")); code != http.StatusForbidden {
			t.Errorf("%s: viewer got %d, want 403", name, code)
		}
		if code := call(erpactMember("dan-dev")); code != http.StatusOK {
			t.Errorf("%s: developer got %d, want 200", name, code)
		}
	}
}

// ── incidents ────────────────────────────────────────────────────────────────

func TestIncidentWrites_RoleGate(t *testing.T) {
	store := newTestAlertStore(t)
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AlertStore: store, GitReader: erpactRoles(), AuditLog: log}}

	seed := func() string {
		a, err := store.Create(context.Background(), &alerts.Alert{
			ID: "role-" + uuid.New().String()[:8], Source: "manual", Type: "workflow_failed",
			Tenant: "erpact", Summary: "test", Severity: "warning", Status: alerts.StatusOpen,
			Fingerprint: "fp-" + uuid.New().String()[:8],
		})
		if err != nil {
			t.Fatalf("seed incident: %v", err)
		}
		return a.ID
	}
	withID := func(method, body, id string, user *auth.User) *http.Request {
		return withURLParam(withUser(httptest.NewRequest(method, "/api/v1/incidents/"+id, strings.NewReader(body)), user), "id", id)
	}

	writes := map[string]struct {
		operation string
		call      func(user *auth.User) int
		wantOK    int
	}{
		"create": {"incident-create", func(u *auth.User) int {
			rec := httptest.NewRecorder()
			h.CreateIncident(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/incidents", strings.NewReader(
				`{"id":"c-`+uuid.New().String()[:8]+`","source":"manual","type":"workflow_failed","tenant":"erpact","summary":"s","severity":"warning"}`)), u))
			return rec.Code
		}, http.StatusCreated},
		"update": {"incident-update", func(u *auth.User) int {
			rec := httptest.NewRecorder()
			h.UpdateIncident(rec, withID(http.MethodPatch, `{"analysis":"looked"}`, seed(), u))
			return rec.Code
		}, http.StatusOK},
		"acknowledge": {"incident-ack", func(u *auth.User) int {
			rec := httptest.NewRecorder()
			h.AcknowledgeIncident(rec, withID(http.MethodPost, ``, seed(), u))
			return rec.Code
		}, http.StatusOK},
		"resolve": {"incident-resolve", func(u *auth.User) int {
			rec := httptest.NewRecorder()
			h.ResolveIncident(rec, withID(http.MethodPost, `{"reason":"fixed"}`, seed(), u))
			return rec.Code
		}, http.StatusOK},
		"resolve by fingerprint": {"incident-resolve", func(u *auth.User) int {
			rec := httptest.NewRecorder()
			h.ResolveIncidentByFingerprint(rec, withUser(httptest.NewRequest(http.MethodPost, "/api/v1/incidents/resolve-by-fingerprint",
				strings.NewReader(`{"tenant":"erpact","fingerprint":"nothing-matches"}`)), u))
			return rec.Code
		}, http.StatusOK},
	}
	for name, wr := range writes {
		t.Run(name, func(t *testing.T) {
			for _, login := range []string{"vic-viewer", "nora-norole"} {
				before := len(log.List(1000))
				if code := wr.call(erpactMember(login)); code != http.StatusForbidden {
					t.Fatalf("%s: status = %d, want 403", login, code)
				}
				entries := log.List(1000)
				if len(entries) != before+1 || entries[0].Status != "denied" || entries[0].Operation != wr.operation {
					t.Fatalf("%s: audit = %d new, newest %+v", login, len(entries)-before, entries[0])
				}
			}
			for _, login := range []string{"dan-dev", "olga-owner"} {
				if code := wr.call(erpactMember(login)); code != wr.wantOK {
					t.Fatalf("%s: status = %d, want %d", login, code, wr.wantOK)
				}
			}
			if code := wr.call(auth.NewServiceUser()); code != wr.wantOK {
				t.Fatalf("service principal: status = %d, want %d", code, wr.wantOK)
			}
		})
	}
}
