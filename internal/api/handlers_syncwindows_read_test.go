package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-api/internal/argocd"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// statusOnlyArgo is an ArgoStatusClient with no sync windows reader.
type statusOnlyArgo struct{}

func (statusOnlyArgo) GetAppStatus(string) (*argocd.AppStatus, error) { return nil, nil }
func (statusOnlyArgo) GetProjectAppStatus(string, string) (*argocd.AppStatus, error) {
	return nil, nil
}
func (statusOnlyArgo) ListApps(string) ([]argocd.AppStatus, error) { return nil, nil }
func (statusOnlyArgo) ListWorkloads() ([]argocd.Workload, error)   { return nil, nil }

// syncWindowsArgo is an ArgoStatusClient that also reads sync windows.
type syncWindowsArgo struct {
	statusOnlyArgo
	project    *argocd.ProjectSyncWindows
	projectErr error
	app        *argocd.AppSyncWindows
	appErr     error
	calls      int
}

func (f *syncWindowsArgo) GetProjectSyncWindows(string) (*argocd.ProjectSyncWindows, error) {
	f.calls++
	return f.project, f.projectErr
}

func (f *syncWindowsArgo) GetAppSyncWindows(string, string) (*argocd.AppSyncWindows, error) {
	f.calls++
	return f.app, f.appErr
}

func syncWindowsCall(opts Options, target string, user *auth.User) (int, map[string]any) {
	h := &Handlers{opts: opts}
	rec := assetsRequest(h, h.GetSyncWindows, "/api/v1/sync-windows", target, user)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

var (
	swAdmin  = &auth.User{ID: "alice", Groups: []string{"admins"}}
	swTenant = &auth.User{ID: "bob", Groups: []string{"acme"}}
)

func TestGetSyncWindowsAdminReadsProjectAndApp(t *testing.T) {
	a := &syncWindowsArgo{
		project: &argocd.ProjectSyncWindows{Project: "admins", Windows: []argocd.SyncWindow{{Kind: "deny", Schedule: "0 22 * * *", Duration: "8h"}}},
		app:     &argocd.AppSyncWindows{Application: "admins-mctl-api", CanSync: false, ActiveWindows: []argocd.AppSyncWindow{{Kind: "deny"}}, AssignedWindows: []argocd.AppSyncWindow{{Kind: "deny"}}},
	}
	code, body := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows?project=admins&application=admins-mctl-api", swAdmin)
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %v", code, body)
	}
	if body["project"] != "admins" || len(body["windows"].([]any)) != 1 {
		t.Errorf("body = %v", body)
	}
	app := body["application"].(map[string]any)
	if app["name"] != "admins-mctl-api" || app["canSync"] != false {
		t.Errorf("application = %v", app)
	}
}

func TestGetSyncWindowsProjectOnlyOmitsApplication(t *testing.T) {
	a := &syncWindowsArgo{project: &argocd.ProjectSyncWindows{Project: "admins", Windows: []argocd.SyncWindow{}}}
	code, body := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows?project=admins", swAdmin)
	if code != http.StatusOK {
		t.Fatalf("code = %d", code)
	}
	if _, has := body["application"]; has {
		t.Errorf("application present without being asked: %v", body)
	}
	if w, ok := body["windows"].([]any); !ok || len(w) != 0 {
		t.Errorf("windows = %#v, want []", body["windows"])
	}
}

func TestGetSyncWindowsIsAdminOnly(t *testing.T) {
	a := &syncWindowsArgo{project: &argocd.ProjectSyncWindows{Project: "admins"}}
	if code, _ := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows?project=admins", nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous: code = %d, want 401", code)
	}
	if code, _ := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows?project=admins", swTenant); code != http.StatusForbidden {
		t.Errorf("tenant user: code = %d, want 403", code)
	}
	if a.calls != 0 {
		t.Errorf("argocd was called %d times for callers that must be refused", a.calls)
	}
}

func TestGetSyncWindowsNeedsAProject(t *testing.T) {
	a := &syncWindowsArgo{}
	if code, _ := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows", swAdmin); code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
}

// A client that cannot read windows is "not configured", never an empty list.
func TestGetSyncWindowsUnavailableWithoutReader(t *testing.T) {
	for name, o := range map[string]Options{"nil client": {}, "status-only client": {ArgoCD: statusOnlyArgo{}}} {
		if code, _ := syncWindowsCall(o, "/api/v1/sync-windows?project=admins", swAdmin); code != http.StatusServiceUnavailable {
			t.Errorf("%s: code = %d, want 503", name, code)
		}
	}
}

// Either read failing fails the call: a project that was read must not be
// returned as if its application's state were known.
func TestGetSyncWindowsPartialFailureFailsTheCall(t *testing.T) {
	a := &syncWindowsArgo{
		project: &argocd.ProjectSyncWindows{Project: "admins", Windows: []argocd.SyncWindow{}},
		appErr:  fmt.Errorf("argocd request failed"),
	}
	code, body := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows?project=admins&application=x", swAdmin)
	if code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", code)
	}
	if _, has := body["windows"]; has {
		t.Errorf("partial result leaked into the error body: %v", body)
	}
}

func TestGetSyncWindowsMapsArgoErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"not found": {fmt.Errorf("%w: gone", argocd.ErrNotFound), http.StatusNotFound},
		"forbidden": {fmt.Errorf("%w: denied", argocd.ErrForbidden), http.StatusBadGateway},
		"other":     {fmt.Errorf("boom"), http.StatusBadGateway},
	} {
		a := &syncWindowsArgo{projectErr: tc.err}
		if code, _ := syncWindowsCall(Options{ArgoCD: a}, "/api/v1/sync-windows?project=admins", swAdmin); code != tc.want {
			t.Errorf("%s: code = %d, want %d", name, code, tc.want)
		}
	}
}
