package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

type signupAdminResolver struct{}

func (signupAdminResolver) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return "prn_01M45DR1GWC87109EH88VBJX26", nil
}
func signupAdminUser(t *testing.T) *auth.User {
	t.Helper()
	u := auth.NewGitHubUser("root", []string{"admins"})
	if err := auth.AttachPrincipal(context.Background(), signupAdminResolver{}, u); err != nil {
		t.Fatal(err)
	}
	return u
}
func signupStore(t *testing.T) *principals.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	s, err := principals.NewStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func TestSignupAdminRefusesServiceRelayAndNonAdmin(t *testing.T) {
	h := &Handlers{}
	admin := signupAdminUser(t)
	users := []*auth.User{nil, auth.NewServiceUser(), auth.NewSurfaceUser("portal"), auth.NewGitHubUser("customer", nil), auth.NewRelayedPrincipalUser("root", admin.PrincipalID(), auth.NewSurfaceUser("portal"))}
	for _, u := range users {
		r := httptest.NewRequest("GET", "/", nil)
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		h.GetSignupCapacity(w, r)
		if w.Code != 403 {
			t.Fatalf("user %+v status %d", u, w.Code)
		}
	}
}
func TestSignupUnknownListingIsNeverEmptyQueue(t *testing.T) {
	s := signupStore(t)
	for _, body := range []string{`{}`, `{"requests":[],"complete":false}`, `{"requests":[{}],"complete":true}`} {
		h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s, SiteCall: func(context.Context, string, string, []byte) ([]byte, error) { return []byte(body), nil }}}}
		r := httptest.NewRequest("GET", "/", nil)
		r = r.WithContext(auth.WithUser(r.Context(), signupAdminUser(t)))
		w := httptest.NewRecorder()
		h.ListSignupRequests(w, r)
		if w.Code != 503 {
			t.Fatalf("malformed %s status %d", body, w.Code)
		}
	}
}
func TestSignupApprovalAtZeroBudgetDoesNotGrantOrNotify(t *testing.T) {
	s := signupStore(t)
	ctx := context.Background()
	if err := s.SetSignupCapacity(ctx, 0, "admin", "Fresh zero budget test"); err != nil {
		t.Fatal(err)
	}
	original := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Test", Email: "test@example.com", GitHub: "test-user", Project: "Test project"}
	raw, _ := json.Marshal(original)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":98765,"login":"test-user"}`))
	}))
	defer github.Close()
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s, GitHubURL: github.URL, SiteCall: func(_ context.Context, method, path string, _ []byte) ([]byte, error) {
		if method != "GET" {
			t.Fatal("notification before saved approval")
		}
		return raw, nil
	}}}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"decision":"approved","reason":"Welcome","confirm":"yes"}`))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", original.ID)
	r = r.WithContext(context.WithValue(auth.WithUser(r.Context(), signupAdminUser(t)), chi.RouteCtxKey, route))
	w := httptest.NewRecorder()
	h.DecideSignupRequest(w, r)
	if w.Code != 409 {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	if allowed, err := s.SignupAllowed(ctx, "98765"); err != nil || allowed {
		t.Fatalf("granted %v %v", allowed, err)
	}
	d, err := s.Signup(ctx, original.ID)
	if err != nil || d.Status != "pending" || d.NotificationPending {
		t.Fatalf("decision %+v %v", d, err)
	}
}
func TestSignupGitHubLookupRefusesUnknownRedirectOrChangedIdentity(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{503, `{}`}, {302, `{}`}, {200, `{"id":123,"login":"other"}`}, {200, `{"id":0,"login":"test-user"}`}, {200, `{"login":"test-user"}`}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		h := &Handlers{opts: Options{Signup: &SignupOptions{GitHubURL: server.URL}}}
		_, _, err := h.resolveSignupGitHub(context.Background(), "test-user")
		server.Close()
		if err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
func TestSignupClaimRefusesCustomerCallingSurfaceEndpoint(t *testing.T) {
	h := &Handlers{}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	r = r.WithContext(auth.WithUser(r.Context(), auth.NewGitHubUser("customer", nil)))
	w := httptest.NewRecorder()
	h.ClaimSignup(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestSignupClaimChecksIdentityProfileAndWorkspace(t *testing.T) {
	s := signupStore(t)
	ctx := context.Background()
	principal, err := s.Provision(ctx, auth.Identity{Provider: auth.ProviderGitHub, Subject: "987654321", Display: "test-profile", Kind: auth.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.ReleaseSignupClaim(ctx, principal.ID); err != nil {
			t.Error(err)
		}
	})
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed test resource capacity"); err != nil {
		t.Fatal(err)
	}
	request := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Test", Email: "test@example.com", GitHub: "test-profile", Project: "Test profile"}
	if err := s.ImportSignup(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideSignup(ctx, request.ID, "approved", "987654321", "test-profile", "admin", "Welcome"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s}}}
	missingActor := httptest.NewRequest("POST", "/api/v1/surface-principals/signup-claim", strings.NewReader(`{}`))
	missingActor = missingActor.WithContext(auth.WithUser(missingActor.Context(), auth.NewSurfaceUser("portal")))
	refused := httptest.NewRecorder()
	h.surfacePrincipalGate(http.HandlerFunc(h.ClaimSignup)).ServeHTTP(refused, missingActor)
	if refused.Code != 400 {
		t.Fatalf("missing surface actor: %d", refused.Code)
	}
	claim := map[string]string{"principal_id": principal.ID, "tenant": "new-team", "memory": "2Gi", "cpu": "1", "memory_limit": "3Gi", "cpu_limit": "2", "pods": "10", "pvcs": "5", "services": "10"}
	call := func() *httptest.ResponseRecorder {
		raw, _ := json.Marshal(claim)
		r := httptest.NewRequest("POST", "/api/v1/surface-principals/signup-claim", strings.NewReader(string(raw)))
		r = r.WithContext(auth.WithUser(r.Context(), auth.NewSurfaceUser("portal")))
		r.Header.Set(SurfaceActorHeader, "principal:"+principal.ID)
		w := httptest.NewRecorder()
		h.surfacePrincipalGate(http.HandlerFunc(h.ClaimSignup)).ServeHTTP(w, r)
		return w
	}
	claim["memory"] = "8Gi"
	if w := call(); w.Code != 409 {
		t.Fatalf("oversized request: %d %s", w.Code, w.Body.String())
	}
	claim["memory"] = "2Gi"
	claim["pvcs"] = "100"
	if w := call(); w.Code != 409 {
		t.Fatalf("oversized storage count: %d %s", w.Code, w.Body.String())
	}
	claim["pvcs"] = "5"
	for n := 0; n < 2; n++ {
		if w := call(); w.Code != 200 {
			t.Fatalf("valid/retry: %d %s", w.Code, w.Body.String())
		}
	}
	claim["tenant"] = "second-team"
	if w := call(); w.Code != 409 {
		t.Fatalf("second workspace: %d %s", w.Code, w.Body.String())
	}
}
