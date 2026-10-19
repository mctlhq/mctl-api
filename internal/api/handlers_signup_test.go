package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	federatedService := auth.NewFederatedUser("oidc", "https://issuer.example", "service-subject", "service", auth.KindService)
	federatedService.Groups = []string{"admins"}
	if err := auth.AttachPrincipal(context.Background(), signupAdminResolver{}, federatedService); err != nil {
		t.Fatal(err)
	}
	users := []*auth.User{nil, federatedService, auth.NewServiceUser(), auth.NewSurfaceUser("portal"), auth.NewGitHubUser("customer", nil), auth.NewRelayedPrincipalUser("root", admin.PrincipalID(), auth.NewSurfaceUser("portal"))}
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
	for _, body := range []string{`{}`, `{"requests":[],"complete":false}`, `{"requests":null,"complete":true}`} {
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
	cleanupSignupRows(t, principal.ID)
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
	reader := &signupFixtureReader{}
	h := &Handlers{opts: Options{GitReader: reader, Signup: &SignupOptions{Store: s}}}
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
	reader.names = []string{"new"}
	if w := call(); w.Code != 400 {
		t.Fatalf("surface name collision: %d %s", w.Code, w.Body.String())
	}
	reader.names = []string{}
	claim["tenant"] = "argocd"
	if w := call(); w.Code != 400 {
		t.Fatalf("reserved surface name: %d", w.Code)
	}
	before, err := s.Signup(ctx, request.ID)
	if err != nil || before.Status != "approved" || before.Tenant != "" {
		t.Fatalf("surface refusal spent claim: %+v %v", before, err)
	}
	claim["tenant"] = "new-team"
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

func cleanupSignupRows(t *testing.T, id string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		conn, err := pgx.Connect(ctx, os.Getenv("TEST_DATABASE_URL"))
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, `DELETE FROM signup_requests WHERE id::text=$1 OR principal_id=$1`, id); err != nil {
			t.Error(err)
		}
	})
}

func TestSignupQueueReturnsHealthyRecordsAndExplicitUnknownItems(t *testing.T) {
	s := signupStore(t)
	good := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: strings.Repeat("я", 80), Email: "test@example.com", Project: strings.Repeat("я", 800)}
	cleanupSignupRows(t, good.ID)
	expired := good
	expired.ID = uuid.NewString()
	expired.CreatedAt = time.Now().Add(-91 * 24 * time.Hour)
	badID := uuid.NewString()
	page, _ := json.Marshal(map[string]any{"requests": []any{good, map[string]any{"id": uuid.NewString()}, expired}, "issues": []any{map[string]string{"id": badID, "error": "record_unreadable"}}, "complete": false, "traversal_complete": true, "cursor": ""})
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s, SiteCall: func(context.Context, string, string, []byte) ([]byte, error) { return page, nil }}}}
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(auth.WithUser(r.Context(), signupAdminUser(t)))
	w := httptest.NewRecorder()
	h.ListSignupRequests(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Requests    []principals.SignupDecision `json:"requests"`
		Issues      []any                       `json:"issues"`
		Complete    bool                        `json:"complete"`
		Traversal   bool                        `json:"traversal_complete"`
		Observation string                      `json:"observation"`
		Expired     []string                    `json:"expired"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Requests) != 1 || len(body.Issues) != 2 || body.Complete || !body.Traversal || body.Observation != "partial" || len(body.Expired) != 1 {
		t.Fatalf("unexpected listing %+v", body)
	}
	if body.Requests[0].Request.Name != good.Name {
		t.Fatal("valid Unicode submission was hidden")
	}
}
func TestSignupQueueConflictDoesNotOverwriteRecipientOrHideOtherRequests(t *testing.T) {
	s := signupStore(t)
	ctx := context.Background()
	original := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Original", Email: "original@example.com", Project: "Project"}
	cleanupSignupRows(t, original.ID)
	if err := s.ImportSignup(ctx, original); err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.Email = "changed@example.com"
	good := original
	good.ID = uuid.NewString()
	cleanupSignupRows(t, good.ID)
	page, _ := json.Marshal(map[string]any{"requests": []any{changed, good}, "issues": []any{}, "complete": true, "traversal_complete": true, "cursor": ""})
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s, SiteCall: func(context.Context, string, string, []byte) ([]byte, error) { return page, nil }}}}
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(auth.WithUser(r.Context(), signupAdminUser(t)))
	w := httptest.NewRecorder()
	h.ListSignupRequests(w, r)
	var result map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatalf("status %d", w.Code)
	}
	if result["complete"] != false || len(result["requests"].([]any)) != 1 || len(result["issues"].([]any)) != 1 {
		t.Fatalf("partial listing missing: %s", w.Body.String())
	}
	saved, err := s.Signup(ctx, original.ID)
	if err != nil || saved.Request.Email != original.Email {
		t.Fatalf("contact overwritten: %v", err)
	}
}
func TestSignupExplicitGitHubCorrectionWinsOverUnverifiedSubmission(t *testing.T) {
	s := signupStore(t)
	ctx := context.Background()
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed resource budget"); err != nil {
		t.Fatal(err)
	}
	original := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Test", Email: "test@example.com", GitHub: "provided-typo", Project: "Project"}
	cleanupSignupRows(t, original.ID)
	raw, _ := json.Marshal(original)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/corrected-user" {
			t.Errorf("ignored explicit login: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":98766001,"login":"corrected-user"}`))
	}))
	defer github.Close()
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s, GitHubURL: github.URL, SiteCall: func(context.Context, string, string, []byte) ([]byte, error) { return raw, nil }}}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"decision":"approved","reason":"Welcome","github":"corrected-user","confirm":"yes"}`))
	route := chi.NewRouteContext()
	route.URLParams.Add("id", original.ID)
	r = r.WithContext(context.WithValue(auth.WithUser(r.Context(), signupAdminUser(t)), chi.RouteCtxKey, route))
	w := httptest.NewRecorder()
	h.DecideSignupRequest(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	saved, err := s.Signup(ctx, original.ID)
	if err != nil || saved.GitHubID != "98766001" || saved.GitHubLogin != "corrected-user" || saved.Request.GitHub != "provided-typo" {
		t.Fatalf("identity correction lost: %+v %v", saved, err)
	}
}

func TestSignupAmbiguousOrDisabledPrincipalIsRefused(t *testing.T) {
	s := signupStore(t)
	ctx := context.Background()
	number := time.Now().UnixNano()
	principal, err := s.Provision(ctx, auth.Identity{Provider: auth.ProviderGitHub, Subject: strconv.FormatInt(number, 10), Display: "ambiguous-one", Kind: auth.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkIdentity(ctx, principal.ID, auth.Identity{Provider: auth.ProviderGitHub, Subject: strconv.FormatInt(number+1, 10), Issuer: "https://another-issuer.example", Display: "ambiguous-two", Kind: auth.KindHuman}); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s}}}
	if status, message := h.claimSignupPrincipal(ctx, principal.ID, "new-team", "2Gi", "1", "3Gi", "2", "10", "5", "10"); status != 409 || !strings.Contains(message, "ambiguous") {
		t.Fatalf("ambiguous identity: %d %s", status, message)
	}
	if err := s.SetStatus(ctx, principal.ID, principals.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.claimSignupPrincipal(ctx, principal.ID, "new-team", "2Gi", "1", "3Gi", "2", "10", "5", "10"); status != 403 {
		t.Fatalf("disabled principal admitted: %d", status)
	}
}

func TestSignupBridgeCompatibilityProblemsAreExplicitlyPartial(t *testing.T) {
	s := signupStore(t)
	good := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Test", Email: "test@example.com", Project: "Project"}
	cleanupSignupRows(t, good.ID)
	for _, mode := range []string{"missing_issues", "missing_traversal", "missing_completion", "conflicting_completion", "new_issue_code", "provider_partial"} {
		page := map[string]any{"requests": []any{good}, "issues": []any{}, "complete": true, "traversal_complete": true, "cursor": ""}
		switch mode {
		case "missing_issues":
			delete(page, "issues")
		case "missing_traversal":
			delete(page, "traversal_complete")
		case "missing_completion":
			delete(page, "complete")
		case "conflicting_completion":
			page["complete"] = false
		case "new_issue_code":
			page["issues"] = []any{map[string]string{"id": good.ID, "error": "future_provider_error"}}
			page["complete"] = false
		case "provider_partial":
			page["observation"] = "partial"
		}
		raw, _ := json.Marshal(page)
		h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s, SiteCall: func(context.Context, string, string, []byte) ([]byte, error) { return raw, nil }}}}
		r := httptest.NewRequest("GET", "/", nil)
		r = r.WithContext(auth.WithUser(r.Context(), signupAdminUser(t)))
		w := httptest.NewRecorder()
		h.ListSignupRequests(w, r)
		var body map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("%s status %d", mode, w.Code)
		}
		if body["complete"] != false || body["traversal_complete"] != true || body["observation"] != "partial" || len(body["requests"].([]any)) != 1 || len(body["issues"].([]any)) == 0 {
			t.Fatalf("%s lost partial observation: %s", mode, w.Body.String())
		}
	}
}
func TestSignupExistingPrincipalIsNotAnInvitation(t *testing.T) {
	s := signupStore(t)
	ctx := context.Background()
	id := strconv.FormatInt(time.Now().UnixNano(), 10)
	principal, err := s.Provision(ctx, auth.Identity{Provider: auth.ProviderGitHub, Subject: id, Display: "existing-budget-test", Kind: auth.KindHuman})
	if err != nil {
		t.Fatal(err)
	}
	cleanupSignupRows(t, principal.ID)
	if err := s.SetSignupCapacity(ctx, 1, "admin", "Reviewed funded capacity"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{opts: Options{Signup: &SignupOptions{Store: s}}}
	claim := func(name string) (int, string) {
		return h.claimSignupPrincipal(ctx, principal.ID, name, "2Gi", "1", "3Gi", "2", "10", "5", "10")
	}
	if status, _ := claim("new-team"); status != 409 {
		t.Fatalf("existing uninvited principal bypassed private signup: %d", status)
	}
	request := principals.SignupRequest{ID: uuid.NewString(), CreatedAt: time.Now().UTC(), Name: "Test", Email: "test@example.com", GitHub: "existing-budget-test", Project: "Test"}
	cleanupSignupRows(t, request.ID)
	if err := s.ImportSignup(ctx, request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideSignup(ctx, request.ID, "approved", id, "existing-budget-test", "admin", "Welcome"); err != nil {
		t.Fatal(err)
	}
	if status, message := claim("new-team"); status != 0 {
		t.Fatalf("approved existing principal refused: %d %s", status, message)
	}
	if status, _ := claim("another-team"); status != 409 {
		t.Fatalf("existing principal bypassed one-workspace rule: %d", status)
	}
}

type signupFixtureReader struct {
	GitReader
	names []string
}

func (r *signupFixtureReader) TenantNames() ([]string, error) { return r.names, nil }
