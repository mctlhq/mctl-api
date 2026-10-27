package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	mctlmcp "github.com/mctlhq/mctl-api/internal/mcp"
)

func supportBody(over map[string]any) []byte {
	m := map[string]any{
		"id": "inc-1", "source": "support", "type": "platform_defect", "tenant": "t1",
		"summary": "secret summary", "severity": "warning", "fingerprint": "support:platform_defect:abc",
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	raw, _ := json.Marshal(m)
	return raw
}

func TestSupportIncidentProducer_IsConfinedToCreatingIncidents(t *testing.T) {
	router := NewRouter(Options{
		AuthMiddleware: injectUser(auth.NewSupportIncidentProducerUser()),
		MCPServer:      mctlmcp.NewServer("http://127.0.0.1:1", ""),
	})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/incidents"},
		{http.MethodGet, "/api/v1/incidents/summary"},
		{http.MethodGet, "/api/v1/incidents/abc"},
		{http.MethodPatch, "/api/v1/incidents/abc"},
		{http.MethodPost, "/api/v1/incidents/abc/ack"},
		{http.MethodPost, "/api/v1/incidents/abc/resolve"},
		{http.MethodPost, "/api/v1/incidents/resolve-by-fingerprint"},
		{http.MethodGet, "/api/v1/incidents/support/aggregation"},
		{http.MethodGet, "/api/v1/whoami"},
		{http.MethodGet, "/api/v1/tenants"},
		{http.MethodPost, "/api/v1/usage/records"},
		{http.MethodPost, "/mcp"},
		{http.MethodGet, "/mcp"},
		{http.MethodPost, "/api/v1/incidents/"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), codeSupportProducerRouteNotAllowed) {
			t.Errorf("%s %s: got %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/incidents", bytes.NewReader(supportBody(nil))))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("valid create: got %d %s, want 503 from the handler", rec.Code, rec.Body.String())
	}
}

func postIncidentAs(h *Handlers, u *auth.User, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/incidents", bytes.NewReader(body))
	req = req.WithContext(auth.WithUser(req.Context(), u))
	rec := httptest.NewRecorder()
	h.CreateIncident(rec, req)
	return rec
}

func TestSupportIncidentProducer_FieldConfinement(t *testing.T) {
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AuditLog: log}}
	producer := auth.NewSupportIncidentProducerUser()

	for _, c := range []struct {
		name string
		over map[string]any
		want int
		code string
	}{
		{"manual source", map[string]any{"source": "manual"}, 403, codeSupportSourceNotAllowed},
		{"alertmanager source", map[string]any{"source": "alertmanager"}, 403, codeSupportSourceNotAllowed},
		{"unknown type", map[string]any{"type": "other"}, 403, codeSupportTypeNotAllowed},
		{"missing fingerprint", map[string]any{"fingerprint": nil}, 400, ""},
		{"bad fingerprint", map[string]any{"fingerprint": "x"}, 400, ""},
		{"valid", nil, 503, ""},
		{"valid needs_owner other tenant", map[string]any{"type": "needs_owner", "tenant": "elsewhere"}, 503, ""},
	} {
		rec := postIncidentAs(h, producer, supportBody(c.over))
		if rec.Code != c.want || (c.code != "" && !strings.Contains(rec.Body.String(), c.code)) {
			t.Errorf("%s: got %d %s", c.name, rec.Code, rec.Body.String())
		}
	}

	denied := 0
	for _, e := range log.List(100) {
		if e.Operation == "incident-create" && e.Status == "denied" {
			denied++
			if e.UserID != auth.SupportIncidentProducerUserID {
				t.Errorf("denied row user = %q", e.UserID)
			}
		}
	}
	if denied != 3 {
		t.Errorf("denied audit rows = %d, want 3", denied)
	}

	// A tenant member posting to a tenant it does not belong to is unchanged.
	member := &auth.User{ID: "m", Groups: []string{"other-tenant"}}
	if rec := postIncidentAs(h, member, supportBody(nil)); rec.Code != http.StatusForbidden {
		t.Errorf("member: got %d %s, want 403", rec.Code, rec.Body.String())
	}
}

func TestSupportIncidentAggregation_Authorization(t *testing.T) {
	h := &Handlers{opts: Options{}}
	get := func(u *auth.User) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/support/aggregation", nil)
		if u != nil {
			req = req.WithContext(auth.WithUser(req.Context(), u))
		}
		rec := httptest.NewRecorder()
		h.SupportIncidentAggregation(rec, req)
		return rec.Code
	}
	for name, u := range map[string]*auth.User{
		"member":   {ID: "m", Groups: []string{"t1"}},
		"surface":  auth.NewSurfaceUser("telegram"),
		"usage":    auth.NewUsageWriterUser(),
		"producer": auth.NewSupportIncidentProducerUser(),
	} {
		if got := get(u); got != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, got)
		}
	}
	if got := get(&auth.User{ID: "a", Groups: []string{"admins"}}); got != http.StatusServiceUnavailable {
		t.Errorf("admin without store: got %d, want 503", got)
	}
}
