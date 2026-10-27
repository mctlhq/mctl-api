package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-api/internal/alerts"
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

// T5 + T7: producer writes through the real store, the aggregation over them,
// and the one succeeded audit row per create (Postgres-backed).
func TestSupportIncidentProducer_StoreAggregationAndAudit(t *testing.T) {
	store := newTestAlertStore(t)
	log := audit.NewLogger()
	h := &Handlers{opts: Options{AuditLog: log, AlertStore: store}}
	producer := auth.NewSupportIncidentProducerUser()
	admin := &auth.User{ID: "a", Groups: []string{"admins"}}
	fp := "support:platform_defect:abc123"

	post := func(id, tenant string, over map[string]any) map[string]any {
		t.Helper()
		body := map[string]any{"id": id, "tenant": tenant, "fingerprint": fp}
		for k, v := range over {
			body[k] = v
		}
		rec := postIncidentAs(h, producer, supportBody(body))
		if rec.Code != http.StatusCreated {
			t.Fatalf("post %s/%s: got %d %s", id, tenant, rec.Code, rec.Body.String())
		}
		var got map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		return got
	}
	aggregate := func() []map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/support/aggregation", nil)
		req = req.WithContext(auth.WithUser(req.Context(), admin))
		rec := httptest.NewRecorder()
		h.SupportIncidentAggregation(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("aggregation: got %d %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Items []map[string]any `json:"items"`
			Count int              `json:"count"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Count != len(out.Items) {
			t.Fatalf("count %d != len(items) %d", out.Count, len(out.Items))
		}
		return out.Items
	}

	first := post("inc-t1", "t1", map[string]any{"status": "resolved"})
	second := post("inc-t2", "t2", nil)
	if first["id"] == second["id"] {
		t.Fatalf("two tenants share an incident: %v", first["id"])
	}
	if first["status"] != "open" {
		t.Fatalf("status = %v, want open even when the body said resolved", first["status"])
	}
	items := aggregate()
	if len(items) != 1 || items[0]["fingerprint"] != fp || items[0]["type"] != "platform_defect" ||
		items[0]["count"] != float64(2) || fmt.Sprint(items[0]["affected_tenants"]) != "[t1 t2]" {
		t.Fatalf("aggregation = %v", items)
	}

	// A repeat for t1 joins the open incident and does not count twice.
	again := post("inc-t1-again", "t1", nil)
	if again["id"] != "inc-t1" {
		t.Fatalf("dedup returned %v, want inc-t1", again["id"])
	}
	if items := aggregate(); items[0]["count"] != float64(2) {
		t.Fatalf("count after dedup = %v, want 2", items[0]["count"])
	}

	// A non-support incident with the same fingerprint is not aggregated.
	if _, err := store.Create(context.Background(), &alerts.Alert{
		ID: "manual-1", Source: "manual", Type: "platform_defect", Tenant: "t3",
		Summary: "s", Severity: "warning", Status: "open", Fingerprint: fp,
	}); err != nil {
		t.Fatalf("manual create: %v", err)
	}
	// Resolving t1's incident drops it from the open groups.
	if _, err := store.ResolveByFingerprint(context.Background(), "t1", fp, "a"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if items := aggregate(); len(items) != 1 || items[0]["count"] != float64(1) || fmt.Sprint(items[0]["affected_tenants"]) != "[t2]" {
		t.Fatalf("aggregation after resolve = %v", items)
	}

	var rows []audit.Entry
	for _, e := range log.List(100) {
		if e.Operation == "incident-create" && e.Status == "succeeded" {
			rows = append(rows, e)
		}
	}
	if len(rows) != 3 {
		t.Fatalf("succeeded audit rows = %d, want 3 (one per producer create)", len(rows))
	}
	dedups := 0
	for _, e := range rows {
		p := e.Parameters
		if e.UserID != auth.SupportIncidentProducerUserID || p["actor"] != auth.SupportIncidentProducerUserID ||
			p["source"] != "support" || p["type"] != "platform_defect" || p["fingerprint"] != fp || p["tenant"] == "" {
			t.Errorf("audit row = %+v", e)
		}
		if p["deduplicated"] == "true" {
			dedups++
			if p["incident_id"] != "inc-t1" || p["requested_id"] != "inc-t1-again" {
				t.Errorf("dedup row = %+v", p)
			}
		}
		for k, v := range p {
			if strings.Contains(v, "secret summary") {
				t.Errorf("audit parameter %s carries the summary", k)
			}
		}
		if strings.Contains(e.Message, "secret summary") {
			t.Errorf("audit message carries the summary")
		}
	}
	if dedups != 1 {
		t.Errorf("deduplicated rows = %d, want 1", dedups)
	}
}
