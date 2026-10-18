package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// incidentLookupRouter wires the four incident handlers that resolve an id
// through GetByPrefix behind a chi router, so {id} reaches chi.URLParam the
// way it does in production.
func incidentLookupRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Get("/api/v1/incidents/{id}", h.GetIncident)
	r.Patch("/api/v1/incidents/{id}", h.UpdateIncident)
	r.Post("/api/v1/incidents/{id}/ack", h.AcknowledgeIncident)
	r.Post("/api/v1/incidents/{id}/resolve", h.ResolveIncident)
	return r
}

func serveAsAdmin(router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: "tester", Groups: []string{"admins"}}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func seedIncidents(t *testing.T, store *alerts.Store, ids ...string) {
	t.Helper()
	for i, id := range ids {
		a := &alerts.Alert{
			ID:          id,
			Source:      alerts.SourceAlertManager,
			Type:        "workflow_failed",
			Tenant:      "admins",
			Service:     "mctl-agents",
			Summary:     "workflow failed",
			Severity:    alerts.SeverityWarning,
			Status:      alerts.StatusOpen,
			Fingerprint: fmt.Sprintf("lookup-fp-%d", i),
		}
		if _, err := store.Create(context.Background(), a); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
}

// incidentState is the part of an incident that PATCH, ack and resolve write.
type incidentState struct {
	Status, Analysis, AcknowledgedBy string
	Acked, Resolved                  bool
	UpdatedAt                        string
}

func stateOf(t *testing.T, store *alerts.Store, id string) incidentState {
	t.Helper()
	a, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return incidentState{
		Status:         a.Status,
		Analysis:       a.Analysis,
		AcknowledgedBy: a.AcknowledgedBy,
		Acked:          a.AcknowledgedAt != nil,
		Resolved:       a.ResolvedAt != nil,
		UpdatedAt:      a.UpdatedAt.String(),
	}
}

// TestMutatingIncidentHandlers_AmbiguousPrefix_ChangesNothing pins the safety
// property of #707: a mutating call whose id matches more than one incident
// is refused with 409 and writes nothing. The old lookup returned the newest
// match, so these calls answered 200 and changed pfx-aaaa-0002.
func TestMutatingIncidentHandlers_AmbiguousPrefix_ChangesNothing(t *testing.T) {
	store := newTestAlertStore(t)
	seedIncidents(t, store, "pfx-aaaa-0001", "pfx-aaaa-0002", "pfx-bbbb-0001")
	router := incidentLookupRouter(&Handlers{opts: Options{AlertStore: store}})

	before := map[string]incidentState{
		"pfx-aaaa-0001": stateOf(t, store, "pfx-aaaa-0001"),
		"pfx-aaaa-0002": stateOf(t, store, "pfx-aaaa-0002"),
	}

	calls := []struct{ name, method, path, body string }{
		{"patch", http.MethodPatch, "/api/v1/incidents/pfx-aaaa", `{"status":"resolved","analysis":"x"}`},
		{"ack", http.MethodPost, "/api/v1/incidents/pfx-aaaa/ack", ``},
		{"resolve", http.MethodPost, "/api/v1/incidents/pfx-aaaa/resolve", `{"reason":"x"}`},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			rec := serveAsAdmin(router, c.method, c.path, c.body)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
			}
			for id, want := range before {
				if got := stateOf(t, store, id); got != want {
					t.Fatalf("%s changed after refused %s:\n got  %+v\n want %+v", id, c.name, got, want)
				}
			}
		})
	}

	// Positive control: the same setup does mutate through a unique prefix,
	// so the refusals above are not an artifact of auth or wiring.
	rec := serveAsAdmin(router, http.MethodPost, "/api/v1/incidents/pfx-bbbb/resolve", `{"reason":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unique prefix resolve: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := stateOf(t, store, "pfx-bbbb-0001"); got.Status != alerts.StatusResolved || !got.Resolved {
		t.Fatalf("unique prefix resolve did not resolve: %+v", got)
	}
}

// TestIncidentHandlers_LookupStatusMapping checks the status codes end to end
// through a handler, including the 400 message, which must name the store's
// actual minimum.
func TestIncidentHandlers_LookupStatusMapping(t *testing.T) {
	store := newTestAlertStore(t)
	seedIncidents(t, store, "pfx-aaaa-0001", "pfx-aaaa-0002")
	router := incidentLookupRouter(&Handlers{opts: Options{AlertStore: store}})

	cases := []struct {
		id   string
		want int
	}{
		{"pfx", http.StatusBadRequest},
		{"pfx-zzzz", http.StatusNotFound},
		{"pfx-aaaa", http.StatusConflict},
		{"pfx-aaaa-0001", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			rec := serveAsAdmin(router, http.MethodGet, "/api/v1/incidents/"+c.id, "")
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.want, rec.Body.String())
			}
			if c.want == http.StatusBadRequest {
				want := fmt.Sprintf("at least %d characters", alerts.MinPrefixLen)
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("400 body %q does not contain %q", rec.Body.String(), want)
				}
			}
		})
	}
}
