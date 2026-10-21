package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-api/internal/alerts"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
)

// The admin test caller of serveAsAdmin, as principalOf renders it.
const incidentAuditActor = "oidc:tester"

func serveAs(router http.Handler, userID, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: userID, Groups: []string{"admins"}}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func incidentAuditRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Patch("/api/v1/incidents/{id}", h.UpdateIncident)
	r.Post("/api/v1/incidents/{id}/ack", h.AcknowledgeIncident)
	r.Post("/api/v1/incidents/{id}/resolve", h.ResolveIncident)
	r.Post("/api/v1/incidents/resolve-by-fingerprint", h.ResolveIncidentByFingerprint)
	return r
}

// successRows returns the succeeded audit rows for op, oldest first.
func successRows(log *audit.Logger, op string) []audit.Entry {
	var out []audit.Entry
	all := log.List(0)
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Operation == op && all[i].Status == "succeeded" {
			out = append(out, all[i])
		}
	}
	return out
}

func wantIncidentRow(t *testing.T, log *audit.Logger, op string, want map[string]string) {
	t.Helper()
	rows := successRows(log, op)
	if len(rows) != 1 {
		t.Fatalf("%s: %d succeeded audit rows, want 1: %+v", op, len(rows), log.List(0))
	}
	got := rows[0]
	if got.UserID != "tester" || got.RiskLevel != "low" {
		t.Fatalf("%s: user=%q risk=%q, want tester/low", op, got.UserID, got.RiskLevel)
	}
	for k, v := range want {
		if got.Parameters[k] != v {
			t.Fatalf("%s: parameter %s = %q, want %q (all: %v)", op, k, got.Parameters[k], v, got.Parameters)
		}
	}
}

// TestIncidentMutations_AuditSuccessAndRecordResolver pins that every
// successful incident change leaves an audit row naming the actor and the
// exact incident, and that every way of resolving records the resolver.
// Before this, only refusals were audited and a resolve kept no resolver.
func TestIncidentMutations_AuditSuccessAndRecordResolver(t *testing.T) {
	store := newTestAlertStore(t)
	seedIncidents(t, store, "audit-ack-0001", "audit-res-0001", "audit-pat-0001", "audit-pat-0002", "audit-fpr-0001")
	log := audit.NewLogger()
	router := incidentAuditRouter(&Handlers{opts: Options{AlertStore: store, AuditLog: log}})

	t.Run("ack", func(t *testing.T) {
		rec := serveAsAdmin(router, http.MethodPost, "/api/v1/incidents/audit-ack-0001/ack", ``)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		wantIncidentRow(t, log, "incident-ack", map[string]string{
			"incident_id": "audit-ack-0001", "tenant": "admins", "service": "mctl-agents",
			"previous_status": alerts.StatusOpen, "status": alerts.StatusAcknowledged,
			"actor": incidentAuditActor,
		})
	})

	t.Run("resolve", func(t *testing.T) {
		rec := serveAsAdmin(router, http.MethodPost, "/api/v1/incidents/audit-res-0001/resolve", `{"reason":"secret-free-text"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		wantIncidentRow(t, log, "incident-resolve", map[string]string{
			"incident_id": "audit-res-0001", "previous_status": alerts.StatusOpen,
			"status": alerts.StatusResolved, "actor": incidentAuditActor,
		})
		for k, v := range successRows(log, "incident-resolve")[0].Parameters {
			if v == "secret-free-text" {
				t.Fatalf("resolution reason leaked into audit parameter %s", k)
			}
		}
		if a, _ := store.Get(context.Background(), "audit-res-0001"); a.ResolvedBy != incidentAuditActor || a.ResolvedAt == nil {
			t.Fatalf("resolve: resolved_by=%q resolved_at=%v", a.ResolvedBy, a.ResolvedAt)
		}
	})

	// Resolving again neither moves the resolver nor the time: the second
	// caller is someone else, and the record must still name the first.
	t.Run("re-resolve-keeps-first-resolver", func(t *testing.T) {
		first, _ := store.Get(context.Background(), "audit-res-0001")
		rowsBefore := len(successRows(log, "incident-resolve"))

		rec := serveAs(router, "someone-else", http.MethodPost, "/api/v1/incidents/audit-res-0001/resolve", ``)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		if got := len(successRows(log, "incident-resolve")); got != rowsBefore {
			t.Fatalf("no-op re-resolve wrote %d audit rows", got-rowsBefore)
		}

		rec = serveAs(router, "someone-else", http.MethodPost, "/api/v1/incidents/audit-res-0001/resolve", `{"reason":"more"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		a, _ := store.Get(context.Background(), "audit-res-0001")
		if a.ResolvedBy != incidentAuditActor || a.ResolvedAt == nil || !a.ResolvedAt.Equal(*first.ResolvedAt) {
			t.Fatalf("re-resolve moved the resolution: resolved_by=%q resolved_at=%v, first %v",
				a.ResolvedBy, a.ResolvedAt, first.ResolvedAt)
		}
		rows := successRows(log, "incident-resolve")
		if len(rows) != rowsBefore+1 {
			t.Fatalf("re-resolve with a reason: %d new rows, want 1", len(rows)-rowsBefore)
		}
		last := rows[len(rows)-1].Parameters
		if last["previous_status"] != alerts.StatusResolved || last["actor"] != "oidc:someone-else" {
			t.Fatalf("re-resolve row: %v", last)
		}
	})

	t.Run("patch", func(t *testing.T) {
		rec := serveAsAdmin(router, http.MethodPatch, "/api/v1/incidents/audit-pat-0001", `{"analysis":"x"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		wantIncidentRow(t, log, "incident-update", map[string]string{
			"incident_id": "audit-pat-0001", "previous_status": alerts.StatusOpen,
			"status": alerts.StatusOpen, "actor": incidentAuditActor,
		})
		if a, _ := store.Get(context.Background(), "audit-pat-0001"); a.ResolvedBy != "" || a.ResolvedAt != nil {
			t.Fatalf("non-resolving patch set resolved_by=%q resolved_at=%v", a.ResolvedBy, a.ResolvedAt)
		}
	})

	// A PATCH to resolved is a resolve by another route: it must record the
	// resolver, or this path would be the way to resolve without one.
	t.Run("patch-to-resolved", func(t *testing.T) {
		rec := serveAsAdmin(router, http.MethodPatch, "/api/v1/incidents/audit-pat-0002", `{"status":"resolved"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		if a, _ := store.Get(context.Background(), "audit-pat-0002"); a.ResolvedBy != incidentAuditActor || a.ResolvedAt == nil {
			t.Fatalf("patch to resolved: resolved_by=%q resolved_at=%v", a.ResolvedBy, a.ResolvedAt)
		}
	})

	t.Run("resolve-by-fingerprint", func(t *testing.T) {
		before := len(successRows(log, "incident-resolve"))
		// seedIncidents gives the i-th id the fingerprint lookup-fp-<i>.
		rec := serveAsAdmin(router, http.MethodPost, "/api/v1/incidents/resolve-by-fingerprint",
			`{"tenant":"admins","fingerprint":"lookup-fp-4"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		rows := successRows(log, "incident-resolve")
		if len(rows) != before+1 {
			t.Fatalf("resolve by fingerprint wrote %d incident-resolve rows, want 1", len(rows)-before)
		}
		last := rows[len(rows)-1]
		want := map[string]string{
			"incident_id": "audit-fpr-0001", "tenant": "admins", "status": alerts.StatusResolved,
			"fingerprint": "lookup-fp-4", "actor": incidentAuditActor,
		}
		for k, v := range want {
			if last.Parameters[k] != v {
				t.Fatalf("parameter %s = %q, want %q (all: %v)", k, last.Parameters[k], v, last.Parameters)
			}
		}
		if a, _ := store.Get(context.Background(), "audit-fpr-0001"); a.ResolvedBy != incidentAuditActor {
			t.Fatalf("resolve by fingerprint: resolved_by=%q", a.ResolvedBy)
		}
	})

	// A refused mutation (ambiguous prefix, #707) writes no success row.
	t.Run("refused-writes-no-success-row", func(t *testing.T) {
		before := len(log.List(0))
		rec := serveAsAdmin(router, http.MethodPost, "/api/v1/incidents/audit-pat/resolve", ``)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if after := len(log.List(0)); after != before {
			t.Fatalf("refused resolve wrote %d audit rows", after-before)
		}
	})
}
