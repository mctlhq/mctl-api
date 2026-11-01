// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/reviewreceipts"
	"github.com/mctlhq/mctl-api/internal/reviewstore"
)

func TestIsReviewRequestWriteRoute(t *testing.T) {
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, "/api/v1/review-requests", true},
		{http.MethodGet, "/api/v1/review-requests", false},
		{http.MethodPost, "/api/v1/review-requests/rr_1", false},
		{http.MethodPost, "/api/v1/review-receipts/manual", false},
		{http.MethodPost, "/api/v1/review-receipts", false},
	} {
		if got := isReviewRequestWriteRoute(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// The evidence writer reaches review ingest (503 from the handler, which a
// request that was stopped at the gate cannot produce) and no other review
// route.
func TestEvidenceWriter_ReachesReviewIngestOnly(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(evidenceWriter(t))})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/review-requests", bytes.NewReader([]byte("{}"))))
	if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeReviewStoreUnavailable {
		t.Errorf("POST review-requests: %d %s, want 503 from the handler", rec.Code, rec.Body.String())
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/review-receipts/manual"},
		{http.MethodPost, "/api/v1/review-receipts"},
		{http.MethodGet, "/api/v1/review-receipts"},
		{http.MethodGet, "/api/v1/review-requests/rr_1"},
		{http.MethodGet, "/api/v1/review-gate"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusForbidden || bodyCode(rec) != codeEvidenceWriterForbidden {
			t.Errorf("%s %s: %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), codeEvidenceWriterForbidden)
		}
	}
}

func TestReview_UnconfiguredStoreAnswers503(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(adminUser())})
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/review-requests"},
		{http.MethodPost, "/api/v1/review-receipts/manual"},
		{http.MethodGet, "/api/v1/review-requests/rr_0000000000000000"},
		{http.MethodGet, "/api/v1/review-receipts"},
		{http.MethodGet, "/api/v1/review-gate"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeReviewStoreUnavailable {
			t.Errorf("%s %s: %d %s, want 503 %s", c.method, c.path, rec.Code, rec.Body.String(), codeReviewStoreUnavailable)
		}
	}
}

func TestReview_WorkerIngestIsDisabled(t *testing.T) {
	router := NewRouter(Options{AuthMiddleware: injectUser(adminUser())})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/review-receipts", bytes.NewReader([]byte("{}"))))
	if rec.Code != http.StatusNotImplemented || bodyCode(rec) != codeReviewWorkerIngestDisabled {
		t.Errorf("got %d %s, want 501 %s", rec.Code, rec.Body.String(), codeReviewWorkerIngestDisabled)
	}
}

func TestWriteReviewError_Table(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{&reviewreceipts.Error{Code: reviewreceipts.CodeUnknownKey, Message: "x"}, 400, reviewreceipts.CodeUnknownKey},
		{reviewstore.ErrUnsealed, 400, codeReviewUnsealed},
		{fmt.Errorf("w: %w", reviewstore.ErrRequestNotFound), 404, codeReviewRequestNotFound},
		{reviewstore.ErrRequestClosed, 409, codeReviewRequestClosed},
		{reviewstore.ErrBindingMismatch, 409, codeReviewBindingMismatch},
		{reviewstore.ErrRequestModeWorker, 409, codeReviewRequestModeWorker},
		{reviewstore.ErrNonceReused, 409, codeReviewNonceReused},
		{reviewstore.ErrIdempotencyConflict, 409, codeReviewRequestConflict},
		{reviewstore.ErrAuthoringUnresolved, 422, codeReviewAuthoringUnresolved},
		{reviewstore.ErrTenantUnresolved, 422, codeReviewTenantUnresolved},
		{reviewstore.ErrPoolTooLarge, 503, codeReviewPoolTooLarge},
		{fmt.Errorf("w: %w", reviewstore.ErrEvidenceUnavailable), 503, codeReviewEvidenceUnavailable},
		{reviewstore.ErrStoreCorrupt, 503, codeReviewStoreUnavailable},
		{errors.New("driver"), 503, codeReviewStoreUnavailable},
	} {
		rec := httptest.NewRecorder()
		writeReviewError(rec, c.err)
		if rec.Code != c.status || bodyCode(rec) != c.code {
			t.Errorf("%v: %d %s, want %d %s", c.err, rec.Code, bodyCode(rec), c.status, c.code)
		}
	}
}

// Review writes spend their own bucket: exhausting it throttles them and
// leaves evidence ingest, under the same principal, untouched.
func TestReviewWrites_HaveTheirOwnRateBucket(t *testing.T) {
	if reviewWritesPerMinute+decisionWritesPerMinute+evidenceIngestPerMinute > 300 {
		t.Fatal("review, decision and evidence budgets exceed the global 300/min")
	}
	router := NewRouter(Options{AuthMiddleware: injectUser(evidenceWriter(t))})
	for i := 0; i < reviewWritesPerMinute; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/review-requests", bytes.NewReader([]byte("{}"))))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("review write %d throttled below its budget", i+1)
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/review-requests", bytes.NewReader([]byte("{}"))))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("write over budget: %d, want 429", rec.Code)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/evidence/records", bytes.NewReader([]byte("{}"))))
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("evidence ingest throttled by review writes")
	}
}

// fakeHumanChecker is a principal store that answers CheckHumanPrincipal
// with a fixed error.
type fakeHumanChecker struct{ err error }

func (fakeHumanChecker) ResolvePrincipal(context.Context, auth.Identity) (string, error) {
	return "prn_fake", nil
}

func (f fakeHumanChecker) CheckHumanPrincipal(context.Context, string) error { return f.err }

// reviewAuthRouter builds the real router with a non-nil review store whose
// methods are never reached: every case below is decided before the store.
func reviewAuthRouter(u *auth.User, principals auth.PrincipalResolver) http.Handler {
	return NewRouter(Options{
		AuthMiddleware: injectUser(u),
		ReviewStore:    &reviewstore.Store{},
		Principals:     principals,
	})
}

func postManual(router http.Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/review-receipts/manual", bytes.NewReader([]byte(body))))
	return rec
}

// Only a direct human administrator submits a manual assertion. The service
// principal carries the admins group, so IsAdmin alone would let it through.
func TestSubmitManualReview_OnlyADirectHumanAdmin(t *testing.T) {
	surface := auth.NewSurfaceUser("telegram")
	for name, u := range map[string]*auth.User{
		"service (in admins)": auth.NewServiceUser(),
		"tenant user":         {ID: "alice", Groups: []string{"acme"}},
		"surface":             surface,
		"relayed admin":       auth.NewRelayedUser("root", []string{"admins"}, surface),
		"evidence writer":     evidenceWriter(t),
	} {
		rec := postManual(reviewAuthRouter(u, fakeHumanChecker{}), "{")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s, want 403", name, rec.Code, rec.Body.String())
		}
		// A surface and the evidence writer are stopped by the router before the
		// handler runs; the others reach the handler's own check.
		if name != "evidence writer" && name != "surface" && bodyCode(rec) != codeReviewNotPermitted {
			t.Errorf("%s: code %q, want %s", name, bodyCode(rec), codeReviewNotPermitted)
		}
	}
	// A human admin passes the authorization (the malformed body is then 400).
	rec := postManual(reviewAuthRouter(adminUser(), fakeHumanChecker{}), "{")
	if rec.Code != http.StatusBadRequest || bodyCode(rec) != reviewreceipts.CodeMalformed {
		t.Fatalf("human admin: %d %s, want 400 %s", rec.Code, rec.Body.String(), reviewreceipts.CodeMalformed)
	}
}

// The principal store decides whether the admin is an active human: a
// definite no is 403, and an answer that could not be obtained is 503, never
// read as a yes or as a refusal.
func TestSubmitManualReview_PrincipalCheck(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"disabled principal": {auth.ErrPrincipalDisabled, http.StatusForbidden, codeReviewNotPermitted},
		"refused identity":   {auth.ErrIdentityRefused, http.StatusForbidden, codeReviewNotPermitted},
		"store unavailable":  {errors.New("db down"), http.StatusServiceUnavailable, codeReviewPrincipalUnavailable},
	} {
		rec := postManual(reviewAuthRouter(adminUser(), fakeHumanChecker{err: c.err}), "{")
		if rec.Code != c.status || bodyCode(rec) != c.code {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), c.status, c.code)
		}
	}
}

// The reads are admin-only: a tenant user, a service and the evidence writer
// are refused before the store is touched.
func TestReviewReads_AreAdminOnly(t *testing.T) {
	for name, u := range map[string]*auth.User{
		"tenant user": {ID: "alice", Groups: []string{"acme"}},
	} {
		router := reviewAuthRouter(u, fakeHumanChecker{})
		for _, path := range []string{"/api/v1/review-receipts", "/api/v1/review-gate", "/api/v1/review-requests/rr_0000000000000000"} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d %s, want 403", name, path, rec.Code, rec.Body.String())
			}
		}
	}
}
