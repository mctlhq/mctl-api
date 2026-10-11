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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/evidence"
)

// ADR 018 Amendment 2 over HTTP: the current read, its 400/422/403 codes,
// the subject filters and the work-item-scoped variant.

type a2Subject struct{ repo, revision, authority, observedAt, supersedes, workItemID string }

func uniqueA2Subject() a2Subject {
	sum := sha256.Sum256([]byte(uniqueTrace()))
	return a2Subject{repo: "mctlhq/h" + uniqueTrace(), revision: hex.EncodeToString(sum[:20]),
		authority: "observed", observedAt: "2026-10-04T10:00:00Z"}
}

func (s a2Subject) query() url.Values {
	return url.Values{"subject_kind": {"pull_request"}, "repository": {s.repo}, "ref": {"1"}, "revision": {s.revision}}
}

// sealA2Envelope builds a sealed, ASCII-only PR-subject envelope. The
// content payload is exactly what Tier A hashes (blocks in full shape), so
// encoding/json's sorted compact output is the canonical form.
func sealA2Envelope(t *testing.T, s a2Subject) []byte {
	t.Helper()
	trace := uniqueTrace()
	content := map[string]any{
		"api_version": evidence.APIVersionV1Alpha1,
		"kind":        evidence.KindV1Alpha1,
		"execution":   map[string]any{"execution_id": "we_" + trace, "work_item_id": s.workItemID, "trace_id": trace},
		"outcome":     map[string]any{"code": "succeeded", "reason_code": "test"},
		"subject":     map[string]any{"kind": "pull_request", "repository": s.repo, "ref": "1", "revision": s.revision},
		"provenance":  map[string]any{"authority": s.authority, "observed_at": s.observedAt, "supersedes": s.supersedes},
	}
	canonical, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	content["content_hash"] = hash
	content["evidence_id"] = "ev-" + hash[7:23]
	content["created_at"] = "2026-10-04T10:00:05Z"
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ingestBody(env []byte) []byte {
	body, _ := json.Marshal(map[string]string{"envelope_b64": base64.StdEncoding.EncodeToString(env)})
	return body
}

func evidenceIDOf(t *testing.T, env []byte) string {
	t.Helper()
	var m struct {
		ID string `json:"evidence_id"`
	}
	if err := json.Unmarshal(env, &m); err != nil {
		t.Fatal(err)
	}
	return m.ID
}

func TestEvidenceA2_CurrentRouteIsNotAnID(t *testing.T) {
	// Through the real router with no store: /evidence/current reaches
	// CurrentEvidence (503 from its own guard), never GetEvidence("current").
	router := NewRouter(Options{AuthMiddleware: injectUser(adminUser())})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/evidence/current?subject_kind=issue", nil))
	if rec.Code != http.StatusServiceUnavailable || bodyCode(rec) != codeEvidenceStoreUnavailable {
		t.Fatalf("GET /api/v1/evidence/current: got %d %s, want 503 %s", rec.Code, rec.Body.String(), codeEvidenceStoreUnavailable)
	}
}

func TestEvidenceA2_IngestAndCurrentRead(t *testing.T) {
	h := &Handlers{opts: Options{Evidence: newEvidenceStore(t)}}
	r := chi.NewRouter()
	r.Post("/api/v1/evidence/records", h.IngestEvidence)
	r.Get("/api/v1/evidence/current", h.CurrentEvidence)
	r.Get("/api/v1/evidence", h.ListEvidence)
	r.Get("/api/v1/evidence/{id}", h.GetEvidence)
	call := func(u *auth.User, method, target string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, bytes.NewReader(body))
		req = req.WithContext(auth.WithUser(req.Context(), u))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	current := func(q url.Values) *httptest.ResponseRecorder {
		return call(adminUser(), http.MethodGet, "/api/v1/evidence/current?"+q.Encode(), nil)
	}
	state := func(rec *httptest.ResponseRecorder) (string, map[string]any) {
		var body struct {
			State    string         `json:"state"`
			Evidence map[string]any `json:"evidence"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return body.State, body.Evidence
	}

	subj := uniqueA2Subject()
	if rec := current(subj.query()); rec.Code != http.StatusOK {
		t.Fatalf("current(empty): %d %s", rec.Code, rec.Body.String())
	} else if s, ev := state(rec); s != evidence.CurrentStateNoEvidence || ev != nil {
		t.Fatalf("current(empty) = %s %v, want no_evidence", s, ev)
	}

	env := sealA2Envelope(t, subj)
	if rec := call(evidenceWriter(t), http.MethodPost, "/api/v1/evidence/records", ingestBody(env)); rec.Code != http.StatusCreated {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	} else {
		var body struct {
			Evidence map[string]any `json:"evidence"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.Evidence["authority"] != "observed" || body.Evidence["subject"] == nil || body.Evidence["observed_at"] == nil {
			t.Fatalf("ingest response lacks subject/provenance: %s", rec.Body.String())
		}
	}
	rec := current(subj.query())
	if s, ev := state(rec); rec.Code != http.StatusOK || s != evidence.CurrentStateCurrent || ev["id"] != evidenceIDOf(t, env) {
		t.Fatalf("current = %d %s, want current %s", rec.Code, rec.Body.String(), evidenceIDOf(t, env))
	}

	// Missing revision for a SHA-bound kind is unknown_revision, not 400
	// and not no_evidence.
	q := subj.query()
	q.Del("revision")
	if rec := current(q); rec.Code != http.StatusOK {
		t.Fatalf("current(no revision): %d", rec.Code)
	} else if s, _ := state(rec); s != evidence.CurrentStateUnknownRevision {
		t.Fatalf("current(no revision) = %s, want unknown_revision", s)
	}

	// Malformed parameters answer 400, never no_evidence.
	for name, mutate := range map[string]func(url.Values){
		"abbreviated SHA": func(v url.Values) { v.Set("revision", subj.revision[:7]) },
		"unknown kind":    func(v url.Values) { v.Set("subject_kind", "commit") },
		"missing kind":    func(v url.Values) { v.Del("subject_kind") },
		"PR ref":          func(v url.Values) { v.Set("ref", "x") },
		"missing repo":    func(v url.Values) { v.Del("repository") },
		"repeated param":  func(v url.Values) { v.Add("revision", subj.revision) },
		"unknown param":   func(v url.Values) { v.Set("subject_revision", subj.revision) },
	} {
		q := subj.query()
		mutate(q)
		if rec := current(q); rec.Code != http.StatusBadRequest || bodyCode(rec) != codeEvidenceQueryInvalid {
			t.Errorf("%s: got %d %s, want 400 %s", name, rec.Code, rec.Body.String(), codeEvidenceQueryInvalid)
		}
	}

	// A malformed percent-encoding is 400, never a silently dropped key.
	if rec := call(adminUser(), http.MethodGet, "/api/v1/evidence/current?"+subj.query().Encode()+"&revision=%zz", nil); rec.Code != http.StatusBadRequest || bodyCode(rec) != codeEvidenceQueryInvalid {
		t.Errorf("malformed query: got %d %s, want 400 %s", rec.Code, rec.Body.String(), codeEvidenceQueryInvalid)
	}
	if rec := call(adminUser(), http.MethodGet, "/api/v1/evidence?subject_revision=%zz", nil); rec.Code != http.StatusBadRequest || bodyCode(rec) != codeEvidenceQueryInvalid {
		t.Errorf("malformed list query: got %d %s, want 400 %s", rec.Code, rec.Body.String(), codeEvidenceQueryInvalid)
	}

	// Non-admins are refused, like GET /api/v1/evidence.
	member := auth.NewGitHubUser("alice", []string{"some-tenant"})
	if rec := call(member, http.MethodGet, "/api/v1/evidence/current?"+subj.query().Encode(), nil); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin current: got %d, want 403", rec.Code)
	}

	// A supersedes link to a stored envelope about another revision is 422.
	bad := uniqueA2Subject()
	bad.repo = subj.repo
	bad.supersedes = evidenceIDOf(t, env)
	if rec := call(evidenceWriter(t), http.MethodPost, "/api/v1/evidence/records", ingestBody(sealA2Envelope(t, bad))); rec.Code != http.StatusUnprocessableEntity || bodyCode(rec) != codeEvidenceSupersedesInvalid {
		t.Errorf("invalid supersedes: got %d %s, want 422 %s", rec.Code, rec.Body.String(), codeEvidenceSupersedesInvalid)
	}

	// A rule violation inside a new block is 400 evidence_invalid.
	viol := uniqueA2Subject()
	viol.authority = "verified"
	if rec := call(evidenceWriter(t), http.MethodPost, "/api/v1/evidence/records", ingestBody(sealA2Envelope(t, viol))); rec.Code != http.StatusBadRequest || bodyCode(rec) != codeEvidenceInvalid {
		t.Errorf("invalid authority: got %d %s, want 400 %s", rec.Code, rec.Body.String(), codeEvidenceInvalid)
	}

	// Subject filters on the list route; an unknown subject_kind is 400.
	if rec := call(adminUser(), http.MethodGet, "/api/v1/evidence?subject_repository="+url.QueryEscape(subj.repo), nil); rec.Code != http.StatusOK {
		t.Fatalf("list by subject: %d", rec.Code)
	} else {
		var list struct {
			Evidence []map[string]any `json:"evidence"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &list)
		if len(list.Evidence) != 1 || list.Evidence[0]["id"] != evidenceIDOf(t, env) {
			t.Errorf("list by subject_repository: %s", rec.Body.String())
		}
	}
	if rec := call(adminUser(), http.MethodGet, "/api/v1/evidence?subject_kind=commit", nil); rec.Code != http.StatusBadRequest || bodyCode(rec) != codeEvidenceQueryInvalid {
		t.Errorf("list by unknown subject_kind: got %d %s, want 400 %s", rec.Code, rec.Body.String(), codeEvidenceQueryInvalid)
	}
}

func TestEvidenceA2_WorkItemCurrentFollowsItemVisibility(t *testing.T) {
	e := newWorkItemsEnv(t)
	store := newEvidenceStore(t)
	e.h.opts.Evidence = store
	e.router.Get("/api/v1/work-items/{id}/evidence/current", e.h.CurrentWorkItemEvidence)
	e.router.Get("/api/v1/work-items/{id}/evidence", e.h.ListWorkItemEvidence)

	owner := e.user("alice")
	itemID := e.open(owner, nil)["id"].(string)
	subj := uniqueA2Subject()
	subj.workItemID = itemID
	env := sealA2Envelope(t, subj)
	if _, _, err := store.Ingest(context.Background(), evidence.IngestInput{EnvelopeBytes: env, IngestedBy: "test:writer"}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	path := "/api/v1/work-items/" + itemID + "/evidence/current?" + subj.query().Encode()

	outsider := auth.NewGitHubUser("mallory", []string{"another-tenant"})
	if res := e.do(outsider, http.MethodGet, path, nil); res.code != http.StatusNotFound {
		t.Fatalf("outsider: got %d %s, want 404", res.code, res.raw)
	}
	res := e.do(owner, http.MethodGet, path, nil)
	if res.code != http.StatusOK || res.body["state"] != evidence.CurrentStateCurrent {
		t.Fatalf("owner: got %d %s, want 200 current", res.code, res.raw)
	}
	if res := e.do(owner, http.MethodGet, "/api/v1/work-items/"+itemID+"/evidence?subject_kind=pull_request&subject_repository="+url.QueryEscape(subj.repo), nil); res.code != http.StatusOK {
		t.Fatalf("owner list by subject: %d %s", res.code, res.raw)
	} else if list, _ := res.body["evidence"].([]any); len(list) != 1 {
		t.Fatalf("owner list by subject: %d records, want 1", len(list))
	}

	// Evidence from another work item in the pool: refused with a typed
	// 403, never resolved over the visible part only.
	theirs := subj
	theirs.workItemID = "wi_someone-else"
	theirs.observedAt = "2026-10-04T11:00:00Z"
	if _, _, err := store.Ingest(context.Background(), evidence.IngestInput{EnvelopeBytes: sealA2Envelope(t, theirs), IngestedBy: "test:writer"}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res := e.do(owner, http.MethodGet, path, nil); res.code != http.StatusForbidden || code(res) != codeEvidenceCurrentNotVisible {
		t.Fatalf("mixed pool: got %d %s, want 403 %s", res.code, res.raw, codeEvidenceCurrentNotVisible)
	}
}
