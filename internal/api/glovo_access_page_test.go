// Copyright 2026 MCTL Authors
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
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// Glovo access decision page (mctl-glovo#82 stage B): approve, reject and
// revoke only on a page that needs a fresh sign-in with a second factor.

const accessPageEmail = "someone.private@example.invalid"

type accessPageEnv struct {
	*releasePageEnv
	acc   *memAccessStore
	cons  *memConsentStore
	audit *audit.Logger
}

func newAccessPageEnv(t *testing.T) *accessPageEnv {
	t.Helper()
	r := newReleasePageEnv(t)
	e := &accessPageEnv{releasePageEnv: r, acc: newMemAccessStore(), cons: newMemConsentStore(), audit: audit.NewLogger()}
	g := mountedConsent(e.cons, 7)
	g.Access = e.acc
	r.h.opts.GlovoConsent = g
	r.h.opts.AuditLog = e.audit
	r.h.glovoAccessApproval = newGlovoAccessDecider(r.ropts)
	r.page = accessRouter(r.h)
	return e
}

func accessRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()
	r.Post(glovoAccessStartPath, h.handleGlovoAccessStart)
	r.Get(glovoAccessCallbackPath, h.handleGlovoAccessCallback)
	r.Post(glovoAccessConfirmPath, h.handleGlovoAccessConfirm)
	r.Get(glovoAccessPagePrefix+"{principal_id}", h.handleGlovoAccessPage)
	return r
}

func (e *accessPageEnv) signIn(pid string, claims map[string]any) (*httptest.ResponseRecorder, *http.Cookie, url.Values) {
	e.t.Helper()
	page := e.send(http.MethodGet, glovoAccessPagePrefix+pid, nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `action="`+glovoAccessStartPath+`"`) {
		e.t.Fatalf("link page = %d %s", page.Code, page.Body.String())
	}
	if len(page.Result().Cookies()) != 0 {
		e.t.Fatal("the link page set state")
	}
	start := e.send(http.MethodPost, glovoAccessStartPath, nil, url.Values{"principal": {pid}})
	if start.Code != http.StatusSeeOther {
		e.t.Fatalf("start = %d %s", start.Code, start.Body.String())
	}
	var ck *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == glovoAccessPageCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.Domain != "" || !strings.HasPrefix(ck.Name, "__Host-") {
		e.t.Fatalf("cookie = %+v", ck)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	if q.Get("client_id") != "release-client" || q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "login" ||
		q.Get("max_age") != "0" || q.Get("nonce") == "" || q.Get("redirect_uri") != "https://api.example"+glovoAccessCallbackPath {
		e.t.Fatalf("authorize URL %s", u)
	}
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce = q.Get("code_challenge"), q.Get("nonce")
	e.idp.extra = claims
	e.idp.username = accessPageEmail
	e.idp.mu.Unlock()
	rec := e.send(http.MethodGet, glovoAccessCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	form := url.Values{}
	for _, m := range basketField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return rec, ck, form
}

func (e *accessPageEnv) confirm(ck *http.Cookie, form url.Values, decision, reason string) *httptest.ResponseRecorder {
	return e.send(http.MethodPost, glovoAccessConfirmPath, ck, url.Values{
		"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {decision}, "reason": {reason},
	})
}

func (e *accessPageEnv) status(pid string) glovoconsent.AccessStatus {
	e.t.Helper()
	a, err := e.acc.GetAccess(context.Background(), pid)
	if err != nil {
		e.t.Fatal(err)
	}
	return a.Status
}

const accessPagePRN = glovoOwnerPRN

func TestGlovoAccessPage_DeciderApproves(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	rec, ck, form := e.signIn(accessPagePRN, deciderClaims())
	body := rec.Body.String()
	if rec.Code != http.StatusOK || form.Get("csrf") == "" || !strings.Contains(body, accessPagePRN) ||
		!strings.Contains(body, "Approve access") || !strings.Contains(body, "Reject") || strings.Contains(body, "Revoke access") {
		t.Fatalf("callback = %d %s", rec.Code, body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") ||
		strings.Contains(body, "<script") || strings.Contains(body, "<link") || strings.Contains(body, "<img") || strings.Contains(body, "src=") || strings.Contains(body, " onclick=") || strings.Contains(body, " onsubmit=") {
		t.Fatalf("headers or body not strict: %v", rec.Header())
	}
	if e.status(accessPagePRN) != glovoconsent.AccessPending {
		t.Fatal("showing the request decided it")
	}
	got := e.confirm(ck, form, "approve", "known colleague")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Access approved") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	a, _ := e.acc.GetAccess(context.Background(), accessPagePRN)
	if a.Status != glovoconsent.AccessApproved || a.DecidedBy != basketAdminPRN || a.Reason != "known colleague" || e.acc.lastCapacity != 7 {
		t.Fatalf("row %+v capacity %d", a, e.acc.lastCapacity)
	}
}

func TestGlovoAccessPage_DeciderRejects(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	if got := e.confirm(ck, form, "reject", "not now"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Access rejected") {
		t.Fatalf("reject = %d %s", got.Code, got.Body.String())
	}
	if e.status(accessPagePRN) != glovoconsent.AccessRejected || e.acc.approveCalls != 0 {
		t.Fatal("not rejected")
	}
}

// Revoking is a decision of the same page. It ends the grant at the next
// check: the glovo:c2 grant source reads the access state live.
func TestGlovoAccessPage_RevokeEndsTheGrantAtNextCheck(t *testing.T) {
	e := newAccessPageEnv(t)
	if _, _, err := e.cons.Record(context.Background(), accessPagePRN, accessPagePRN, 5); err != nil {
		t.Fatal(err)
	}
	e.acc.set(accessPagePRN, glovoconsent.AccessApproved)
	grants := glovoconsent.ConsentGrants{Store: e.cons, Access: e.acc}
	if ok, err := grants.HasGrant(context.Background(), accessPagePRN, glovoconsent.GrantC2); err != nil || !ok {
		t.Fatalf("control: grant before revoke = %v %v", ok, err)
	}
	rec, ck, form := e.signIn(accessPagePRN, deciderClaims())
	if !strings.Contains(rec.Body.String(), "Revoke access") || strings.Contains(rec.Body.String(), "Approve access") {
		t.Fatalf("approved page: %s", rec.Body.String())
	}
	if got := e.confirm(ck, form, "revoke", "offboarded"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Access revoked") {
		t.Fatalf("revoke = %d %s", got.Code, got.Body.String())
	}
	if ok, err := grants.HasGrant(context.Background(), accessPagePRN, glovoconsent.GrantC2); err != nil || ok {
		t.Fatalf("grant after revoke = %v %v", ok, err)
	}
}

// Second factor: a sign-in without mfa in amr decides nothing and gets no
// decision form.
func TestGlovoAccessPage_MFARequired(t *testing.T) {
	for name, amr := range map[string][]string{"password only": {"pwd"}, "no amr": nil, "lookalike": {"mfa-ish", "otp-not"}} {
		e := newAccessPageEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessPending)
		rec, _, form := e.signIn(accessPagePRN, map[string]any{"sub": "z-admin", "amr": amr})
		if rec.Code != http.StatusForbidden || form.Get("challenge") != "" || strings.Contains(rec.Body.String(), "Approve access") {
			t.Errorf("%s: callback = %d %s", name, rec.Code, rec.Body.String())
		}
		if e.status(accessPagePRN) != glovoconsent.AccessPending || e.acc.approveCalls != 0 {
			t.Errorf("%s: decided without a second factor", name)
		}
	}
}

func TestGlovoAccessPage_OnlyDecidersSeeAndDecide(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	// An admin who is not a decider, and a person who is no admin at all.
	e.ropts.Deciders = []string{glovoOtherPRN}
	for name, sub := range map[string]string{"admin not in deciders": "z-admin", "ordinary person": "z-other"} {
		rec, _, form := e.signIn(accessPagePRN, map[string]any{"sub": sub, "amr": []string{"mfa"}})
		if rec.Code != http.StatusNotFound || form.Get("challenge") != "" || strings.Contains(rec.Body.String(), accessPagePRN) {
			t.Errorf("%s: callback = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if e.acc.approveCalls != 0 || e.status(accessPagePRN) != glovoconsent.AccessPending {
		t.Fatal("a non-decider decided")
	}
}

func TestGlovoAccessPage_ReasonRequiredAndKeepsChallenge(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	for _, reason := range []string{"", "   ", strings.Repeat("x", 501), "line\nbreak"} {
		if got := e.confirm(ck, form, "approve", reason); got.Code != http.StatusBadRequest {
			t.Errorf("reason %q = %d", reason, got.Code)
		}
	}
	if e.acc.approveCalls != 0 {
		t.Fatal("decided without a usable reason")
	}
	// The refusal did not spend the challenge: the same form still works.
	if got := e.confirm(ck, form, "approve", "ok"); got.Code != http.StatusOK {
		t.Fatalf("retry with a reason = %d %s", got.Code, got.Body.String())
	}
}

// The decide form is one-time and bound to the browser cookie: a replay, a
// wrong csrf, a wrong challenge and a foreign cookie all decide nothing.
func TestGlovoAccessPage_CSRFIsOneTime(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	wrongCSRF := url.Values{"challenge": {form.Get("challenge")}, "csrf": {"not-the-csrf"}, "decision": {"approve"}, "reason": {"r"}}
	if got := e.send(http.MethodPost, glovoAccessConfirmPath, ck, wrongCSRF); got.Code != http.StatusBadRequest {
		t.Fatalf("wrong csrf = %d", got.Code)
	}
	foreign := &http.Cookie{Name: glovoAccessPageCookie, Value: "another-browser"}
	if got := e.confirm(foreign, form, "approve", "r"); got.Code != http.StatusBadRequest {
		t.Fatalf("foreign cookie = %d", got.Code)
	}
	if got := e.confirm(nil, form, "approve", "r"); got.Code != http.StatusBadRequest {
		t.Fatalf("no cookie = %d", got.Code)
	}
	if e.acc.approveCalls != 0 {
		t.Fatal("a refused form decided")
	}
	if got := e.confirm(ck, form, "approve", "r"); got.Code != http.StatusOK {
		t.Fatalf("real confirm = %d %s", got.Code, got.Body.String())
	}
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	calls := e.acc.approveCalls
	if got := e.confirm(ck, form, "approve", "r"); got.Code != http.StatusBadRequest || e.acc.approveCalls != calls {
		t.Fatalf("replayed form = %d, approve calls %d -> %d", got.Code, calls, e.acc.approveCalls)
	}
}

// A request past its expiry cannot be approved, even by a store that would
// still accept it: the page refuses on the row's own expiry.
func TestGlovoAccessPage_ExpiredPendingCannotBeApproved(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	e.acc.mu.Lock()
	a := e.acc.rows[accessPagePRN]
	a.RequestedAt, a.ExpiresAt = time.Now().Add(-8*24*time.Hour), time.Now().Add(-24*time.Hour)
	e.acc.rows[accessPagePRN] = a
	e.acc.mu.Unlock()
	rec, _, form := e.signIn(accessPagePRN, deciderClaims())
	if rec.Code != http.StatusOK || form.Get("challenge") != "" || strings.Contains(rec.Body.String(), "Approve access") ||
		!strings.Contains(rec.Body.String(), "nothing to decide") {
		t.Fatalf("expired callback = %d %s", rec.Code, rec.Body.String())
	}
	// Forge the form: a request that expires between the page and the
	// confirm is refused at confirm. Reopen as live, show, then let it lapse.
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	e.acc.mu.Lock()
	a = e.acc.rows[accessPagePRN]
	a.ExpiresAt = time.Now().Add(-time.Minute)
	e.acc.rows[accessPagePRN] = a
	e.acc.mu.Unlock()
	if got := e.confirm(ck, form, "approve", "late"); got.Code != http.StatusConflict {
		t.Fatalf("lapsed between page and confirm = %d %s", got.Code, got.Body.String())
	}
	if e.acc.approveCalls != 0 || e.acc.rejectCalls != 0 {
		t.Fatalf("a lapsed request reached the store: approve %d reject %d", e.acc.approveCalls, e.acc.rejectCalls)
	}
}

// A decider cannot reject their own request: a self-rejection is stored like
// a withdrawal and would read as none to the requester. Approving or revoking
// one's own access stays allowed (the owner is the only decider).
func TestGlovoAccessPage_SelfRejectionRefused(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(basketAdminPRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(basketAdminPRN, deciderClaims())
	if got := e.confirm(ck, form, "reject", "r"); got.Code != http.StatusConflict || e.acc.rejectCalls != 0 {
		t.Fatalf("self-reject = %d, reject calls %d", got.Code, e.acc.rejectCalls)
	}
	_, ck, form = e.signIn(basketAdminPRN, deciderClaims())
	if got := e.confirm(ck, form, "approve", "owner"); got.Code != http.StatusOK || e.status(basketAdminPRN) != glovoconsent.AccessApproved {
		t.Fatalf("self-approve = %d", got.Code)
	}
}

// Two deciders with the page open: the first decision wins, the second is
// refused by the page and never reaches the store.
func TestGlovoAccessPage_DoubleDecisionRefused(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ckA, formA := e.signIn(accessPagePRN, deciderClaims())
	_, ckB, formB := e.signIn(accessPagePRN, deciderClaims())
	if got := e.confirm(ckA, formA, "approve", "first"); got.Code != http.StatusOK {
		t.Fatalf("first = %d %s", got.Code, got.Body.String())
	}
	if got := e.confirm(ckB, formB, "reject", "second"); got.Code != http.StatusConflict {
		t.Fatalf("second = %d %s", got.Code, got.Body.String())
	}
	if e.status(accessPagePRN) != glovoconsent.AccessApproved || e.acc.rejectCalls != 0 {
		t.Fatalf("status %s, reject calls %d", e.status(accessPagePRN), e.acc.rejectCalls)
	}
	// An approved row is not approved or rejected again either.
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	if got := e.confirm(ck, form, "approve", "again"); got.Code != http.StatusConflict || e.acc.approveCalls != 1 {
		t.Fatalf("approve of approved = %d, calls %d", got.Code, e.acc.approveCalls)
	}
	// And a revoke needs approved access.
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form = e.signIn(accessPagePRN, deciderClaims())
	if got := e.confirm(ck, form, "revoke", "wrong"); got.Code != http.StatusConflict || e.acc.revokeCalls != 0 {
		t.Fatalf("revoke of pending = %d, calls %d", got.Code, e.acc.revokeCalls)
	}
}

// The store itself refusing (someone else decided in the gap the page cannot
// see) is a 409, not a success and not a 5xx.
func TestGlovoAccessPage_StoreSaysAlreadyDecided(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	e.acc.approveErr = glovoconsent.ErrAccessNotPending
	if got := e.confirm(ck, form, "approve", "r"); got.Code != http.StatusConflict {
		t.Fatalf("= %d %s", got.Code, got.Body.String())
	}
	e = newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form = e.signIn(accessPagePRN, deciderClaims())
	e.acc.approveErr = glovoconsent.ErrCapacityReached
	if got := e.confirm(ck, form, "approve", "r"); got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "slot") {
		t.Fatalf("capacity = %d %s", got.Code, got.Body.String())
	}
}

// Every dependency error is a 503 and decides nothing.
func TestGlovoAccessPage_ErrorsAre503(t *testing.T) {
	boom := errors.New("boom")
	t.Run("access read at sign-in", func(t *testing.T) {
		e := newAccessPageEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessPending)
		e.acc.getErr = boom
		rec, _, form := e.signIn(accessPagePRN, deciderClaims())
		if rec.Code != http.StatusServiceUnavailable || form.Get("challenge") != "" {
			t.Fatalf("= %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("access read at confirm", func(t *testing.T) {
		e := newAccessPageEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessPending)
		_, ck, form := e.signIn(accessPagePRN, deciderClaims())
		e.acc.getErr = boom
		if got := e.confirm(ck, form, "approve", "r"); got.Code != http.StatusServiceUnavailable || e.acc.approveCalls != 0 {
			t.Fatalf("= %d, approve calls %d", got.Code, e.acc.approveCalls)
		}
	})
	t.Run("another principal's row", func(t *testing.T) {
		e := newAccessPageEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessPending)
		e.acc.mu.Lock()
		a := e.acc.rows[accessPagePRN]
		a.PrincipalID = glovoOtherPRN
		e.acc.rows[accessPagePRN] = a
		e.acc.mu.Unlock()
		if rec, _, _ := e.signIn(accessPagePRN, deciderClaims()); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("= %d", rec.Code)
		}
	})
	for name, set := range map[string]func(*memAccessStore){
		"approve": func(m *memAccessStore) { m.approveErr = boom },
	} {
		t.Run("store "+name, func(t *testing.T) {
			e := newAccessPageEnv(t)
			e.acc.set(accessPagePRN, glovoconsent.AccessPending)
			_, ck, form := e.signIn(accessPagePRN, deciderClaims())
			set(e.acc)
			if got := e.confirm(ck, form, name, "r"); got.Code != http.StatusServiceUnavailable || e.status(accessPagePRN) != glovoconsent.AccessPending {
				t.Fatalf("= %d", got.Code)
			}
		})
	}
	t.Run("store revoke", func(t *testing.T) {
		e := newAccessPageEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessApproved)
		_, ck, form := e.signIn(accessPagePRN, deciderClaims())
		e.acc.revokeErr = boom
		if got := e.confirm(ck, form, "revoke", "r"); got.Code != http.StatusServiceUnavailable || e.status(accessPagePRN) != glovoconsent.AccessApproved {
			t.Fatalf("= %d", got.Code)
		}
	})
	t.Run("store reject", func(t *testing.T) {
		e := newAccessPageEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessPending)
		_, ck, form := e.signIn(accessPagePRN, deciderClaims())
		e.acc.rejectErr = boom
		if got := e.confirm(ck, form, "reject", "r"); got.Code != http.StatusServiceUnavailable || e.status(accessPagePRN) != glovoconsent.AccessPending {
			t.Fatalf("= %d", got.Code)
		}
	})
	t.Run("not mounted", func(t *testing.T) {
		e := newAccessPageEnv(t)
		e.h.opts.GlovoConsent.Access = nil
		for _, rec := range []*httptest.ResponseRecorder{
			e.send(http.MethodGet, glovoAccessPagePrefix+accessPagePRN, nil, nil),
			e.send(http.MethodPost, glovoAccessStartPath, nil, url.Values{"principal": {accessPagePRN}}),
			e.send(http.MethodPost, glovoAccessConfirmPath, nil, url.Values{"decision": {"approve"}}),
		} {
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("unmounted = %d", rec.Code)
			}
		}
	})
}

// A request withdrawn and opened again between the page and the confirm is a
// different request: the decider was not shown it.
func TestGlovoAccessPage_ChangedSinceShownIsRefused(t *testing.T) {
	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	e.acc.mu.Lock()
	a := e.acc.rows[accessPagePRN]
	a.RequestedAt = a.RequestedAt.Add(time.Hour)
	e.acc.rows[accessPagePRN] = a
	e.acc.mu.Unlock()
	if got := e.confirm(ck, form, "approve", "r"); got.Code != http.StatusConflict || e.acc.approveCalls != 0 {
		t.Fatalf("= %d, approve calls %d", got.Code, e.acc.approveCalls)
	}
}

func TestGlovoAccessPage_UnknownRequestReadsLikeNoRequest(t *testing.T) {
	e := newAccessPageEnv(t)
	rec, _, form := e.signIn(accessPagePRN, deciderClaims())
	if rec.Code != http.StatusNotFound || form.Get("challenge") != "" {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	if got := e.send(http.MethodGet, glovoAccessPagePrefix+"not-a-principal", nil, nil); got.Code != http.StatusBadRequest {
		t.Fatalf("malformed ref = %d", got.Code)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Nothing the page renders, logs or audits carries the signed-in person's
// login name (an email here), a token or a secret.
func TestGlovoAccessPage_NoEmailsOrSecretsInPagesLogsOrAudit(t *testing.T) {
	logs := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newAccessPageEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	var bodies []string
	rec, ck, form := e.signIn(accessPagePRN, deciderClaims())
	bodies = append(bodies, rec.Body.String())
	// A refusal path is logged and audited too.
	e.acc.approveErr = errors.New("db down")
	got := e.confirm(ck, form, "approve", "r")
	bodies = append(bodies, got.Body.String())
	e.acc.approveErr = nil
	rec, ck, form = e.signIn(accessPagePRN, deciderClaims())
	bodies = append(bodies, rec.Body.String())
	got = e.confirm(ck, form, "approve", "fine")
	bodies = append(bodies, got.Body.String())
	rec, _, _ = e.signIn(accessPagePRN, map[string]any{"sub": "z-admin", "amr": []string{"pwd"}})
	bodies = append(bodies, rec.Body.String())

	entries := e.audit.List(100)
	if len(entries) == 0 {
		t.Fatal("no audit rows")
	}
	raw, _ := json.Marshal(entries)
	haystack := strings.Join(append(bodies, logs.String(), string(raw)), "\n")
	for _, secret := range []string{accessPageEmail, "someone.private", "release-secret", "z-code", "access_token", "id_token", "Bearer "} {
		if strings.Contains(haystack, secret) {
			t.Errorf("output carries %q", secret)
		}
	}
	for _, en := range entries {
		if en.Operation != glovoAccessPageAuditOp || en.Parameters["principal"] != accessPagePRN {
			t.Errorf("audit row %+v", en)
		}
		if strings.Contains(en.UserID, "@") {
			t.Errorf("audit actor %q", en.UserID)
		}
	}
}

// Admin list of pending requests.

func accessListCall(t *testing.T, h *Handlers, u *auth.User) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1"+glovoAccessAdminPath, nil)
	r = r.WithContext(auth.WithUser(r.Context(), u))
	w := httptest.NewRecorder()
	h.ListGlovoAccessRequests(w, r)
	return w
}

func accessListHandlers(acc GlovoAccessStore) *Handlers {
	g := mountedConsent(newMemConsentStore(), 5)
	g.Access = acc
	return &Handlers{opts: Options{GlovoConsent: g}}
}

func TestGlovoAccessList_AdminOnly(t *testing.T) {
	acc := newMemAccessStore()
	acc.set(accessPagePRN, glovoconsent.AccessPending)
	h := accessListHandlers(acc)
	federated := auth.NewFederatedUser("oidc", "https://issuer.example", "service-subject", "service", auth.KindService)
	federated.Groups = []string{"admins"}
	for name, u := range map[string]*auth.User{
		"nobody": nil, "service": auth.NewServiceUser(), "customer": auth.NewGitHubUser("customer", nil),
		"agent": auth.NewAgentUser("implementer", auth.AgentRun{}), "federated service": federated,
		"relayed admin": auth.NewRelayedPrincipalUser("root", signupAdminUser(t).PrincipalID(), auth.NewSurfaceUser("portal")),
	} {
		if w := accessListCall(t, h, u); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), accessPagePRN) {
			t.Errorf("%s = %d %s", name, w.Code, w.Body.String())
		}
	}
	w := accessListCall(t, h, signupAdminUser(t))
	var out struct {
		Requests []glovoAccessListItem `json:"requests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK || len(out.Requests) != 1 ||
		out.Requests[0].PrincipalID != accessPagePRN || w.Header().Get("Cache-Control") != "no-store" || out.Requests[0].DecideURL != "" {
		t.Fatalf("admin = %d %s", w.Code, w.Body.String())
	}
	h.glovoAccessApproval = newGlovoAccessDecider(&ReleaseApprovalPageOptions{BaseURL: "https://api.example"})
	w = accessListCall(t, h, signupAdminUser(t))
	if !strings.Contains(w.Body.String(), `"decide_url":"https://api.example/glovo/access-approvals/`+accessPagePRN+`"`) {
		t.Fatalf("decide_url missing: %s", w.Body.String())
	}
}

func TestGlovoAccessList_FailureIsAnErrorNotAnEmptyList(t *testing.T) {
	for name, set := range map[string]func(*memAccessStore){
		"read error": func(m *memAccessStore) { m.listErr = errors.New("boom") },
		"nil answer": func(m *memAccessStore) { m.listNil = true },
	} {
		acc := newMemAccessStore()
		acc.set(accessPagePRN, glovoconsent.AccessPending)
		set(acc)
		w := accessListCall(t, accessListHandlers(acc), signupAdminUser(t))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), `"requests"`) {
			t.Errorf("%s = %d %s", name, w.Code, w.Body.String())
		}
	}
	// A real empty queue is an empty list.
	w := accessListCall(t, accessListHandlers(newMemAccessStore()), signupAdminUser(t))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"requests":[]`) {
		t.Fatalf("empty = %d %s", w.Code, w.Body.String())
	}
	// A row that is not a pending request of a principal is a failed read.
	acc := newMemAccessStore()
	acc.set(accessPagePRN, glovoconsent.AccessApproved)
	acc.mu.Lock()
	acc.rows["x"] = glovoconsent.Access{PrincipalID: accessPagePRN, Status: glovoconsent.AccessApproved}
	acc.mu.Unlock()
	h := accessListHandlers(&listRows{memAccessStore: acc, rows: []glovoconsent.Access{{PrincipalID: accessPagePRN, Status: glovoconsent.AccessApproved}}})
	if w := accessListCall(t, h, signupAdminUser(t)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("non-pending row = %d %s", w.Code, w.Body.String())
	}
}

// listRows overrides the pending list with fixed rows.
type listRows struct {
	*memAccessStore
	rows []glovoconsent.Access
}

func (l *listRows) ListPendingAccess(context.Context) ([]glovoconsent.Access, error) {
	return l.rows, nil
}

// The admin list route is mounted only with the access store, and answers
// administrators only.
func TestGlovoAccessList_RouteMountedWithAccessStoreOnly(t *testing.T) {
	users := standardConsentUsers(t)
	users["root"] = signupAdminUser(t)
	list := "/api/v1" + glovoAccessAdminPath
	// Without the access store the route does not exist.
	e := newConsentEnv(t, mountedConsent(newMemConsentStore(), consentCap), users)
	if rec := e.call(http.MethodGet, list, "root", ""); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("no access store = %d", rec.Code)
	}
	e, _, as := accessEnv(t, users)
	as.set(consentPIDA, glovoconsent.AccessPending)
	if rec := e.call(http.MethodGet, list, "alice", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("customer = %d", rec.Code)
	}
	if rec := e.call(http.MethodGet, list, "svc", ""); rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), consentPIDA) {
		t.Fatalf("service = %d", rec.Code)
	}
	if rec := e.call(http.MethodGet, list, "root", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), consentPIDA) {
		t.Fatalf("admin = %d %s", rec.Code, rec.Body.String())
	}
	as.listErr = errors.New("boom")
	if rec := e.call(http.MethodGet, list, "root", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error = %d", rec.Code)
	}
}
