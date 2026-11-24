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
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// Decide link (mctl-glovo#82 stage C): the one-time token an owner card's
// link carries.

// memLinkStore is an in-memory GlovoAccessLinkStore over a memAccessStore.
// A token is live while it is unused and its request is the principal's
// pending one; anyState drops the pending condition to reach later guards.
type memLinkStore struct {
	acc *memAccessStore

	mu       sync.Mutex
	tokens   map[string]*memLinkToken // by hash
	checkErr error
	anyState bool
	checks   int
	byLink   int
}

type memLinkToken struct {
	pid  string
	used bool
}

func newMemLinkStore(acc *memAccessStore) *memLinkStore {
	return &memLinkStore{acc: acc, tokens: map[string]*memLinkToken{}}
}

// mint makes a well-formed token for pid; fill picks distinct ones.
func (m *memLinkStore) mint(pid string, fill byte) string {
	raw := strings.Repeat(string(fill), 43)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[glovoconsent.HashDecideToken(raw)] = &memLinkToken{pid: pid}
	return raw
}

func (m *memLinkStore) spendDirect(raw string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[glovoconsent.HashDecideToken(raw)].used = true
}

func (m *memLinkStore) live(pid, hash string) bool {
	t, ok := m.tokens[hash]
	if !ok || t.used || t.pid != pid {
		return false
	}
	if m.anyState {
		return true
	}
	st, _ := m.acc.AccessState(context.Background(), pid)
	return st == glovoconsent.AccessPending
}

func (m *memLinkStore) DecideTokenPrincipal(_ context.Context, hash string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks++
	if m.checkErr != nil {
		return "", false, m.checkErr
	}
	t, ok := m.tokens[hash]
	if !ok || !m.live(t.pid, hash) {
		return "", false, nil
	}
	return t.pid, true, nil
}

func (m *memLinkStore) CheckDecideToken(_ context.Context, pid, hash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checks++
	if m.checkErr != nil {
		return false, m.checkErr
	}
	return m.live(pid, hash), nil
}

func (m *memLinkStore) ApproveAccessByLink(ctx context.Context, pid, actor, reason string, capacity int, hash string) (glovoconsent.Access, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byLink++
	if !m.live(pid, hash) {
		return glovoconsent.Access{}, glovoconsent.ErrDecideTokenInvalid
	}
	a, err := m.acc.ApproveAccess(ctx, pid, actor, reason, capacity)
	if err == nil {
		m.tokens[hash].used = true
	}
	return a, err
}

func (m *memLinkStore) RejectAccessByLink(ctx context.Context, pid, actor, reason, hash string) (glovoconsent.Access, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byLink++
	if !m.live(pid, hash) {
		return glovoconsent.Access{}, glovoconsent.ErrDecideTokenInvalid
	}
	a, err := m.acc.RejectAccess(ctx, pid, actor, reason)
	if err == nil {
		m.tokens[hash].used = true
	}
	return a, err
}

func newAccessLinkEnv(t *testing.T) (*accessPageEnv, *memLinkStore) {
	t.Helper()
	e := newAccessPageEnv(t)
	links := newMemLinkStore(e.acc)
	e.h.opts.GlovoConsent.AccessLinks = links
	return e, links
}

func linkTarget(token string) string {
	return glovoAccessLinkPath + "?" + glovoAccessTokenParam + "=" + url.QueryEscape(token)
}

func TestGlovoAccessLink_DecidesOnceThenIsDead(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	token := links.mint(accessPagePRN, 'a')

	rec, ck, form := e.signInLink(accessPagePRN, token, deciderClaims())
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback = %d %s", rec.Code, rec.Body.String())
	}
	// The token went no further than the sign-in form.
	if strings.Contains(rec.Body.String(), token) || strings.Contains(rec.Body.String(), glovoconsent.HashDecideToken(token)) {
		t.Fatal("the decision form carries the token")
	}
	if e.status(accessPagePRN) != glovoconsent.AccessPending {
		t.Fatal("opening the link decided")
	}
	got := e.confirm(ck, form, "approve", "known colleague")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Access approved") {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if e.status(accessPagePRN) != glovoconsent.AccessApproved || links.byLink != 1 || e.acc.lastCapacity != 7 {
		t.Fatalf("status %s byLink %d capacity %d", e.status(accessPagePRN), links.byLink, e.acc.lastCapacity)
	}

	// Replay of the link: refused at the first step, with no sign-in form.
	page := e.send(http.MethodGet, linkTarget(token), nil, nil)
	if page.Code != http.StatusGone || strings.Contains(page.Body.String(), "<form") || !strings.Contains(page.Body.String(), "Nothing was decided") {
		t.Fatalf("replayed link = %d %s", page.Code, page.Body.String())
	}
}

// A token spent between the page and the decision decides nothing, though
// the request is still pending and everything else about the form is good.
func TestGlovoAccessLink_ReplayAtConfirmDecidesNothing(t *testing.T) {
	for _, decision := range []string{"approve", "reject"} {
		e, links := newAccessLinkEnv(t)
		e.acc.set(accessPagePRN, glovoconsent.AccessPending)
		token := links.mint(accessPagePRN, 'a')
		_, ck, form := e.signInLink(accessPagePRN, token, deciderClaims())
		links.spendDirect(token)
		got := e.confirm(ck, form, decision, "a reason")
		if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "Nothing was decided") {
			t.Fatalf("%s with a spent token = %d %s", decision, got.Code, got.Body.String())
		}
		if e.status(accessPagePRN) != glovoconsent.AccessPending || e.acc.approveCalls != 0 || e.acc.rejectCalls != 0 {
			t.Fatalf("%s with a spent token changed the request", decision)
		}
	}
}

// A link with a token never falls back to the token-less decision: the store
// without the token is not called at all.
func TestGlovoAccessLink_NoFallbackToTokenlessDecision(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	token := links.mint(accessPagePRN, 'a')
	_, ck, form := e.signInLink(accessPagePRN, token, deciderClaims())
	e.h.opts.GlovoConsent.AccessLinks = nil // the link store goes away mid-flow
	got := e.confirm(ck, form, "approve", "a reason")
	if got.Code != http.StatusConflict || e.acc.approveCalls != 0 || e.status(accessPagePRN) != glovoconsent.AccessPending {
		t.Fatalf("confirm = %d, approve calls %d", got.Code, e.acc.approveCalls)
	}
}

func TestGlovoAccessLink_BadTokensRefusedBeforeSignIn(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	e.acc.set(basketAdminPRN, glovoconsent.AccessApproved)
	decided := links.mint(basketAdminPRN, 'b')
	used := links.mint(accessPagePRN, 'c')
	links.spendDirect(used)
	for name, token := range map[string]string{
		"empty": "", "malformed": "short", "unknown": strings.Repeat("z", 43),
		"a decided request's": decided, "used": used, "padded": strings.Repeat("a", 42) + "=",
	} {
		page := e.send(http.MethodGet, linkTarget(token), nil, nil)
		if page.Code != http.StatusGone || strings.Contains(page.Body.String(), "<form") {
			t.Fatalf("%s token: page = %d %s", name, page.Code, page.Body.String())
		}
	}
	// The link without its parameter is as dead as a bad token.
	if page := e.send(http.MethodGet, glovoAccessLinkPath, nil, nil); page.Code != http.StatusGone {
		t.Fatalf("link without a token = %d", page.Code)
	}
	// The start step resolves the token itself: a bad one starts no sign-in.
	for name, token := range map[string]string{"malformed": "short", "empty": "", "unknown": strings.Repeat("z", 43), "used": used} {
		start := e.send(http.MethodPost, glovoAccessStartPath, nil, url.Values{"token": {token}})
		if start.Code != http.StatusGone || len(start.Result().Cookies()) != 0 {
			t.Fatalf("start with a %s token = %d", name, start.Code)
		}
	}
	// A token and a principal are never mixed: not in the start form, and
	// not on the page of a principal.
	good := links.mint(accessPagePRN, 'e')
	start := e.send(http.MethodPost, glovoAccessStartPath, nil, url.Values{"principal": {accessPagePRN}, "token": {good}})
	if start.Code != http.StatusBadRequest || len(start.Result().Cookies()) != 0 {
		t.Fatalf("start with a token and a principal = %d", start.Code)
	}
	page := e.send(http.MethodGet, glovoAccessPagePrefix+accessPagePRN+"?"+glovoAccessTokenParam+"="+good, nil, nil)
	if page.Code != http.StatusGone || strings.Contains(page.Body.String(), "<form") {
		t.Fatalf("token on a principal's page = %d", page.Code)
	}
	// Without a link store every token is refused; the token-less page works.
	e.h.opts.GlovoConsent.AccessLinks = nil
	live := links.mint(accessPagePRN, 'd')
	if page := e.send(http.MethodGet, linkTarget(live), nil, nil); page.Code != http.StatusGone {
		t.Fatalf("token with no link store = %d", page.Code)
	}
	if page := e.send(http.MethodGet, glovoAccessPagePrefix+accessPagePRN, nil, nil); page.Code != http.StatusOK {
		t.Fatalf("token-less page = %d", page.Code)
	}
}

// A token that stops being live during the sign-in is refused when the
// person comes back, before any decision form.
func TestGlovoAccessLink_RecheckedAfterSignIn(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	token := links.mint(accessPagePRN, 'a')
	// The token is live when the sign-in starts and dies during it: the
	// start step keeps only the hash, the callback must check it again.
	dead := links.mint(accessPagePRN, 'q')
	start := e.send(http.MethodPost, glovoAccessStartPath, nil, url.Values{"token": {dead}})
	if start.Code != http.StatusSeeOther {
		t.Fatalf("start = %d", start.Code)
	}
	links.spendDirect(dead)
	var ck *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == glovoAccessPageCookie {
			ck = c
		}
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	q := u.Query()
	e.idp.mu.Lock()
	e.idp.challenge, e.idp.nonce, e.idp.extra, e.idp.username = q.Get("code_challenge"), q.Get("nonce"), deciderClaims(), accessPageEmail
	e.idp.mu.Unlock()
	rec := e.send(http.MethodGet, glovoAccessCallbackPath+"?code=z-code&state="+url.QueryEscape(q.Get("state")), ck, nil)
	if rec.Code != http.StatusGone || strings.Contains(rec.Body.String(), `name="csrf"`) {
		t.Fatalf("callback with a dead token = %d %s", rec.Code, rec.Body.String())
	}
	// The live token still works afterwards.
	if rec, _, form := e.signInLink(accessPagePRN, token, deciderClaims()); rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("live link = %d", rec.Code)
	}
}

func TestGlovoAccessLink_UnreadableTokenIs503(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	token := links.mint(accessPagePRN, 'a')
	links.checkErr = errors.New("db down")
	page := e.send(http.MethodGet, linkTarget(token), nil, nil)
	if page.Code != http.StatusServiceUnavailable || strings.Contains(page.Body.String(), "<form") {
		t.Fatalf("page = %d %s", page.Code, page.Body.String())
	}
	start := e.send(http.MethodPost, glovoAccessStartPath, nil, url.Values{"token": {token}})
	if start.Code != http.StatusServiceUnavailable || len(start.Result().Cookies()) != 0 {
		t.Fatalf("start = %d", start.Code)
	}
	if e.status(accessPagePRN) != glovoconsent.AccessPending {
		t.Fatal("a failed token read decided")
	}
}

// The link is for a pending request: it cannot revoke.
func TestGlovoAccessLink_CannotRevoke(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	links.anyState = true
	e.acc.set(accessPagePRN, glovoconsent.AccessApproved)
	token := links.mint(accessPagePRN, 'a')
	_, ck, form := e.signInLink(accessPagePRN, token, deciderClaims())
	got := e.confirm(ck, form, "revoke", "a reason")
	if got.Code != http.StatusConflict || e.acc.revokeCalls != 0 || e.status(accessPagePRN) != glovoconsent.AccessApproved {
		t.Fatalf("revoke through a link = %d, revoke calls %d", got.Code, e.acc.revokeCalls)
	}
}

// The admin list's decide_url has no token and keeps working: the sign-in,
// the second factor and the deciders list are what prove the person.
func TestGlovoAccessLink_TokenlessPageStillDecides(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	_, ck, form := e.signIn(accessPagePRN, deciderClaims())
	got := e.confirm(ck, form, "approve", "from the list")
	if got.Code != http.StatusOK || e.status(accessPagePRN) != glovoconsent.AccessApproved {
		t.Fatalf("confirm = %d %s", got.Code, got.Body.String())
	}
	if links.checks != 0 || links.byLink != 0 || e.acc.approveCalls != 1 {
		t.Fatalf("token-less decision touched the link store: checks %d byLink %d", links.checks, links.byLink)
	}
}

// A link does not replace any check: without the second factor, or for
// someone who is not a decider, a live token decides nothing.
func TestGlovoAccessLink_ReplacesNoCheck(t *testing.T) {
	e, links := newAccessLinkEnv(t)
	e.acc.set(accessPagePRN, glovoconsent.AccessPending)
	token := links.mint(accessPagePRN, 'a')
	rec, _, form := e.signInLink(accessPagePRN, token, map[string]any{"amr": []string{"pwd"}})
	if rec.Code == http.StatusOK || form.Get("csrf") != "" {
		t.Fatalf("no second factor = %d", rec.Code)
	}
	e.ropts.Deciders = []string{"prn_ZZZZZZZZZZZZZZZZZZZZZZZZZ9"}
	e.h.glovoAccessApproval = newGlovoAccessDecider(e.ropts)
	rec, _, form = e.signInLink(accessPagePRN, token, deciderClaims())
	if rec.Code == http.StatusOK || form.Get("csrf") != "" {
		t.Fatalf("not a decider = %d", rec.Code)
	}
	if e.status(accessPagePRN) != glovoconsent.AccessPending || links.byLink != 0 {
		t.Fatal("a refused sign-in decided")
	}
}
