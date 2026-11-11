package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// mctl-api runs more than one replica: the basket approval page keeps its
// challenges in the shared OAuth flow store, so any replica, or a restarted
// one, serves any step, and each step is taken exactly once across all of
// them. Each replica below is its own Handlers with its own decider, sharing
// only the database and ZITADEL.

// The full flow across replicas: started on A, back from ZITADEL on B,
// confirmed on A. A replay on B, and a used sign-in on either, are refused.
func TestGlovoBasketReplicas_StartAcallbackBconfirmA(t *testing.T) {
	e := newBasketEnv(t)
	a, b := e.page, e.replica()
	id := e.pending("replicas")

	ck, state := e.startOn(a, id)
	rec, form := e.callbackOn(b, ck, state, "z-owner")
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback on B = %d %s", rec.Code, rec.Body.String())
	}
	// The sign-in was taken by B: replaying it on either replica finds
	// nothing.
	for name, p := range map[string]http.Handler{"A": a, "B": b} {
		if again, f := e.callbackOn(p, ck, state, "z-owner"); again.Code != http.StatusBadRequest || f.Get("csrf") != "" {
			t.Errorf("callback replayed on %s = %d", name, again.Code)
		}
	}

	res := e.confirmOn(a, ck, form, "approve")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "Basket approved") {
		t.Fatalf("confirm on A = %d %s", res.Code, res.Body.String())
	}
	if again := e.confirmOn(b, ck, form, "approve"); again.Code != http.StatusBadRequest {
		t.Errorf("confirm replayed on B = %d", again.Code)
	}
	if again := e.confirmOn(a, ck, form, "reject"); again.Code != http.StatusBadRequest {
		t.Errorf("confirm replayed on A = %d", again.Code)
	}
	if e.ledger.count() != 1 || e.state(id) != workitems.ApprovalApproved {
		t.Fatalf("ledger %d, state %s", e.ledger.count(), e.state(id))
	}
}

// A restart loses nothing pending: a replica that did not exist when the
// sign-in started completes it, and another new one takes the confirm.
func TestGlovoBasketReplicas_RestartKeepsPendingChallenge(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("restart")
	ck, state := e.startOn(e.page, id)

	restarted := e.replica()
	rec, form := e.callbackOn(restarted, ck, state, "z-owner")
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("callback after restart = %d %s", rec.Code, rec.Body.String())
	}
	if res := e.confirmOn(e.replica(), ck, form, "reject"); res.Code != http.StatusOK {
		t.Fatalf("confirm after another restart = %d %s", res.Code, res.Body.String())
	}
	if e.ledger.count() != 1 || e.state(id) != workitems.ApprovalDenied {
		t.Fatalf("ledger %d, state %s", e.ledger.count(), e.state(id))
	}
}

// expireEntry ages one flow store entry past its TTL on the store's clock.
func (e *basketEnv) expireEntry(kind, key string) {
	e.t.Helper()
	h := sha256.Sum256([]byte(key))
	tag, err := e.pool.Exec(context.Background(),
		`UPDATE oauth_flow_entries SET expires_at = now() - interval '1 second' WHERE kind=$1 AND key_hash=$2`, kind, h[:])
	if err != nil || tag.RowsAffected() != 1 {
		e.t.Fatalf("expire %s: %v, %d rows", kind, err, tag.RowsAffected())
	}
}

// Expired is refused, whichever clock says so: the store's TTL for a sign-in
// and for a shown basket, and the page's ten minutes counted from the start.
func TestGlovoBasketReplicas_ExpiredChallengeIsRefused(t *testing.T) {
	e := newBasketEnv(t)

	id := e.pending("expired-start")
	ck, state := e.startOn(e.page, id)
	e.expireEntry(basketKindStart, basketStartKey(state, ck.Value))
	if rec, form := e.callbackOn(e.replica(), ck, state, "z-owner"); rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
		t.Errorf("expired sign-in = %d %s", rec.Code, rec.Body.String())
	}

	id2 := e.pending("expired-decide")
	_, ck2, form2 := e.signIn(id2, "z-owner")
	e.expireEntry(basketKindDecide, basketDecideKey(form2.Get("challenge"), form2.Get("csrf"), ck2.Value))
	if res := e.confirmOn(e.replica(), ck2, form2, "approve"); res.Code != http.StatusBadRequest {
		t.Errorf("expired confirm = %d", res.Code)
	}

	// Live in the store, but past the page's ten minutes on the replica that
	// serves it.
	id3 := e.pending("expired-clock")
	_, ck3, form3 := e.signIn(id3, "z-owner")
	late := e.replica(func(o *GlovoBasketApprovalPageOptions) {
		o.clock = func() time.Time { return time.Now().Add(basketChallengeTTL + time.Minute) }
	})
	if res := e.confirmOn(late, ck3, form3, "approve"); res.Code != http.StatusBadRequest {
		t.Errorf("confirm past ten minutes = %d", res.Code)
	}

	if e.ledger.count() != 0 || e.state(id2) != workitems.ApprovalPending || e.state(id3) != workitems.ApprovalPending {
		t.Fatalf("an expired challenge decided: ledger %d", e.ledger.count())
	}
}

// Two confirms of the same form racing on two replicas: the store hands the
// challenge to exactly one, which decides; every other is refused by the
// consume itself and never reaches the decision handler.
func TestGlovoBasketReplicas_ConcurrentConfirmsDecideOnce(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("race")
	_, ck, form := e.signIn(id, "z-owner")
	replicas := []http.Handler{e.page, e.replica()}

	const n = 8
	codes := make([]int, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			res := e.sendTo(replicas[i%2], http.MethodPost, basketConfirmPath, ck, url.Values{
				"challenge": {form.Get("challenge")}, "csrf": {form.Get("csrf")}, "decision": {"approve"},
			})
			codes[i], bodies[i] = res.Code, res.Body.String()
		}(i)
	}
	close(gate)
	wg.Wait()

	ok := 0
	for i, c := range codes {
		switch {
		case c == http.StatusOK:
			ok++
		case c != http.StatusBadRequest || !strings.Contains(bodies[i], "already used"):
			t.Errorf("confirm %d = %d %s, want the consume's refusal", i, c, bodies[i])
		}
	}
	if ok != 1 {
		t.Fatalf("%d confirms succeeded, want exactly 1 (codes %v)", ok, codes)
	}
	if e.ledger.count() != 1 || e.state(id) != workitems.ApprovalApproved {
		t.Fatalf("ledger %d, state %s", e.ledger.count(), e.state(id))
	}
	if got := e.auditOps("action_approval.decision_refused", id); got != 0 {
		t.Fatalf("%d losing confirms reached the decision handler", got)
	}
}

// downStore is a flow store that cannot be read or written.
type downStore struct{}

var errStoreDown = errors.New("flow store down")

func (downStore) Put(context.Context, string, string, []byte, time.Duration) error {
	return errStoreDown
}

func (downStore) Take(context.Context, string, string) ([]byte, bool, error) {
	return nil, false, errStoreDown
}

func (downStore) PutOnce(context.Context, string, string, []byte, time.Duration) (bool, error) {
	return false, errStoreDown
}

func (downStore) GC(context.Context) error { return errStoreDown }

var _ flowstore.Store = downStore{}

// A store that cannot be read is not a store that answered "no such
// challenge": every step refuses with 503, decides nothing and spends
// nothing, and the same challenge still works once the store is back.
func TestGlovoBasketReplicas_StoreDownFailsClosed(t *testing.T) {
	e := newBasketEnv(t)
	down := e.replica(func(o *GlovoBasketApprovalPageOptions) { o.Flow = downStore{} })
	id := e.pending("store-down")

	if rec := e.sendTo(down, http.MethodPost, basketStartPath, nil, url.Values{"approval_ref": {id}}); rec.Code != http.StatusServiceUnavailable ||
		len(rec.Result().Cookies()) != 0 || rec.Header().Get("Location") != "" {
		t.Errorf("start with the store down = %d, cookies %v", rec.Code, rec.Result().Cookies())
	}

	ck, state := e.startOn(e.page, id)
	if rec, form := e.callbackOn(down, ck, state, "z-owner"); rec.Code != http.StatusServiceUnavailable || form.Get("csrf") != "" {
		t.Errorf("callback with the store down = %d %s", rec.Code, rec.Body.String())
	}
	rec, form := e.callbackOn(e.page, ck, state, "z-owner")
	if rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("the same sign-in once the store is back = %d %s", rec.Code, rec.Body.String())
	}

	if res := e.confirmOn(down, ck, form, "approve"); res.Code != http.StatusServiceUnavailable ||
		!strings.Contains(res.Body.String(), "nothing was decided") || len(res.Result().Cookies()) != 0 {
		t.Errorf("confirm with the store down = %d %s", res.Code, res.Body.String())
	}
	if e.ledger.count() != 0 || e.state(id) != workitems.ApprovalPending {
		t.Fatal("a confirm decided without the store")
	}
	if res := e.confirmOn(e.page, ck, form, "approve"); res.Code != http.StatusOK {
		t.Fatalf("the same confirm once the store is back = %d %s", res.Code, res.Body.String())
	}
}

// An owner who lost the team's developer membership is not offered a click
// the decision handler would refuse, and one who loses it between the view
// and the click is told why, in the page's words.
func TestGlovoBasketPage_LostMembership(t *testing.T) {
	e := newBasketEnv(t)
	key := glovoTenant + "|" + glovoOwnerPRN

	id := e.pending("no-member")
	delete(e.members.roles, key)
	rec, _, form := e.signIn(id, "z-owner")
	if rec.Code != http.StatusForbidden || form.Get("csrf") != "" ||
		!strings.Contains(rec.Body.String(), "not a developer of team "+glovoTenant) ||
		!strings.Contains(rec.Body.String(), "Synthetic Margherita") {
		t.Errorf("view without membership = %d %s", rec.Code, rec.Body.String())
	}
	e.members.roles[key] = "developer"

	id2 := e.pending("lost-member")
	_, ck, form2 := e.signIn(id2, "z-owner")
	if form2.Get("csrf") == "" {
		t.Fatal("no decide form for a member")
	}
	delete(e.members.roles, key)
	res := e.confirm(ck, form2, "approve")
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "not a developer of team "+glovoTenant) ||
		strings.Contains(res.Body.String(), "admin acting directly") {
		t.Errorf("confirm after losing membership = %d %s", res.Code, res.Body.String())
	}
	if e.ledger.count() != 0 || e.state(id) != workitems.ApprovalPending || e.state(id2) != workitems.ApprovalPending {
		t.Fatal("a former member decided")
	}
}

// The ZITADEL callback belongs to the browser that started the sign-in: one
// arriving with another browser's cookie, or none, finds nothing and spends
// nothing, and the real browser still completes it.
func TestGlovoBasketPage_CallbackNeedsTheStartingBrowser(t *testing.T) {
	e := newBasketEnv(t)
	id := e.pending("callback-browser")
	ck, state := e.startOn(e.page, id)
	other := &http.Cookie{Name: basketCookieName, Value: "another-browser"}
	for name, c := range map[string]*http.Cookie{"another browser": other, "no cookie": nil} {
		if rec, form := e.callbackOn(e.replica(), c, state, "z-owner"); rec.Code != http.StatusBadRequest || form.Get("csrf") != "" {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec, form := e.callbackOn(e.page, ck, state, "z-owner"); rec.Code != http.StatusOK || form.Get("csrf") == "" {
		t.Fatalf("the starting browser = %d %s", rec.Code, rec.Body.String())
	}
}
