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
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// Glovo access notifications (mctl-glovo#82 stage C): the delivery loop.

const (
	notifyTestPRN  = "prn_AAAAAAAAAAAAAAAAAAAAAAAAA1"
	notifyTestMail = "someone.private@example.invalid"
	notifyTestBase = "https://api.example"
)

var notifyTestAt = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// fakeNotifyStore is an in-memory outbox. It has no way to write an access
// row: the notifier's store interface offers none.
type fakeNotifyStore struct {
	queue     []glovoconsent.Notification
	access    map[string]glovoconsent.Access
	leaseErr  error
	accessErr error
	mintErr   error
	ackErr    error
	sweepErr  error
	lapsed    int
	expired   int

	leases    []string
	acked     map[int64]string
	abandoned map[int64]string
	minted    []string
	sweeps    int
}

func newFakeNotifyStore() *fakeNotifyStore {
	return &fakeNotifyStore{access: map[string]glovoconsent.Access{}, acked: map[int64]string{}, abandoned: map[int64]string{}}
}

// add queues one row about notifyTestPRN and sets the access row to match.
func (f *fakeNotifyStore) add(kind glovoconsent.NotifyKind, status glovoconsent.AccessStatus) glovoconsent.Notification {
	n := glovoconsent.Notification{
		ID: int64(len(f.queue) + 1), PrincipalID: notifyTestPRN, Kind: kind,
		RequestedAt: notifyTestAt, ExpiresAt: notifyTestAt.Add(glovoconsent.AccessRequestTTL), CreatedAt: notifyTestAt, Attempts: 1,
	}
	f.queue = append(f.queue, n)
	a := glovoconsent.Access{PrincipalID: notifyTestPRN, Status: status, RequestedAt: n.RequestedAt, ExpiresAt: n.ExpiresAt}
	if status == glovoconsent.AccessApproved || status == glovoconsent.AccessRejected || status == glovoconsent.AccessRevoked {
		a.DecidedBy = "prn_CCCCCCCCCCCCCCCCCCCCCCCCC3"
	}
	f.access[notifyTestPRN] = a
	return n
}

func (f *fakeNotifyStore) LeaseNotification(_ context.Context, lease string) (glovoconsent.Notification, bool, error) {
	if f.leaseErr != nil {
		return glovoconsent.Notification{}, false, f.leaseErr
	}
	if len(f.queue) == 0 {
		return glovoconsent.Notification{}, false, nil
	}
	n := f.queue[0]
	f.queue = f.queue[1:]
	f.leases = append(f.leases, lease)
	return n, true, nil
}

func (f *fakeNotifyStore) AckNotification(_ context.Context, id int64, _, deliveryID string) error {
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked[id] = deliveryID
	return nil
}

func (f *fakeNotifyStore) AbandonNotification(_ context.Context, id int64, _, outcome string) error {
	f.abandoned[id] = outcome
	return nil
}

func (f *fakeNotifyStore) EnqueueLapsed(context.Context) (int, error) {
	f.sweeps++
	return f.lapsed, f.sweepErr
}

func (f *fakeNotifyStore) ExpireNotifications(context.Context) (int, error) {
	return f.expired, f.sweepErr
}

func (f *fakeNotifyStore) MintDecideToken(_ context.Context, _ string, _ time.Time) (string, error) {
	if f.mintErr != nil {
		return "", f.mintErr
	}
	raw := strings.Repeat(string("abcdefghijklmnopqrstuvwxyz"[len(f.minted)%26]), 43)
	f.minted = append(f.minted, raw)
	return raw, nil
}

func (f *fakeNotifyStore) GetAccess(_ context.Context, pid string) (glovoconsent.Access, error) {
	if f.accessErr != nil {
		return glovoconsent.Access{}, f.accessErr
	}
	if a, ok := f.access[pid]; ok {
		return a, nil
	}
	return glovoconsent.Access{PrincipalID: pid, Status: glovoconsent.AccessNone}, nil
}

type notifyIdentity struct {
	facts glovoconsent.IdentityFacts
	err   error
}

func (f notifyIdentity) IdentityFacts(context.Context, string) (glovoconsent.IdentityFacts, error) {
	return f.facts, f.err
}

// notifyEnv is a notifier over fakes that records every bridge call.
type notifyEnv struct {
	store     *fakeNotifyStore
	n         *GlovoAccessNotifier
	sent      []map[string]any
	bridgeErr error
	receipt   func(body map[string]any) string
	recipErr  error
	recipient string
	recips    int
	logs      *lockedBuffer
}

func newNotifyEnv(t *testing.T) *notifyEnv {
	t.Helper()
	e := &notifyEnv{store: newFakeNotifyStore(), recipient: notifyTestMail, logs: &lockedBuffer{}}
	e.receipt = func(body map[string]any) string {
		raw, _ := json.Marshal(map[string]any{"delivery_key": body["delivery_key"], "delivery_id": "d-" + body["kind"].(string)})
		return string(raw)
	}
	e.n = &GlovoAccessNotifier{
		Store: e.store,
		Identity: notifyIdentity{facts: glovoconsent.IdentityFacts{DisplayName: "Alice Example",
			Identities: []glovoconsent.IdentityFact{{Provider: "google"}}}},
		Recipient: func(context.Context, string) (string, error) {
			e.recips++
			return e.recipient, e.recipErr
		},
		Bridge: func(_ context.Context, body []byte) ([]byte, error) {
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatalf("bridge body %s: %v", body, err)
			}
			e.sent = append(e.sent, m)
			if e.bridgeErr != nil {
				return nil, e.bridgeErr
			}
			return []byte(e.receipt(m)), nil
		},
		PageBaseURL: notifyTestBase,
	}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return e
}

func notifyCount(kind, outcome string) float64 {
	return testutil.ToFloat64(glovoAccessNotifications.WithLabelValues(kind, outcome))
}

var notifyLink = regexp.MustCompile(`^https://api\.example/glovo/access-approvals/link\?t=([A-Za-z0-9_-]{43})$`)

func TestGlovoNotify_OwnerCard(t *testing.T) {
	e := newNotifyEnv(t)
	row := e.store.add(glovoconsent.NotifyOwnerCard, glovoconsent.AccessPending)
	before := notifyCount("owner_card", glovoNotifySent)
	e.n.Round(context.Background())

	if len(e.sent) != 1 {
		t.Fatalf("%d bridge calls", len(e.sent))
	}
	body := e.sent[0]
	card, _ := body["card"].(map[string]any)
	if body["kind"] != "owner_card" || body["delivery_key"] != row.DeliveryKey() || card == nil {
		t.Fatalf("body %v", body)
	}
	if _, has := body["to"]; has || e.recips != 0 {
		t.Fatal("the owner card looked up or carried an address")
	}
	m := notifyLink.FindStringSubmatch(card["decide_url"].(string))
	if m == nil || len(e.store.minted) != 1 || m[1] != e.store.minted[0] {
		t.Fatalf("decide_url %v minted %v", card["decide_url"], e.store.minted)
	}
	if card["identity"] != "google:A***" || card["requested_at"] != "2026-11-23T12:00:00Z" || card["expires_at"] != "2026-11-30T12:00:00Z" || len(card) != 4 {
		t.Fatalf("card %v", card)
	}
	if e.store.acked[row.ID] != "d-owner_card" || len(e.store.abandoned) != 0 {
		t.Fatalf("acked %v abandoned %v", e.store.acked, e.store.abandoned)
	}
	if notifyCount("owner_card", glovoNotifySent) != before+1 {
		t.Fatal("sent not counted")
	}
	// Neither the token nor the link is logged.
	if logs := e.logs.String(); strings.Contains(logs, m[1]) || strings.Contains(logs, "access-approvals") || strings.Contains(logs, notifyTestPRN) {
		t.Fatalf("logs leak: %s", logs)
	}
}

// A card without a buildable label still goes out, with no identity; a
// failed read of the facts does not.
func TestGlovoNotify_OwnerCardIdentity(t *testing.T) {
	e := newNotifyEnv(t)
	e.n.Identity = notifyIdentity{}
	row := e.store.add(glovoconsent.NotifyOwnerCard, glovoconsent.AccessPending)
	e.n.Round(context.Background())
	if len(e.sent) != 1 || e.store.acked[row.ID] == "" {
		t.Fatalf("sent %d acked %v", len(e.sent), e.store.acked)
	}
	if _, has := e.sent[0]["card"].(map[string]any)["identity"]; has {
		t.Fatal("identity invented")
	}

	e = newNotifyEnv(t)
	e.n.Identity = notifyIdentity{err: errors.New("db down")}
	row = e.store.add(glovoconsent.NotifyOwnerCard, glovoconsent.AccessPending)
	e.n.Round(context.Background())
	if len(e.sent) != 0 || len(e.store.minted) != 0 || len(e.store.acked) != 0 || len(e.store.abandoned) != 0 {
		t.Fatalf("unreadable identity: sent %d minted %d acked %v abandoned %v", len(e.sent), len(e.store.minted), e.store.acked, e.store.abandoned)
	}
	_ = row
}

func TestGlovoNotify_EachEmailKindSendsOnce(t *testing.T) {
	for kind, status := range map[glovoconsent.NotifyKind]glovoconsent.AccessStatus{
		glovoconsent.NotifyApproved: glovoconsent.AccessApproved,
		glovoconsent.NotifyRejected: glovoconsent.AccessRejected,
		glovoconsent.NotifyLapsed:   glovoconsent.AccessNone, // a lapsed pending row reads as none
	} {
		e := newNotifyEnv(t)
		row := e.store.add(kind, status)
		e.n.Round(context.Background())
		want := map[string]any{"delivery_key": row.DeliveryKey(), "kind": string(kind), "to": notifyTestMail}
		if len(e.sent) != 1 || len(e.sent[0]) != 3 {
			t.Fatalf("%s: sent %v", kind, e.sent)
		}
		for k, v := range want {
			if e.sent[0][k] != v {
				t.Fatalf("%s: %s = %v, want %v", kind, k, e.sent[0][k], v)
			}
		}
		if e.store.acked[row.ID] != "d-"+string(kind) || len(e.store.minted) != 0 || e.recips != 1 {
			t.Fatalf("%s: acked %v minted %d recips %d", kind, e.store.acked, len(e.store.minted), e.recips)
		}
		// The address is sent, never logged.
		if logs := e.logs.String(); strings.Contains(logs, notifyTestMail) || strings.Contains(logs, notifyTestPRN) {
			t.Fatalf("%s: logs leak: %s", kind, logs)
		}
	}
}

// With the emails switched off the notifier has no recipient lookup: an
// email row is closed unsent and no address is asked for, while the owner
// card is delivered as usual.
func TestGlovoNotify_EmailsOffSendOnlyTheCard(t *testing.T) {
	for kind, status := range map[glovoconsent.NotifyKind]glovoconsent.AccessStatus{
		glovoconsent.NotifyApproved: glovoconsent.AccessApproved,
		glovoconsent.NotifyRejected: glovoconsent.AccessRejected,
		glovoconsent.NotifyLapsed:   glovoconsent.AccessNone,
	} {
		e := newNotifyEnv(t)
		e.n.Recipient = nil
		row := e.store.add(kind, status)
		before := notifyCount(string(kind), glovoNotifyEmailOff)
		e.n.Round(context.Background())
		if len(e.sent) != 0 || e.recips != 0 || len(e.store.acked) != 0 || e.store.abandoned[row.ID] != glovoNotifyEmailOff {
			t.Fatalf("%s: sent %v recips %d abandoned %v", kind, e.sent, e.recips, e.store.abandoned)
		}
		if notifyCount(string(kind), glovoNotifyEmailOff) != before+1 {
			t.Fatalf("%s: email_off not counted", kind)
		}
	}
	e := newNotifyEnv(t)
	e.n.Recipient = nil
	row := e.store.add(glovoconsent.NotifyOwnerCard, glovoconsent.AccessPending)
	e.n.Round(context.Background())
	if !e.n.Ready() || len(e.sent) != 1 || e.sent[0]["kind"] != "owner_card" || e.store.acked[row.ID] == "" || e.recips != 0 {
		t.Fatalf("card with the emails off: sent %v acked %v", e.sent, e.store.acked)
	}
}

// A failed send leaves the row for the next lease and changes nothing else:
// no ack, no abandon. The decision is not the notifier's to touch.
func TestGlovoNotify_FailedSendIsRetriedNotClosed(t *testing.T) {
	for name, breakIt := range map[string]func(*notifyEnv){
		"bridge error":     func(e *notifyEnv) { e.bridgeErr = errors.New("503 from " + notifyTestMail) },
		"receipt not json": func(e *notifyEnv) { e.receipt = func(map[string]any) string { return "<html>" } },
		"receipt wrong key": func(e *notifyEnv) {
			e.receipt = func(map[string]any) string { return `{"delivery_key":"other","delivery_id":"d"}` }
		},
		"receipt without id": func(e *notifyEnv) {
			e.receipt = func(b map[string]any) string { return `{"delivery_key":"` + b["delivery_key"].(string) + `"}` }
		},
		"receipt id too long": func(e *notifyEnv) {
			e.receipt = func(b map[string]any) string {
				return `{"delivery_key":"` + b["delivery_key"].(string) + `","delivery_id":"` + strings.Repeat("x", 201) + `"}`
			}
		},
		"ack lost": func(e *notifyEnv) { e.store.ackErr = glovoconsent.ErrNotifyLeaseLost },
	} {
		e := newNotifyEnv(t)
		breakIt(e)
		e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
		before := e.store.access[notifyTestPRN]
		e.n.Round(context.Background())
		if len(e.sent) != 1 || len(e.store.acked) != 0 || len(e.store.abandoned) != 0 {
			t.Fatalf("%s: sent %d acked %v abandoned %v", name, len(e.sent), e.store.acked, e.store.abandoned)
		}
		if e.store.access[notifyTestPRN] != before {
			t.Fatalf("%s: the access row changed", name)
		}
		if strings.Contains(e.logs.String(), notifyTestMail) && name != "bridge error" {
			t.Fatalf("%s: logs leak", name)
		}
		if !strings.Contains(e.logs.String(), "attempt failed") {
			t.Fatalf("%s: failure not logged: %s", name, e.logs.String())
		}
	}
}

func TestGlovoNotify_SupersededIsDroppedNotSent(t *testing.T) {
	type c struct {
		kind   glovoconsent.NotifyKind
		mutate func(a *glovoconsent.Access)
	}
	for name, tc := range map[string]c{
		"card after decision":      {glovoconsent.NotifyOwnerCard, func(a *glovoconsent.Access) { a.Status = glovoconsent.AccessApproved }},
		"card for earlier request": {glovoconsent.NotifyOwnerCard, func(a *glovoconsent.Access) { a.RequestedAt = a.RequestedAt.Add(time.Hour) }},
		"approved then revoked":    {glovoconsent.NotifyApproved, func(a *glovoconsent.Access) { a.Status = glovoconsent.AccessRevoked }},
		"rejected then re-asked": {glovoconsent.NotifyRejected, func(a *glovoconsent.Access) {
			a.Status, a.RequestedAt = glovoconsent.AccessPending, a.RequestedAt.Add(time.Hour)
		}},
		"withdrawn by requester": {glovoconsent.NotifyRejected, func(a *glovoconsent.Access) { a.DecidedBy = a.PrincipalID }},
		"lapsed then re-asked": {glovoconsent.NotifyLapsed, func(a *glovoconsent.Access) {
			a.Status, a.RequestedAt = glovoconsent.AccessPending, a.RequestedAt.Add(time.Hour)
		}},
		"lapsed but still pending": {glovoconsent.NotifyLapsed, func(a *glovoconsent.Access) { a.Status = glovoconsent.AccessPending }},
	} {
		e := newNotifyEnv(t)
		status := map[glovoconsent.NotifyKind]glovoconsent.AccessStatus{
			glovoconsent.NotifyOwnerCard: glovoconsent.AccessPending, glovoconsent.NotifyApproved: glovoconsent.AccessApproved,
			glovoconsent.NotifyRejected: glovoconsent.AccessRejected, glovoconsent.NotifyLapsed: glovoconsent.AccessNone,
		}[tc.kind]
		row := e.store.add(tc.kind, status)
		a := e.store.access[notifyTestPRN]
		tc.mutate(&a)
		e.store.access[notifyTestPRN] = a
		e.n.Round(context.Background())
		if len(e.sent) != 0 || e.recips != 0 || len(e.store.minted) != 0 || e.store.abandoned[row.ID] != glovoNotifySuperseded {
			t.Fatalf("%s: sent %d recips %d minted %d abandoned %v", name, len(e.sent), e.recips, len(e.store.minted), e.store.abandoned)
		}
	}
	// A request decided between the read and the mint: no token, no card.
	e := newNotifyEnv(t)
	row := e.store.add(glovoconsent.NotifyOwnerCard, glovoconsent.AccessPending)
	e.store.mintErr = glovoconsent.ErrAccessNotPending
	e.n.Round(context.Background())
	if len(e.sent) != 0 || e.store.abandoned[row.ID] != glovoNotifySuperseded {
		t.Fatalf("mint refused: sent %d abandoned %v", len(e.sent), e.store.abandoned)
	}
}

func TestGlovoNotify_RecipientAbsentVersusUnreadable(t *testing.T) {
	// Documented absence: closed, counted, nothing sent.
	e := newNotifyEnv(t)
	row := e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
	e.recipErr, e.recipient = ErrGlovoNoRecipient, ""
	before := notifyCount("approved", glovoNotifyNoRecipient)
	e.n.Round(context.Background())
	if len(e.sent) != 0 || e.store.abandoned[row.ID] != glovoNotifyNoRecipient || notifyCount("approved", glovoNotifyNoRecipient) != before+1 {
		t.Fatalf("no recipient: sent %d abandoned %v", len(e.sent), e.store.abandoned)
	}
	// A failed lookup, or an empty answer without the absence error, is
	// retried: never closed as "no recipient".
	for name, set := range map[string]func(*notifyEnv){
		"lookup error": func(e *notifyEnv) { e.recipErr, e.recipient = errors.New("IdP said "+notifyTestMail), "" },
		"empty answer": func(e *notifyEnv) { e.recipErr, e.recipient = nil, "" },
	} {
		e := newNotifyEnv(t)
		e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
		set(e)
		e.n.Round(context.Background())
		if len(e.sent) != 0 || len(e.store.abandoned) != 0 || len(e.store.acked) != 0 {
			t.Fatalf("%s: sent %d abandoned %v", name, len(e.sent), e.store.abandoned)
		}
		if strings.Contains(e.logs.String(), notifyTestMail) {
			t.Fatalf("%s: the lookup error reached the log: %s", name, e.logs.String())
		}
	}
}

func TestGlovoNotify_UnreadableStateIsRetried(t *testing.T) {
	e := newNotifyEnv(t)
	e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
	e.store.accessErr = errors.New("db down")
	e.n.Round(context.Background())
	if len(e.sent) != 0 || len(e.store.abandoned) != 0 {
		t.Fatalf("unreadable access: sent %d abandoned %v", len(e.sent), e.store.abandoned)
	}
	// A failed lease ends the round; it is not "nothing to do".
	e = newNotifyEnv(t)
	e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
	e.store.leaseErr = errors.New("db down")
	before := notifyCount("any", glovoNotifyLeaseError)
	e.n.Round(context.Background())
	if len(e.sent) != 0 || notifyCount("any", glovoNotifyLeaseError) != before+1 {
		t.Fatal("lease error not counted or something was sent")
	}
	// Token minting failure: no card without a link.
	e = newNotifyEnv(t)
	e.store.add(glovoconsent.NotifyOwnerCard, glovoconsent.AccessPending)
	e.store.mintErr = errors.New("db down")
	e.n.Round(context.Background())
	if len(e.sent) != 0 || len(e.store.abandoned) != 0 {
		t.Fatalf("mint error: sent %d abandoned %v", len(e.sent), e.store.abandoned)
	}
}

func TestGlovoNotify_RoundSweepsAndBounds(t *testing.T) {
	e := newNotifyEnv(t)
	e.store.expired = 2
	for i := 0; i < glovoNotifyBatch+3; i++ {
		e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
	}
	before := notifyCount("any", glovoconsent.NotifyOutcomeExpired)
	e.n.Round(context.Background())
	if e.store.sweeps != 1 || len(e.sent) != glovoNotifyBatch || notifyCount("any", glovoconsent.NotifyOutcomeExpired) != before+2 {
		t.Fatalf("sweeps %d sent %d", e.store.sweeps, len(e.sent))
	}
	seen := map[string]bool{}
	for _, l := range e.store.leases {
		if l == "" || seen[l] {
			t.Fatalf("lease %q reused or empty", l)
		}
		seen[l] = true
	}
	// A failed sweep does not stop delivery.
	e = newNotifyEnv(t)
	e.store.sweepErr = errors.New("db down")
	e.store.add(glovoconsent.NotifyApproved, glovoconsent.AccessApproved)
	e.n.Round(context.Background())
	if len(e.sent) != 1 {
		t.Fatalf("sent %d after a failed sweep", len(e.sent))
	}
	// A sweep that closed rows and then failed still counts them: the store
	// can return a count together with an error.
	e = newNotifyEnv(t)
	e.store.expired, e.store.sweepErr = 3, errors.New("prune failed")
	before = notifyCount("any", glovoconsent.NotifyOutcomeExpired)
	failed := notifyCount("any", glovoNotifySweepError)
	e.n.Round(context.Background())
	if notifyCount("any", glovoconsent.NotifyOutcomeExpired) != before+3 || notifyCount("any", glovoNotifySweepError) != failed+1 {
		t.Fatal("rows closed by a sweep that then failed were not counted, or the failure was not")
	}
	if !strings.Contains(e.logs.String(), "gave up on undelivered notifications") {
		t.Fatal("the loss was not logged")
	}
}

func TestGlovoNotify_Ready(t *testing.T) {
	e := newNotifyEnv(t)
	if !e.n.Ready() {
		t.Fatal("complete notifier not ready")
	}
	var none *GlovoAccessNotifier
	if none.Ready() {
		t.Fatal("nil notifier ready")
	}
	for _, base := range []string{"", "http://api.example", "https://", "https://api.example/x", "https://api.example?x=1", "https://api.example#f", "api.example"} {
		n := *e.n
		n.PageBaseURL = base
		if n.Ready() {
			t.Fatalf("base %q accepted", base)
		}
	}
	for _, strip := range []func(*GlovoAccessNotifier){
		func(n *GlovoAccessNotifier) { n.Store = nil }, func(n *GlovoAccessNotifier) { n.Identity = nil },
		func(n *GlovoAccessNotifier) { n.Bridge = nil }, func(n *GlovoAccessNotifier) { n.PageBaseURL = "" },
	} {
		n := *e.n
		strip(&n)
		if n.Ready() {
			t.Fatal("incomplete notifier ready")
		}
	}
	if got := GlovoAccessDecideLink("https://api.example/", strings.Repeat("a", 43)); !notifyLink.MatchString(got) {
		t.Fatalf("link %q", got)
	}
}
