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
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
)

// Glovo access notifications (mctl-glovo#82 stage C, design 5.4 and 5.5).
//
// The access store appends an outbox row with every change worth telling
// (glovoconsent/notify.go). This loop delivers them through the mctl-web
// Worker's private bridge, the signup decision email's contract: lease a row,
// POST it with a stable idempotency key, store the receipt.
//
//   - owner_card: the Worker sends the owner a Telegram message with a link
//     to the decision page. The link carries a one-time token minted for this
//     attempt. The message decides nothing.
//   - approved, rejected, lapsed: the Worker emails the requester the fixed
//     text of that kind. The address is read from the IdP for this attempt
//     and is neither stored nor logged here.
//
// Delivery is beside the decision, never part of it: the decision was
// committed before the row could be leased, and nothing here writes the
// access row. A failed attempt is retried when its lease runs out, for
// glovoconsent.NotifyWindow; after that the row is closed as expired.
//
// Dark by default: cmd/api builds a notifier only when
// GLOVO_ACCESS_NOTIFY_ENABLED is true and every dependency is there, and
// gives it a recipient lookup only when GLOVO_ACCESS_EMAIL_ENABLED is true
// as well. Without the lookup only the owner card is delivered.

// Notification outcomes, the metric's label and the code stored on an
// abandoned row. A fixed set: no free text.
const (
	glovoNotifySent         = "sent"
	glovoNotifySuperseded   = "superseded"
	glovoNotifyNoRecipient  = "no_recipient"
	glovoNotifyLeaseError   = "lease_error"
	glovoNotifyStateError   = "state_error"
	glovoNotifyTokenError   = "token_error"
	glovoNotifyIdentityErr  = "identity_error"
	glovoNotifyRecipientErr = "recipient_error"
	glovoNotifyEncodeError  = "encode_error"
	glovoNotifyBridgeError  = "bridge_error"
	glovoNotifyReceiptError = "receipt_error"
	glovoNotifyAckError     = "ack_error"
	glovoNotifySweepError   = "sweep_error"
	// glovoNotifyEmailOff closes an email row found while the emails are
	// switched off: it is not sent, and no address is looked up for it.
	glovoNotifyEmailOff = "email_off"
)

var glovoAccessNotifications = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_glovo_access_notifications_total",
	Help: "Glovo access notification delivery attempts, by kind and outcome.",
}, []string{"kind", "outcome"})

func init() { prometheus.MustRegister(glovoAccessNotifications) }

// ErrGlovoNoRecipient is the documented absence of an address to mail: the
// principal is not a customer, or the IdP has no verified email for it. A
// failed lookup is any other error and is retried.
var ErrGlovoNoRecipient = errors.New("glovo access: no recipient address")

// GlovoAccessNotifyStore is the outbox side of the access store.
type GlovoAccessNotifyStore interface {
	LeaseNotification(ctx context.Context, lease string) (glovoconsent.Notification, bool, error)
	AckNotification(ctx context.Context, id int64, lease, deliveryID string) error
	AbandonNotification(ctx context.Context, id int64, lease, outcome string) error
	EnqueueLapsed(ctx context.Context) (int, error)
	ExpireNotifications(ctx context.Context) (int, error)
	MintDecideToken(ctx context.Context, principalID string, requestedAt time.Time) (string, error)
	GetAccess(ctx context.Context, principalID string) (glovoconsent.Access, error)
}

// GlovoAccessNotifier delivers the access outbox.
type GlovoAccessNotifier struct {
	Store GlovoAccessNotifyStore
	// Identity reads the facts the owner card's masked label is built from.
	Identity glovoconsent.IdentitySource
	// Recipient resolves the requester's email for one attempt.
	// ErrGlovoNoRecipient means there is none; any other error is retried.
	// Nil means the emails are switched off: only the owner card is
	// delivered, and no address is ever asked for.
	Recipient func(ctx context.Context, principalID string) (string, error)
	// Bridge posts one notification to the Worker and returns its receipt.
	Bridge func(ctx context.Context, body []byte) ([]byte, error)
	// PageBaseURL is the origin serving the decision page (https, no path).
	PageBaseURL string
	// Interval between rounds; a minute when zero.
	Interval time.Duration
}

// Ready reports whether every dependency of the owner card is set. The
// emails need Recipient on top of it.
func (n *GlovoAccessNotifier) Ready() bool {
	if n == nil || n.Store == nil || n.Identity == nil || n.Bridge == nil {
		return false
	}
	u, err := url.Parse(n.PageBaseURL)
	return err == nil && u.Scheme == "https" && u.Host != "" && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}

// GlovoAccessDecideLink is the link an owner card carries: the decide link
// with a one-time token. It names no principal.
func GlovoAccessDecideLink(base, token string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	u.Path = glovoAccessLinkPath
	u.RawQuery = url.Values{glovoAccessTokenParam: {token}}.Encode()
	return u.String()
}

// glovoAccessNotifyCard is what the owner card shows. No principal id, name
// or address: the masked label only (design 5.4).
type glovoAccessNotifyCard struct {
	Identity    string `json:"identity,omitempty"`
	RequestedAt string `json:"requested_at"`
	ExpiresAt   string `json:"expires_at"`
	DecideURL   string `json:"decide_url"`
}

// glovoAccessNotifyBody is the bridge request.
type glovoAccessNotifyBody struct {
	DeliveryKey string                 `json:"delivery_key"`
	Kind        string                 `json:"kind"`
	To          string                 `json:"to,omitempty"`
	Card        *glovoAccessNotifyCard `json:"card,omitempty"`
}

// Run delivers until ctx ends.
func (n *GlovoAccessNotifier) Run(ctx context.Context) {
	interval := n.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		n.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// glovoNotifyBatch bounds one round.
const glovoNotifyBatch = 10

// Round sweeps and then delivers up to glovoNotifyBatch rows.
func (n *GlovoAccessNotifier) Round(ctx context.Context) {
	if _, err := n.Store.EnqueueLapsed(ctx); err != nil {
		n.failed(string(glovoconsent.NotifyLapsed), glovoNotifySweepError, 0, err)
	}
	expired, err := n.Store.ExpireNotifications(ctx)
	if err != nil {
		n.failed("any", glovoNotifySweepError, 0, err)
	}
	if expired > 0 {
		glovoAccessNotifications.WithLabelValues("any", glovoconsent.NotifyOutcomeExpired).Add(float64(expired))
		slog.Error("glovo access notification: gave up on undelivered notifications", "count", expired)
	}
	for i := 0; i < glovoNotifyBatch; i++ {
		lease := uuid.NewString()
		row, found, err := n.Store.LeaseNotification(ctx, lease)
		if err != nil {
			n.failed("any", glovoNotifyLeaseError, 0, err)
			return
		}
		if !found {
			return
		}
		n.deliver(ctx, row, lease)
	}
}

// failed counts and logs one failed step. The log carries the row id and a
// fixed outcome, never a principal id or an address.
func (n *GlovoAccessNotifier) failed(kind, outcome string, id int64, err error) {
	glovoAccessNotifications.WithLabelValues(kind, outcome).Inc()
	slog.Warn("glovo access notification: attempt failed", "kind", kind, "outcome", outcome, "notification_id", id, "error", err)
}

// abandon closes a row that will never be delivered.
func (n *GlovoAccessNotifier) abandon(ctx context.Context, row glovoconsent.Notification, lease, outcome string) {
	kind := string(row.Kind)
	if err := n.Store.AbandonNotification(ctx, row.ID, lease, outcome); err != nil {
		n.failed(kind, glovoNotifyAckError, row.ID, err)
		return
	}
	glovoAccessNotifications.WithLabelValues(kind, outcome).Inc()
	slog.Info("glovo access notification: not delivered", "kind", kind, "outcome", outcome, "notification_id", row.ID)
}

// current reports whether the row still describes the principal's access:
// the same request, in the state the notification tells. A notification
// overtaken by a later change is dropped, not sent late.
func glovoNotifyCurrent(row glovoconsent.Notification, a glovoconsent.Access) bool {
	if a.PrincipalID != row.PrincipalID || !a.RequestedAt.Equal(row.RequestedAt) {
		return false
	}
	switch row.Kind {
	case glovoconsent.NotifyOwnerCard:
		return a.Status == glovoconsent.AccessPending
	case glovoconsent.NotifyApproved:
		return a.Status == glovoconsent.AccessApproved
	case glovoconsent.NotifyRejected:
		return a.Status == glovoconsent.AccessRejected && !withdrawnByRequester(a)
	case glovoconsent.NotifyLapsed:
		// GetAccess reports a lapsed pending request as none, with the
		// row's times.
		return a.Status == glovoconsent.AccessNone
	}
	return false
}

func (n *GlovoAccessNotifier) deliver(ctx context.Context, row glovoconsent.Notification, lease string) {
	kind := string(row.Kind)
	if !auth.ValidPrincipalID(row.PrincipalID) || !row.Kind.Valid() {
		n.failed(kind, glovoNotifyStateError, row.ID, errors.New("unusable notification row"))
		return
	}
	a, err := n.Store.GetAccess(ctx, row.PrincipalID)
	if err != nil || !validAccessOf(a, row.PrincipalID) {
		n.failed(kind, glovoNotifyStateError, row.ID, err)
		return
	}
	if !glovoNotifyCurrent(row, a) {
		n.abandon(ctx, row, lease, glovoNotifySuperseded)
		return
	}
	body := glovoAccessNotifyBody{DeliveryKey: row.DeliveryKey(), Kind: kind}
	if row.Kind == glovoconsent.NotifyOwnerCard {
		card, outcome, err := n.card(ctx, row)
		switch {
		case errors.Is(err, glovoconsent.ErrAccessNotPending):
			n.abandon(ctx, row, lease, glovoNotifySuperseded)
			return
		case err != nil:
			n.failed(kind, outcome, row.ID, err)
			return
		}
		body.Card = card
	} else {
		if n.Recipient == nil {
			n.abandon(ctx, row, lease, glovoNotifyEmailOff)
			return
		}
		to, err := n.Recipient(ctx, row.PrincipalID)
		switch {
		case errors.Is(err, ErrGlovoNoRecipient):
			n.abandon(ctx, row, lease, glovoNotifyNoRecipient)
			return
		case err != nil || to == "":
			// The error may quote the IdP's answer: it is not logged.
			n.failed(kind, glovoNotifyRecipientErr, row.ID, errors.New("recipient lookup failed"))
			return
		}
		body.To = to
	}
	raw, err := json.Marshal(body)
	if err != nil {
		n.failed(kind, glovoNotifyEncodeError, row.ID, err)
		return
	}
	data, err := n.Bridge(ctx, raw)
	if err != nil {
		n.failed(kind, glovoNotifyBridgeError, row.ID, err)
		return
	}
	var receipt struct {
		DeliveryKey string `json:"delivery_key"`
		DeliveryID  string `json:"delivery_id"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil || receipt.DeliveryKey != body.DeliveryKey ||
		receipt.DeliveryID == "" || len(receipt.DeliveryID) > 200 {
		n.failed(kind, glovoNotifyReceiptError, row.ID, errors.New("receipt does not match the notification"))
		return
	}
	if err := n.Store.AckNotification(ctx, row.ID, lease, receipt.DeliveryID); err != nil {
		n.failed(kind, glovoNotifyAckError, row.ID, err)
		return
	}
	glovoAccessNotifications.WithLabelValues(kind, glovoNotifySent).Inc()
	slog.Info("glovo access notification: delivered", "kind", kind, "notification_id", row.ID, "attempts", row.Attempts)
}

// card builds the owner card of a pending request, minting the link's token
// for this attempt. The label is left out when none can be built; a failed
// read of the facts is an error.
func (n *GlovoAccessNotifier) card(ctx context.Context, row glovoconsent.Notification) (*glovoAccessNotifyCard, string, error) {
	label := ""
	facts, err := n.Identity.IdentityFacts(ctx, row.PrincipalID)
	if err != nil {
		return nil, glovoNotifyIdentityErr, errors.New("identity facts unreadable")
	}
	if l, err := glovoconsent.MaskIdentity(facts); err == nil {
		label = l
	} else if !errors.Is(err, glovoconsent.ErrNoIdentityLabel) {
		return nil, glovoNotifyIdentityErr, err
	}
	token, err := n.Store.MintDecideToken(ctx, row.PrincipalID, row.RequestedAt)
	if err != nil {
		return nil, glovoNotifyTokenError, err
	}
	link := GlovoAccessDecideLink(n.PageBaseURL, token)
	if link == "" || glovoconsent.HashDecideToken(token) == "" {
		return nil, glovoNotifyTokenError, errors.New("decide link could not be built")
	}
	return &glovoAccessNotifyCard{
		Identity:    label,
		RequestedAt: row.RequestedAt.UTC().Format(time.RFC3339),
		ExpiresAt:   row.ExpiresAt.UTC().Format(time.RFC3339),
		DecideURL:   link,
	}, "", nil
}
