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

package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"
)

// ErrRefreshRejected is what a Refresher returns when the provider
// definitively refused the refresh token (revoked, expired, already rotated).
// It is permanent: the manager records relogin_required.
var ErrRefreshRejected = errors.New("glovo session: provider rejected the refresh token")

// ErrRefreshNotSent is what a Refresher wraps around a failure that happened
// before any request reached the provider (DNS, connect, local validation).
// It proves nothing was rotated. Any other non-rejection error (timeout,
// reset, 5xx, malformed body) is an unknown outcome: the request may have
// rotated the token.
var ErrRefreshNotSent = errors.New("glovo session: refresh request not sent")

// Refresher exchanges a refresh token for a new pair. The live adapter is
// the only implementation and is out of this slice; it must map a definitive
// 400/401/403 from the refresh endpoint to ErrRefreshRejected and must not
// retry internally (one request per call, or the single-flight guarantee
// means nothing).
type Refresher interface {
	Refresh(ctx context.Context, refresh Secret) (Tokens, error)
}

// Event is an audit record. It carries identifiers and a code only: no
// token, no provider text, no profile data. PrincipalID is an opaque id.
type Event struct {
	Kind         string // loaded, refreshed, refresh_rejected, refresh_unknown, relogin_required, revoked, rotated_not_persisted, token_served
	TenantID     string
	PrincipalID  string
	ConnectionID string
	Generation   int64
	Code         string
	At           time.Time
}

// Auditor receives events. It must not block the caller for long.
type Auditor interface{ Record(Event) }

// Config of a Manager. Enabled is false by default: a zero Config serves
// nothing and every call returns ErrDisabled.
type Config struct {
	Store     Store
	Refresher Refresher
	Auditor   Auditor
	// Enabled is the default-off switch.
	Enabled bool
	// Kill is the runtime kill switch, read on every call. Returning true
	// makes every call return ErrDisabled without touching the store or the
	// provider.
	Kill func() bool
	// HolderID names this replica's refresh lease. It must be unique per
	// process (pod name plus a random suffix).
	HolderID string
	// Skew: an access token that expires within Skew is refreshed.
	Skew time.Duration
	// LeaseTTL must exceed RefreshTimeout plus the persist retries, so a live
	// holder is never taken over.
	LeaseTTL       time.Duration
	RefreshTimeout time.Duration
	// WaitMax bounds how long a replica waits for another replica's refresh.
	WaitMax      time.Duration
	PollInterval time.Duration
	// PersistAttempts and PersistBackoff bound the retries that keep a
	// rotated token from being lost to a transient store error.
	PersistAttempts int
	PersistBackoff  time.Duration
	PersistTimeout  time.Duration
	Now             func() time.Time
}

func (c *Config) defaults() {
	if c.Skew == 0 {
		c.Skew = 60 * time.Second
	}
	if c.RefreshTimeout == 0 {
		c.RefreshTimeout = 10 * time.Second
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = 45 * time.Second
	}
	if c.WaitMax == 0 {
		c.WaitMax = 15 * time.Second
	}
	if c.PollInterval == 0 {
		c.PollInterval = 100 * time.Millisecond
	}
	if c.PersistAttempts == 0 {
		c.PersistAttempts = 5
	}
	if c.PersistBackoff == 0 {
		c.PersistBackoff = 200 * time.Millisecond
	}
	if c.PersistTimeout == 0 {
		c.PersistTimeout = 20 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Auditor == nil {
		c.Auditor = discard{}
	}
}

type discard struct{}

func (discard) Record(Event) {}

// Manager hands out access tokens and is the only code that refreshes. Per
// connection, at most one refresh request is in flight across all replicas:
// a process-local single-flight collapses concurrent callers in one pod, and
// the store's lease serializes pods. Every committed refresh is a
// compare-and-swap on the generation, so a rotated token is either persisted
// as the next generation or the caller is told it was not.
type Manager struct {
	cfg Config
	sf  singleflight.Group
}

// NewManager returns a manager. With a nil Store or Refresher, or Enabled
// false, every call returns ErrDisabled.
func NewManager(cfg Config) *Manager {
	cfg.defaults()
	return &Manager{cfg: cfg}
}

// AccessToken is a usable access token and the generation it came from. The
// caller passes the generation back to Rejected when the provider answers
// 401/403 to it.
type AccessToken struct {
	Value      Secret
	Generation int64
	ExpiresAt  time.Time
}

func (m *Manager) off() error {
	if !m.cfg.Enabled || m.cfg.Store == nil || m.cfg.Refresher == nil || (m.cfg.Kill != nil && m.cfg.Kill()) {
		return ErrDisabled
	}
	return nil
}

func (m *Manager) fresh(t Tokens) bool {
	return t.Access != "" && t.AccessExpiresAt.After(m.cfg.Now().Add(m.cfg.Skew))
}

func (m *Manager) audit(kind string, k Key, gen int64, code string) {
	m.cfg.Auditor.Record(Event{Kind: kind, TenantID: k.TenantID, PrincipalID: k.PrincipalID,
		ConnectionID: k.ConnectionID, Generation: gen, Code: code, At: m.cfg.Now()})
}

// Load is the owner load: it stores a freshly captured session.
func (m *Manager) Load(ctx context.Context, key Key, t Tokens) (Status, error) {
	if err := m.off(); err != nil {
		return Status{}, err
	}
	if t.Refresh == "" || t.Access == "" {
		return Status{}, ErrInvalid
	}
	rec, err := m.cfg.Store.Put(ctx, key, t)
	if err != nil {
		return Status{}, err
	}
	m.audit("loaded", key, rec.Generation, "")
	return m.cfg.Store.Status(ctx, key)
}

// Revoke is the kill switch for one session: it wipes the tokens.
func (m *Manager) Revoke(ctx context.Context, key Key) error {
	if m.cfg.Store == nil {
		return ErrDisabled
	}
	if err := m.cfg.Store.Revoke(ctx, key); err != nil {
		return err
	}
	m.audit("revoked", key, 0, "")
	return nil
}

// Status is the secret-free state, including relogin_required and revoked as
// explicit data.
func (m *Manager) Status(ctx context.Context, key Key) (Status, error) {
	if err := m.off(); err != nil {
		return Status{}, err
	}
	return m.cfg.Store.Status(ctx, key)
}

// AccessToken returns a usable access token, refreshing at most once across
// all replicas when needed. A session that needs the owner returns
// ErrReloginRequired (wrapped in *ReloginError) or ErrRevoked, never an empty
// token.
func (m *Manager) AccessToken(ctx context.Context, key Key) (AccessToken, error) {
	if err := m.off(); err != nil {
		return AccessToken{}, err
	}
	rec, err := m.cfg.Store.Get(ctx, key)
	if err != nil {
		return AccessToken{}, err
	}
	if err := stateErr(rec); err != nil {
		return AccessToken{}, err
	}
	if m.fresh(rec.Tokens) {
		return tokenOf(rec), nil
	}
	return m.refresh(ctx, key, rec.Generation, false)
}

// Rejected reports that the provider answered 401/403 to the access token of
// usedGeneration. It forces at most one refresh per generation:
//   - a newer generation already exists: it is returned, nothing is refreshed;
//   - the rejected generation came from a refresh: refreshing again cannot
//     help, so the session becomes relogin_required (this is what bounds the
//     retry that upstream's recursion left unbounded);
//   - otherwise one refresh is performed.
func (m *Manager) Rejected(ctx context.Context, key Key, usedGeneration int64) (AccessToken, error) {
	if err := m.off(); err != nil {
		return AccessToken{}, err
	}
	rec, err := m.cfg.Store.Get(ctx, key)
	if err != nil {
		return AccessToken{}, err
	}
	if err := stateErr(rec); err != nil {
		return AccessToken{}, err
	}
	if rec.Generation > usedGeneration {
		if m.fresh(rec.Tokens) {
			return tokenOf(rec), nil
		}
		return m.refresh(ctx, key, rec.Generation, false)
	}
	if rec.FromRefresh {
		if err := m.cfg.Store.MarkRelogin(ctx, key, rec.Generation, ReasonAccessRejectedAfter); err != nil && !errors.Is(err, ErrStale) {
			return AccessToken{}, err
		}
		m.audit("relogin_required", key, rec.Generation, ReasonAccessRejectedAfter)
		return AccessToken{}, &ReloginError{Reason: ReasonAccessRejectedAfter}
	}
	return m.refresh(ctx, key, rec.Generation, true)
}

func stateErr(rec Record) error {
	switch rec.State {
	case StateActive:
		return nil
	case StateRevoked:
		return ErrRevoked
	default:
		return &ReloginError{Reason: rec.ReloginReason}
	}
}

func tokenOf(rec Record) AccessToken {
	return AccessToken{Value: rec.Tokens.Access, Generation: rec.Generation, ExpiresAt: rec.Tokens.AccessExpiresAt}
}

// refresh collapses concurrent callers of one connection in this process.
// seen is the generation the caller observed; force skips the freshness
// double-check (a rejected token is stale whatever its expiry says).
func (m *Manager) refresh(ctx context.Context, key Key, seen int64, force bool) (AccessToken, error) {
	sfKey := fmt.Sprintf("%s|%s|%s|%d|%t", key.TenantID, key.PrincipalID, key.ConnectionID, seen, force)
	// The shared call must not die with one caller's context: a rotated token
	// has to reach the store even if the caller that triggered the refresh
	// gave up. Each caller still stops waiting when its own ctx ends.
	ch := m.sf.DoChan(sfKey, func() (any, error) {
		return m.refreshOnce(context.WithoutCancel(ctx), key, seen, force)
	})
	select {
	case r := <-ch:
		if r.Err != nil {
			return AccessToken{}, r.Err
		}
		return r.Val.(AccessToken), nil
	case <-ctx.Done():
		return AccessToken{}, fmt.Errorf("%w: caller cancelled", ErrUnavailable)
	}
}

func (m *Manager) refreshOnce(ctx context.Context, key Key, seen int64, force bool) (AccessToken, error) {
	deadline := m.cfg.Now().Add(m.cfg.WaitMax)
	for {
		rec, err := m.cfg.Store.AcquireLease(ctx, key, m.cfg.HolderID, m.cfg.LeaseTTL)
		if errors.Is(err, ErrLeaseHeld) {
			// Another replica is refreshing. Wait for its result instead of
			// refreshing in parallel.
			if m.cfg.Now().After(deadline) {
				return AccessToken{}, fmt.Errorf("%w: refresh in progress elsewhere", ErrUnavailable)
			}
			time.Sleep(m.cfg.PollInterval)
			cur, gerr := m.cfg.Store.Get(ctx, key)
			if gerr != nil {
				return AccessToken{}, gerr
			}
			if serr := stateErr(cur); serr != nil {
				return AccessToken{}, serr
			}
			if cur.Generation > seen && m.fresh(cur.Tokens) {
				return tokenOf(cur), nil
			}
			continue
		}
		if err != nil {
			return AccessToken{}, err
		}
		if serr := stateErr(rec); serr != nil {
			return AccessToken{}, serr
		}
		return m.refreshHolding(ctx, key, rec, seen, force)
	}
}

// refreshHolding runs with the lease held.
func (m *Manager) refreshHolding(ctx context.Context, key Key, rec Record, seen int64, force bool) (AccessToken, error) {
	// Double-check under the lease: another replica may have refreshed
	// between our read and our acquire. The generation moving is the proof.
	if rec.Generation > seen && m.fresh(rec.Tokens) {
		_ = m.cfg.Store.Release(ctx, key, m.cfg.HolderID, true)
		return tokenOf(rec), nil
	}
	if !force && rec.Generation == seen && m.fresh(rec.Tokens) {
		_ = m.cfg.Store.Release(ctx, key, m.cfg.HolderID, true)
		return tokenOf(rec), nil
	}
	if rec.Tokens.Refresh == "" {
		_ = m.cfg.Store.MarkRelogin(ctx, key, rec.Generation, ReasonExpiredNoRefresh)
		m.audit("relogin_required", key, rec.Generation, ReasonExpiredNoRefresh)
		return AccessToken{}, &ReloginError{Reason: ReasonExpiredNoRefresh}
	}
	// A previous holder may have crashed after the provider rotated the
	// token. The intent flag was set when it took the lease and never cleared.
	unknownBefore := rec.RefreshIntent // AcquireLease returns the PRIOR intent

	rctx, cancel := context.WithTimeout(ctx, m.cfg.RefreshTimeout)
	defer cancel()
	nt, err := m.cfg.Refresher.Refresh(rctx, rec.Tokens.Refresh)
	switch {
	case errors.Is(err, ErrRefreshRejected):
		reason := ReasonRefreshRejected
		if unknownBefore {
			reason = ReasonRefreshOutcomeLost
		}
		if merr := m.cfg.Store.MarkRelogin(ctx, key, rec.Generation, reason); merr != nil && !errors.Is(merr, ErrStale) {
			return AccessToken{}, fmt.Errorf("%w: could not record relogin", ErrUnavailable)
		}
		m.audit("refresh_rejected", key, rec.Generation, reason)
		return AccessToken{}, &ReloginError{Reason: reason}
	case errors.Is(err, ErrRefreshNotSent):
		_ = m.cfg.Store.Release(ctx, key, m.cfg.HolderID, true)
		return AccessToken{}, fmt.Errorf("%w: refresh not sent", ErrUnavailable)
	case err != nil:
		// Unknown outcome: keep the intent so the next holder knows.
		_ = m.cfg.Store.Release(ctx, key, m.cfg.HolderID, false)
		m.audit("refresh_unknown", key, rec.Generation, "outcome_unknown")
		return AccessToken{}, fmt.Errorf("%w: refresh outcome unknown", ErrUnavailable)
	}
	if nt.Access == "" || nt.AccessExpiresAt.IsZero() {
		// A malformed response may still have rotated the token and we have
		// nothing to persist: unknown outcome, never an empty token.
		_ = m.cfg.Store.Release(ctx, key, m.cfg.HolderID, false)
		m.audit("refresh_unknown", key, rec.Generation, "malformed_response")
		return AccessToken{}, fmt.Errorf("%w: refresh response malformed", ErrUnavailable)
	}
	if nt.Refresh == "" {
		nt.Refresh = rec.Tokens.Refresh // the provider did not rotate it
	}
	committed, err := m.persist(ctx, key, rec.Generation, nt)
	if err != nil {
		m.audit("rotated_not_persisted", key, rec.Generation, "persist_failed")
		return AccessToken{}, err
	}
	m.audit("refreshed", key, committed.Generation, "")
	return tokenOf(committed), nil
}

// persist commits the rotated pair. It runs on a context that is not
// cancelled with the caller and retries transient store errors, because the
// new refresh token exists only in this process until the commit succeeds.
// ErrStale and ErrLeaseLost are not retried: a newer lineage won, and the
// rotated pair is discarded on purpose (the owner's later load, or another
// replica's commit, is authoritative).
func (m *Manager) persist(ctx context.Context, key Key, expected int64, nt Tokens) (Record, error) {
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.cfg.PersistTimeout)
	defer cancel()
	for i := 0; i < m.cfg.PersistAttempts; i++ {
		rec, err := m.cfg.Store.Commit(pctx, key, m.cfg.HolderID, expected, nt)
		if err == nil {
			return rec, nil
		}
		if errors.Is(err, ErrStale) || errors.Is(err, ErrLeaseLost) {
			return Record{}, err
		}
		select {
		case <-time.After(m.cfg.PersistBackoff):
		case <-pctx.Done():
			return Record{}, fmt.Errorf("%w: persist timed out", ErrUnavailable)
		}
	}
	return Record{}, fmt.Errorf("%w: persist failed", ErrUnavailable)
}
