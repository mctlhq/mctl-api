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
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/glovo"
	"github.com/mctlhq/mctl-api/internal/glovoconsent"
	"github.com/mctlhq/mctl-api/internal/operations"
)

// Consent to link a real Glovo account (mctl-glovo epic #11, slice C2-1c).
//
// Two surfaces, both dark until GlovoConsentRoutes is mounted:
//
//   - GET/PUT/DELETE /api/v1/glovo/link-consent: the human reads, records and
//     withdraws their own consent. Only a human acting directly, with a
//     resolved principal, reaches them (glovoConsentHuman). The principal is
//     the caller's own; no route names another. Recording claims a slot
//     under the capacity cap (GLOVO_C2_CAPACITY), and the active consent is
//     the glovo:c2 grant; withdrawing frees the slot.
//   - GET /api/v1/assistants/glovo-consent/v1/principals/{principal_id}: the
//     mctl-glovo service reads a principal's active consent version. Only the
//     one configured federated service identity reaches it, and it reaches
//     nothing else (glovoConsentGate).
const (
	glovoConsentMount     = "/assistants/glovo-consent/v1"
	glovoConsentPrefix    = "/api/v1" + glovoConsentMount + "/"
	glovoConsentHumanPath = "/glovo/link-consent"

	// DefaultGlovoConsentReadsPerPrincipalPerMinute bounds the service's
	// reads for one principal. The service as a whole stays under the global
	// per-caller limiter.
	DefaultGlovoConsentReadsPerPrincipalPerMinute = 60
)

// Consent route error codes.
const (
	gcCodeHumanOnly = "glovo_consent_human_required"
	// gcCodeCapacityReached is the fixed, distinct refusal at the cap,
	// which the link page shows as a waitlist message.
	gcCodeCapacityReached  = "capacity_reached"
	gcCodeUnavailable      = "glovo_consent_unavailable"
	gcCodeInvalidPrincipal = "glovo_consent_invalid_principal"
	gcCodeRateLimited      = "glovo_consent_rate_limited"
)

// Consent states in a response.
const (
	gcStateActive = "active"
	gcStateNone   = "none"
)

var glovoConsentEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_glovo_link_consent_events_total",
	Help: "Glovo link consent route outcomes, by route and outcome.",
}, []string{"route", "outcome"})

func init() { prometheus.MustRegister(glovoConsentEvents) }

// GlovoConsentRoutes configures the consent routes. cmd/api sets it only
// when GLOVO_CONSENT_ENABLED is true and every dependency is there.
type GlovoConsentRoutes struct {
	Enabled bool
	Store   glovoconsent.Store
	// Capacity caps the active consents (slots). Zero or less is closed:
	// no new consent, while reads and withdrawals still work.
	Capacity int
	// ServiceProvider and ServiceSubject name the one federated service
	// identity (an MCTL_OIDC_PROVIDERS entry of kind service, and its
	// subject) that may read consent records: mctl-glovo.
	ServiceProvider, ServiceSubject string
	// ReadsPerPrincipalPerMinute; zero keeps the default.
	ReadsPerPrincipalPerMinute int
	// Identity supplies the facts for the masked identity the link preview
	// shows (GET ...?include=masked_identity). Nil: that request is 503, a
	// label that cannot be built is never omitted silently.
	Identity glovoconsent.IdentitySource

	once     sync.Once
	perPrinc *httprate.RateLimiter
}

func (g *GlovoConsentRoutes) mounted() bool {
	return g != nil && g.Enabled && !glovo.IsNil(g.Store) &&
		g.ServiceProvider != "" && g.ServiceSubject != "" && !auth.IsReservedProviderName(g.ServiceProvider)
}

func (g *GlovoConsentRoutes) limiter() *httprate.RateLimiter {
	g.once.Do(func() {
		n := g.ReadsPerPrincipalPerMinute
		if n <= 0 {
			n = DefaultGlovoConsentReadsPerPrincipalPerMinute
		}
		g.perPrinc = httprate.NewRateLimiter(n, time.Minute)
	})
	return g.perPrinc
}

// isService reports whether u is the configured consent reader: a verified
// federated identity of kind service with exactly the configured provider
// and subject, and none of the built-in principal types.
func (g *GlovoConsentRoutes) isService(u *auth.User) bool {
	if !g.mounted() || u == nil {
		return false
	}
	id, ok := u.Identity()
	return ok && id.Kind == auth.KindService && id.Customer == nil &&
		id.Provider == g.ServiceProvider && id.Subject == g.ServiceSubject &&
		!u.IsOrchestratorDevLoop() && !u.IsGlovoFacade() && !u.IsService() && !u.IsAgent() && !u.IsCI() &&
		!u.IsGlovoAudience() && !u.IsSupportAudience()
}

// glovoConsentGate confines the consent read surface in both directions: the
// consent reader reaches only its prefix (every other path, /mcp included,
// is 401), and nobody else reaches the prefix (401). Unmounted, it does
// nothing and the prefix is the router's 404.
func (h *Handlers) glovoConsentGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := h.opts.GlovoConsent
		if !g.mounted() {
			next.ServeHTTP(w, r)
			return
		}
		user := auth.UserFromContext(r.Context())
		onPrefix := strings.HasPrefix(r.URL.Path, glovoConsentPrefix)
		isSvc := g.isService(user)
		switch {
		case isSvc && !onPrefix:
			glovoRouteRefusals.WithLabelValues("consent_gate", "service_off_prefix").Inc()
			glovo.WriteUnauthenticated(w, "")
			return
		case !isSvc && onPrefix:
			glovoRouteRefusals.WithLabelValues("consent_gate", "not_service_identity").Inc()
			glovo.WriteUnauthenticated(w, "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// glovoConsentHuman is the caller a consent may be recorded or withdrawn for:
// a human acting directly with a resolved principal. Refused: every service,
// agent and CI identity, a delegated agent request (its user is the human,
// but an agent acts), a surface and a request a surface relays, a Glovo or
// support audience token, and the dev caller. unresolved is true when the
// caller is a human whose principal could not be resolved.
func glovoConsentHuman(u *auth.User) (pid string, ok, unresolved bool) {
	if u == nil {
		return "", false, false
	}
	id, has := u.Identity()
	if !has || id.Kind != auth.KindHuman || id.Provider == auth.ProviderDev {
		return "", false, false
	}
	_, relayed := u.RelaySurface()
	_, surface := u.Surface()
	_, delegated := u.DelegatingAgent()
	if relayed || surface || delegated || u.ActingPrincipal() != "" || u.IsAgent() || u.IsService() || u.IsCI() ||
		u.IsGlovoAudience() || u.IsSupportAudience() || u.IsGlovoFacade() || u.IsGlovoWorker() || u.IsGlovoControlWorker() ||
		u.IsOrchestratorDevLoop() {
		return "", false, false
	}
	pid = u.PrincipalID()
	if pid == "" && u.PrincipalUnresolved() {
		return "", false, true
	}
	if !auth.ValidPrincipalID(pid) {
		return "", false, false
	}
	return pid, true, false
}

// glovoConsentCaller answers every refusal of the human routes and returns
// the caller's principal. op is the audit operation of a write route ("" for
// the read): a refused write is audited with its refusal code, under the
// caller's own principal when it resolved and with no principal otherwise.
func (h *Handlers) glovoConsentCaller(w http.ResponseWriter, r *http.Request, route, op string) (*auth.User, string, bool) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, "", false
	}
	pid, ok, unresolved := glovoConsentHuman(user)
	switch {
	case unresolved:
		glovoConsentEvents.WithLabelValues(route, "principal_unresolved").Inc()
		if op != "" {
			h.auditGlovoConsent(r, user, op, "refused", "", nil, gcCodeUnavailable)
		}
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the caller's principal could not be resolved; try again", nil)
		return nil, "", false
	case !ok:
		glovoConsentEvents.WithLabelValues(route, "not_human").Inc()
		if op != "" {
			h.auditGlovoConsent(r, user, op, "refused", "", nil, gcCodeHumanOnly)
		}
		writeErrorCode(w, http.StatusForbidden, gcCodeHumanOnly, "only a human acting directly, with a resolved principal, can manage their Glovo link consent", nil)
		return nil, "", false
	}
	return user, pid, true
}

// glovoConsentView is the human routes' answer.
type glovoConsentView struct {
	State string `json:"state"`
	// CurrentVersion is the version a consent recorded now would carry.
	CurrentVersion string               `json:"current_consent_version"`
	Consent        *glovoconsent.Record `json:"consent,omitempty"`
}

func (h *Handlers) auditGlovoConsent(r *http.Request, user *auth.User, op, status, pid string, rec *glovoconsent.Record, refusal string) {
	params := map[string]string{"principal": pid, "consent_version": glovoconsent.Version}
	if rec != nil {
		params["consent_id"] = rec.ID
		params["consent_version"] = rec.Version
	}
	h.logAudit(r, audit.Entry{
		UserID:      user.ID,
		Operation:   op,
		Parameters:  params,
		Status:      status,
		RiskLevel:   string(operations.RiskMedium),
		RefusalCode: refusal,
	})
}

// activeConsentOf reports whether a store answer describes an active
// consent of pid. Every reader applies it: an answer about another
// principal, a revoked row or a row with no version is unreadable, never a
// consent, so a faulty Store cannot expose another principal's record.
func activeConsentOf(rec glovoconsent.Record, pid string) bool {
	return rec.PrincipalID == pid && rec.Version != "" && rec.Active()
}

// GetGlovoLinkConsent handles GET /api/v1/glovo/link-consent: the caller's
// own active consent, or state none.
func (h *Handlers) GetGlovoLinkConsent(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.glovoConsentCaller(w, r, "human_read", "")
	if !ok {
		return
	}
	rec, err := h.opts.GlovoConsent.Store.Active(r.Context(), pid)
	switch {
	case errors.Is(err, glovoconsent.ErrNoConsent):
		writeJSON(w, http.StatusOK, glovoConsentView{State: gcStateNone, CurrentVersion: glovoconsent.Version})
	case err != nil:
		glovoConsentEvents.WithLabelValues("human_read", "store_error").Inc()
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent record could not be read", nil)
	case !activeConsentOf(rec, pid):
		glovoConsentEvents.WithLabelValues("human_read", "store_inconsistent").Inc()
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent record could not be read", nil)
	default:
		writeJSON(w, http.StatusOK, glovoConsentView{State: gcStateActive, CurrentVersion: glovoconsent.Version, Consent: &rec})
	}
}

// PutGlovoLinkConsent handles PUT /api/v1/glovo/link-consent: the caller
// records consent to the current text. The version is fixed server-side; the
// request body is never read. A new consent claims a slot under the
// capacity cap, atomically in the store; at the cap the answer is 409
// capacity_reached. Re-recording takes no second slot.
func (h *Handlers) PutGlovoLinkConsent(w http.ResponseWriter, r *http.Request) {
	const op = "glovo.link_consent.record"
	user, pid, ok := h.glovoConsentCaller(w, r, "human_record", op)
	if !ok {
		return
	}
	rec, created, err := h.opts.GlovoConsent.Store.Record(r.Context(), pid, principalOf(user), h.opts.GlovoConsent.Capacity)
	if errors.Is(err, glovoconsent.ErrCapacityReached) {
		glovoConsentEvents.WithLabelValues("human_record", "capacity_reached").Inc()
		h.auditGlovoConsent(r, user, op, "refused", pid, nil, gcCodeCapacityReached)
		writeErrorCode(w, http.StatusConflict, gcCodeCapacityReached, "Glovo account linking is full right now; you are not linked and can try again later", nil)
		return
	}
	if err != nil {
		glovoConsentEvents.WithLabelValues("human_record", "store_error").Inc()
		h.auditGlovoConsent(r, user, op, "failed", pid, nil, gcCodeUnavailable)
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent could not be recorded", nil)
		return
	}
	if !activeConsentOf(rec, pid) {
		glovoConsentEvents.WithLabelValues("human_record", "store_inconsistent").Inc()
		h.auditGlovoConsent(r, user, op, "failed", pid, nil, gcCodeUnavailable)
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent could not be recorded", nil)
		return
	}
	status, outcome := http.StatusOK, "unchanged"
	if created {
		status, outcome = http.StatusCreated, "recorded"
	}
	glovoConsentEvents.WithLabelValues("human_record", outcome).Inc()
	h.auditGlovoConsent(r, user, op, outcome, pid, &rec, "")
	writeJSON(w, status, glovoConsentView{State: gcStateActive, CurrentVersion: glovoconsent.Version, Consent: &rec})
}

// DeleteGlovoLinkConsent handles DELETE /api/v1/glovo/link-consent: the
// caller withdraws their consent, which frees its slot. Idempotent:
// with no active consent the answer is state none.
func (h *Handlers) DeleteGlovoLinkConsent(w http.ResponseWriter, r *http.Request) {
	const op = "glovo.link_consent.revoke"
	user, pid, ok := h.glovoConsentCaller(w, r, "human_revoke", op)
	if !ok {
		return
	}
	rec, err := h.opts.GlovoConsent.Store.Revoke(r.Context(), pid, principalOf(user))
	switch {
	case errors.Is(err, glovoconsent.ErrNoConsent):
		glovoConsentEvents.WithLabelValues("human_revoke", "none").Inc()
		writeJSON(w, http.StatusOK, glovoConsentView{State: gcStateNone, CurrentVersion: glovoconsent.Version})
	case err != nil:
		glovoConsentEvents.WithLabelValues("human_revoke", "store_error").Inc()
		h.auditGlovoConsent(r, user, op, "failed", pid, nil, gcCodeUnavailable)
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent could not be withdrawn", nil)
	default:
		glovoConsentEvents.WithLabelValues("human_revoke", "revoked").Inc()
		h.auditGlovoConsent(r, user, op, "revoked", pid, &rec, "")
		writeJSON(w, http.StatusOK, glovoConsentView{State: gcStateNone, CurrentVersion: glovoconsent.Version, Consent: &rec})
	}
}

// GlovoConsentReadResponse is the service read: the principal's active
// consent version, or state none. A read that failed is never this body.
type GlovoConsentReadResponse struct {
	PrincipalID    string     `json:"principal_id"`
	State          string     `json:"state"`
	ConsentVersion string     `json:"consent_version,omitempty"`
	RecordedAt     *time.Time `json:"recorded_at,omitempty"`
	// MaskedIdentity is present only when the caller asked for it
	// (include=masked_identity) and the state is active: a provider prefix,
	// the first character of the readable name and "***".
	MaskedIdentity string `json:"masked_identity,omitempty"`
}

// gcIncludeMaskedIdentity is the opt-in query value: the per-call admission
// read of mctl-glovo stays as cheap as it was, and only the link preview asks
// for the label.
const gcIncludeMaskedIdentity = "masked_identity"

// ReadGlovoLinkConsent handles GET
// /api/v1/assistants/glovo-consent/v1/principals/{principal_id}. Only the
// configured consent reader reaches it (glovoConsentGate). Only the store's
// documented absence is state none; every other failure is 503.
func (h *Handlers) ReadGlovoLinkConsent(w http.ResponseWriter, r *http.Request) {
	g := h.opts.GlovoConsent
	if !g.isService(auth.UserFromContext(r.Context())) {
		// The gate already refuses this; kept so the handler is safe alone.
		glovo.WriteUnauthenticated(w, "")
		return
	}
	pid := chi.URLParam(r, "principal_id")
	if !auth.ValidPrincipalID(pid) {
		glovoConsentEvents.WithLabelValues("service_read", "invalid_principal").Inc()
		writeErrorCode(w, http.StatusBadRequest, gcCodeInvalidPrincipal, "principal_id must be a prn_ principal id", nil)
		return
	}
	if g.limiter().OnLimit(w, r, "glovo-consent-read:"+pid) {
		glovoConsentEvents.WithLabelValues("service_read", "rate_limited").Inc()
		writeErrorCode(w, http.StatusTooManyRequests, gcCodeRateLimited, "too many consent reads for this principal", nil)
		return
	}
	rec, err := g.Store.Active(r.Context(), pid)
	switch {
	case errors.Is(err, glovoconsent.ErrNoConsent):
		glovoConsentEvents.WithLabelValues("service_read", "none").Inc()
		writeJSON(w, http.StatusOK, GlovoConsentReadResponse{PrincipalID: pid, State: gcStateNone})
	case err != nil:
		glovoConsentEvents.WithLabelValues("service_read", "store_error").Inc()
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent record could not be read", nil)
	case !activeConsentOf(rec, pid):
		// A store answer that does not describe an active consent of this
		// principal is unreadable, not a consent.
		glovoConsentEvents.WithLabelValues("service_read", "store_inconsistent").Inc()
		writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the consent record could not be read", nil)
	default:
		at := rec.RecordedAt.UTC()
		out := GlovoConsentReadResponse{PrincipalID: pid, State: gcStateActive, ConsentVersion: rec.Version, RecordedAt: &at}
		if r.URL.Query().Get("include") == gcIncludeMaskedIdentity {
			label, err := h.glovoMaskedIdentity(r, g, pid)
			if err != nil {
				glovoConsentEvents.WithLabelValues("service_read", "identity_unavailable").Inc()
				writeErrorCode(w, http.StatusServiceUnavailable, gcCodeUnavailable, "the identity label could not be built", nil)
				return
			}
			out.MaskedIdentity = label
		}
		glovoConsentEvents.WithLabelValues("service_read", "active").Inc()
		writeJSON(w, http.StatusOK, out)
	}
}

// glovoMaskedIdentity builds the label from live identity facts. Any failure
// (no source, a failed read, nothing readable) is an error: the label is
// never empty, never raw.
func (h *Handlers) glovoMaskedIdentity(r *http.Request, g *GlovoConsentRoutes, pid string) (string, error) {
	if glovo.IsNil(g.Identity) {
		return "", glovoconsent.ErrNoIdentityLabel
	}
	facts, err := g.Identity.IdentityFacts(r.Context(), pid)
	if err != nil {
		return "", err
	}
	return glovoconsent.MaskIdentity(facts)
}
