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
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/auth/flowstore"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/workitems"
)

// Glovo basket approval page (mctl-api#1006). glovo_request_approval freezes
// a synthetic basket revision and opens an owner-bound aar_; the MCP client
// shows its owner a link to /glovo/basket/approvals/{aar_id}. The link
// carries no secret and grants nothing. The page asks the person to sign in
// to ZITADEL in this browser, fresh (prompt=login, max_age=0, PKCE S256, a
// nonce), resolves them exactly as a bearer of theirs would be resolved
// (auth.UserForSignIn), shows them the frozen revision, and on their click
// calls the existing decision handler (DecideActionApproval) as them, with
// the binding {approval_ref, context_digest, content_digest} of what was
// shown. Every gate of that handler still decides: the Glovo owner check
// (bound owner, live developer membership of the binding's tenant, no
// admin pass, no agent, service, relay or Glovo token), the decision
// context, the binding and the ledger's own state machine. The page adds
// checks of its own in front (owner, kind, revision still current, totals
// consistent) and never relaxes one.
//
// It is the DevLoop decide page's model (mctl-api#964), not a new one: no
// session, no long-lived cookie, no token in the browser. A cookie lives
// only for one decision (ten minutes, __Host-, HttpOnly, Secure,
// SameSite=Lax) and binds the ZITADEL round trip and the confirm POST to
// this browser; the confirm POST also carries a one-time CSRF token held
// server-side as a hash. The page has no script at all.
//
// Dark by default: the routes are mounted only when GlovoBasketApproval is
// complete (see enabled), which cmd/api does only with
// GLOVO_BASKET_UI_ENABLED=true and every dependency present.
//
// State is shared, not this process's memory: mctl-api runs more than one
// replica, and the start, the ZITADEL callback and the confirm POST may each
// reach a different one, or a restarted one. The challenge lives in the OAuth
// flow store (oauth_flow_entries, internal/auth/flowstore) with a TTL, under
// keys that are bearer secrets kept only as hashes, and every step consumes
// its entry with the store's atomic Take: an entry is handed out at most once
// across all replicas. A store that cannot be read refuses the step; it is
// never read as "no such challenge".

// GlovoBasketApprovalKind is the action kind of a basket approval. The page
// serves no other kind: a Glovo order approval is not decided here.
const GlovoBasketApprovalKind = workitems.ActionKindGlovoBasketApproval

// ErrGlovoBasketApprovalNotFound is what a GlovoBasketApprovalView answers
// when it holds no basket approval with that reference. Any other error is a
// failed read, never an absence.
var ErrGlovoBasketApprovalNotFound = errors.New("glovo basket approval not found")

// GlovoBasketApprovalView reads the frozen basket revision an approval is
// bound to. The basket store implements it.
//
// Contract: Fingerprint is the fingerprint of exactly the frozen snapshot
// the lines and totals are read from, and it is the aar_'s artifact_hash
// (the content_digest of the decision binding). CurrentRevision is the
// basket's newest revision at read time.
type GlovoBasketApprovalView interface {
	BasketApproval(ctx context.Context, approvalRef string) (*GlovoBasketApprovalSnapshot, error)
}

// GlovoBasketApprovalSnapshot is one frozen basket revision as its owner is
// shown it. Money is in minor units of Currency (two decimals).
type GlovoBasketApprovalSnapshot struct {
	ApprovalRef      string
	Tenant           string
	OwnerPrincipalID string
	BasketID         string
	Revision         int64
	CurrentRevision  int64
	Fingerprint      string
	Currency         string
	Lines            []GlovoBasketLine
	FeesMinor        int64
	TotalMinor       int64
}

// GlovoBasketLine is one line of a frozen revision. Name is data from the
// synthetic catalog, never markup.
type GlovoBasketLine struct {
	ProductID      string
	Name           string
	Quantity       int64
	UnitPriceMinor int64
	LineTotalMinor int64
}

// GlovoBasketApprovalPageOptions configures the page. All fields are needed;
// with any missing the routes are not mounted.
type GlovoBasketApprovalPageOptions struct {
	// ProviderName and Issuer are the federation entry the signed-in
	// identity is resolved as (MCTL_OIDC_PROVIDERS), so the person is the
	// same principal their bearer would be.
	ProviderName string
	Issuer       string
	// ClientID and ClientSecret are a ZITADEL web client whose redirect URIs
	// include BaseURL + /glovo/basket/approvals/callback. Only its ID token
	// is read, never an access token.
	ClientID     string
	ClientSecret string
	// BaseURL is mctl-api's public URL.
	BaseURL    string
	Principals auth.PrincipalResolver
	Authz      *auth.PrincipalAuthz
	View       GlovoBasketApprovalView
	// Flow is the shared store of challenges in flight: the OAuth server's
	// flow store, so every replica sees every challenge.
	Flow flowstore.Store

	// clock replaces time.Now in tests.
	clock func() time.Time
}

func (o *GlovoBasketApprovalPageOptions) enabled() bool {
	return o != nil && o.ProviderName != "" && o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" &&
		o.BaseURL != "" && o.Principals != nil && o.Authz != nil && o.View != nil && o.Flow != nil
}

const (
	basketCookieName      = "__Host-mctl_glovo_basket"
	basketPagePrefix      = "/glovo/basket/approvals/"
	basketStartPath       = "/glovo/basket/approvals/start"
	basketCallbackPath    = "/glovo/basket/approvals/callback"
	basketConfirmPath     = "/glovo/basket/approvals/confirm"
	basketChallengeTTL    = 10 * time.Minute
	basketMaxLines        = 200
	basketMaxFeesMinor    = 1_000_000_000
	basketReasonApprove   = "approved on the Glovo basket approval page"
	basketReasonReject    = "rejected on the Glovo basket approval page"
	basketAuditOp         = "glovo-basket-approval-page"
	basketNotFoundMessage = "There is no basket approval with this reference waiting for you."
)

// basketApprovalRefRe is an aar_ id as the store mints it.
var basketApprovalRefRe = regexp.MustCompile(`^aar_[0-9a-f]{32}$`)

// Kinds of flow store entry. A key is looked up only within its kind, so a
// state can never be redeemed as a confirm or as an OAuth server entry.
const (
	basketKindStart  = "glovo-basket-start"
	basketKindDecide = "glovo-basket-decide"
)

// basketStartEntry is a sign-in waiting for ZITADEL. Its key is the OAuth
// state joined with this browser's cookie, so a callback from another
// browser finds nothing and spends nothing.
type basketStartEntry struct {
	ApprovalRef string    `json:"approval_ref"`
	StartedAt   time.Time `json:"started_at"`
	Nonce       string    `json:"nonce"`
	Verifier    string    `json:"verifier"`
}

// basketDecideEntry is a signed-in owner shown a basket. Its key is the
// challenge id, the one-time CSRF token and this browser's cookie, joined:
// a confirm missing any of them finds nothing and spends nothing, and the
// one confirm that has all three takes the entry atomically.
type basketDecideEntry struct {
	ApprovalRef string         `json:"approval_ref"`
	StartedAt   time.Time      `json:"started_at"`
	Identity    basketIdentity `json:"identity"`
	// Shown is the binding of what the person was shown at sign-in; the
	// decision is bound to it and to nothing read later.
	Shown decisionBinding `json:"shown"`
}

// basketIdentity is the ZITADEL identity a sign-in proved, as stored.
type basketIdentity struct {
	Provider string `json:"provider"`
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Display  string `json:"display"`
}

func (b basketIdentity) identity() auth.Identity {
	return auth.Identity{Provider: b.Provider, Issuer: b.Issuer, Subject: b.Subject, Display: b.Display, Kind: auth.KindHuman}
}

func basketStartKey(state, browser string) string { return state + "\x00" + browser }

func basketDecideKey(challenge, csrf, browser string) string {
	return challenge + "\x00" + csrf + "\x00" + browser
}

type basketDecider struct {
	opts *GlovoBasketApprovalPageOptions
	lazyOIDCProvider
	now func() time.Time
}

func newBasketDecider(opts *GlovoBasketApprovalPageOptions) *basketDecider {
	now := time.Now
	if opts.clock != nil {
		now = opts.clock
	}
	return &basketDecider{opts: opts, lazyOIDCProvider: lazyOIDCProvider{issuer: opts.Issuer}, now: now}
}

// put stores v under (kind, key) for ttl.
func (d *basketDecider) put(ctx context.Context, kind, key string, v any, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return d.opts.Flow.Put(ctx, kind, key, b, ttl)
}

// take consumes the entry under (kind, key) into v. found is false only when
// the store answered that no live entry exists; err is a store that could
// not be read, which the caller must refuse on, never read as absent.
func (d *basketDecider) take(ctx context.Context, kind, key string, v any) (found bool, err error) {
	b, found, err := d.opts.Flow.Take(ctx, kind, key)
	if err != nil || !found {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("glovo basket approval: %s entry unreadable: %w", kind, err)
	}
	return true, nil
}

// remaining is what is left of a challenge's ten minutes.
func (d *basketDecider) remaining(startedAt time.Time) time.Duration {
	return startedAt.Add(basketChallengeTTL).Sub(d.now())
}

func (d *basketDecider) storeDown(w http.ResponseWriter, err error) {
	slog.Warn("glovo basket approval: flow store unavailable", "error", err)
	d.failed(w, http.StatusServiceUnavailable, "The approval page cannot reach its store right now; nothing was decided. Try again in a few minutes.")
}

func (d *basketDecider) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     d.opts.ClientID,
		ClientSecret: d.opts.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  d.opts.BaseURL + basketCallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
}

// basketBrowser is this browser's cookie, "" when it has none.
func basketBrowser(r *http.Request) string {
	ck, err := r.Cookie(basketCookieName)
	if err != nil {
		return ""
	}
	return ck.Value
}

func setBasketCookie(w http.ResponseWriter, value string, maxAge int) {
	// SameSite=Lax: sent on the top-level redirect back from ZITADEL and on
	// the same-site confirm POST, never on a cross-site POST.
	http.SetCookie(w, &http.Cookie{
		Name: basketCookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// basketPage draws the frozen revision as a table. html/template escapes
// every value, product names included; there is no script on the page.
var basketPage = shellPage("glovo-basket-approval", `{{with .Basket}}<table style="width:100%;border-collapse:collapse;margin:.5rem 0 1rem;font-size:.9375rem">
<thead><tr><th style="text-align:left">Item</th><th style="text-align:right">Qty</th><th style="text-align:right">Price</th><th style="text-align:right">Total</th></tr></thead>
<tbody>{{range .Lines}}<tr><td style="overflow-wrap:anywhere">{{.Name}}</td><td style="text-align:right">{{.Quantity}}</td><td style="text-align:right">{{.Unit}}</td><td style="text-align:right">{{.Total}}</td></tr>
{{end}}</tbody>
<tfoot>{{if .Fees}}<tr><td colspan="3">Fees</td><td style="text-align:right">{{.Fees}}</td></tr>{{end}}<tr><th colspan="3" style="text-align:left">Total ({{.Currency}})</th><th style="text-align:right">{{.Total}}</th></tr></tfoot>
</table>{{end}}
{{if .SignIn}}<form class="actions" method="post" action="{{.SignIn.Action}}">
<input type="hidden" name="approval_ref" value="{{.SignIn.ApprovalRef}}">
<button type="submit">Sign in to review this basket</button></form>{{end}}
{{if .Decide}}<form class="actions" method="post" action="{{.Decide.Action}}">
<input type="hidden" name="challenge" value="{{.Decide.Challenge}}">
<input type="hidden" name="csrf" value="{{.Decide.CSRF}}">
<button type="submit" name="decision" value="approve">Approve this basket</button>
<button type="submit" name="decision" value="reject" class="secondary">Reject</button></form>{{end}}`)

type basketTable struct {
	Lines    []basketTableLine
	Fees     string
	Total    string
	Currency string
}

type basketTableLine struct {
	Name        string
	Quantity    int64
	Unit, Total string
}

type basketPageData struct {
	Basket *basketTable
	SignIn *struct{ Action, ApprovalRef string }
	Decide *struct{ Action, Challenge, CSRF string }
}

func (d *basketDecider) renderPage(w http.ResponseWriter, status int, title string, lines []string, p basketPageData) {
	// form-action names the issuer too: the sign-in POST answers with a
	// redirect to ZITADEL, and form-action governs that redirect.
	formAction := "'self'"
	if d != nil {
		if u, err := url.Parse(d.opts.Issuer); err == nil && u.Scheme == "https" && u.Host != "" {
			formAction += " https://" + u.Host
		}
	}
	renderShellPage(w, status, "default-src 'none'; style-src 'unsafe-inline'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'",
		basketPage, shellData{Title: title, Lines: lines, Page: p})
}

func (d *basketDecider) failed(w http.ResponseWriter, status int, msg string) {
	d.renderPage(w, status, "Cannot decide this basket", []string{msg, "Open the approval link again to start over."}, basketPageData{})
}

func (h *Handlers) basketPageDecider(w http.ResponseWriter) (*basketDecider, bool) {
	d := h.glovoBasketApproval
	if d == nil || !d.opts.enabled() {
		var none *basketDecider
		none.failed(w, http.StatusServiceUnavailable, "The basket approval page is not enabled on this server.")
		return nil, false
	}
	return d, true
}

// handleGlovoBasketApprovalPage: GET /glovo/basket/approvals/{approval_ref}.
// It reads nothing and changes nothing: the sign-in starts on a POST, so a
// link preview or a prefetch creates no state, and it shows no basket, so
// the link alone tells nobody whether the approval exists.
func (h *Handlers) handleGlovoBasketApprovalPage(w http.ResponseWriter, r *http.Request) {
	d, ok := h.basketPageDecider(w)
	if !ok {
		return
	}
	ref := chi.URLParam(r, "approval_ref")
	if !basketApprovalRefRe.MatchString(ref) {
		d.failed(w, http.StatusBadRequest, "This approval link is malformed.")
		return
	}
	d.renderPage(w, http.StatusOK, "Review a basket", []string{
		"Approval: " + ref,
		"Sign in to ZITADEL as yourself to see the basket and approve or reject it. Only the person who asked for this approval can see or decide it.",
		"Nothing is ordered or paid either way: the basket is synthetic.",
	}, basketPageData{SignIn: &struct{ Action, ApprovalRef string }{Action: basketStartPath, ApprovalRef: ref}})
}

// handleGlovoBasketApprovalStart: POST /glovo/basket/approvals/start.
func (h *Handlers) handleGlovoBasketApprovalStart(w http.ResponseWriter, r *http.Request) {
	d, ok := h.basketPageDecider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	ref := r.PostForm.Get("approval_ref")
	if !basketApprovalRefRe.MatchString(ref) {
		d.failed(w, http.StatusBadRequest, "This approval link is malformed.")
		return
	}
	prov, err := d.oidcProvider(r.Context())
	if err != nil {
		slog.Warn("glovo basket approval: ZITADEL discovery failed", "issuer", d.opts.Issuer, "error", err)
		d.failed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	browser, err1 := randomLinkToken()
	state, err2 := randomLinkToken()
	nonce, err3 := randomLinkToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	entry := basketStartEntry{ApprovalRef: ref, StartedAt: d.now(), Nonce: nonce, Verifier: oauth2.GenerateVerifier()}
	// Abuse is bounded by the route's per-IP rate limit and the entry's TTL;
	// the store's GC drops what is never finished.
	if err := d.put(r.Context(), basketKindStart, basketStartKey(state, browser), entry, basketChallengeTTL); err != nil {
		d.storeDown(w, err)
		return
	}

	setBasketCookie(w, browser, int(basketChallengeTTL.Seconds()))
	// prompt=login: the person signs in now, in this browser. max_age=0
	// makes auth_time a REQUIRED claim (OIDC Core 3.1.2.1), checked below.
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(entry.Verifier), oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// basketShown is a basket approval as its owner is shown it, after every
// check of the page.
type basketShown struct {
	approvalRef   string
	state         string
	expiresAt     time.Time
	contextDigest string
	snap          *GlovoBasketApprovalSnapshot
	table         *basketTable
}

// decidable reports whether an approve or a reject may be offered.
func (s *basketShown) decidable(now time.Time) bool {
	return s.state == workitems.ApprovalPending && now.Before(s.expiresAt) && !s.superseded()
}

func (s *basketShown) superseded() bool { return s.snap.CurrentRevision != s.snap.Revision }

func (s *basketShown) binding() decisionBinding {
	return decisionBinding{ApprovalRef: s.approvalRef, ContextDigest: s.contextDigest, ContentDigest: s.snap.Fingerprint}
}

// basketRefusal is a page answer instead of a basket.
type basketRefusal struct {
	status int
	msg    string
	audit  string // the reason recorded, never shown
}

func basketNotFound(reason string) *basketRefusal {
	return &basketRefusal{status: http.StatusNotFound, msg: basketNotFoundMessage, audit: reason}
}

// readBasketApproval reads approval ref as user and checks that user is its
// bound owner. Every "not yours" reads like "no such approval": an unknown
// id, another kind, someone else's basket (an admin's included), a binding
// or a basket that names another person, and a caller who may never own one.
func (h *Handlers) readBasketApproval(r *http.Request, d *basketDecider, user *auth.User, ref string) (*basketShown, *basketRefusal) {
	if !isGlovoOwnerCandidate(user) {
		return nil, basketNotFound("not an owner candidate")
	}
	// The aar_ as the API serves it to this person: its own read gate first.
	status, body := h.callAs(r, user, http.MethodGet, "id", ref, nil, h.GetActionApproval)
	if status != http.StatusOK {
		return nil, basketNotFound("approval read: " + strconv.Itoa(status))
	}
	var got struct {
		Approval struct {
			ID           string    `json:"id"`
			ActionKind   string    `json:"action_kind"`
			State        string    `json:"state"`
			ExpiresAt    time.Time `json:"expires_at"`
			ArtifactHash string    `json:"artifact_hash"`
		} `json:"approval"`
		Context struct {
			Digest string `json:"context_digest"`
		} `json:"decision_context"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		return nil, &basketRefusal{status: http.StatusBadGateway, msg: "The approval could not be read.", audit: "approval body unreadable"}
	}
	if got.Approval.ID != ref || got.Approval.ActionKind != GlovoBasketApprovalKind {
		return nil, basketNotFound("not a basket approval")
	}
	// The decision ledger's binding: the same owner the decision handler
	// will require. An admin reads every aar_, so this, not the read above,
	// is what keeps another owner's basket hidden.
	ledger := h.basketApprovalLedger()
	if ledger == nil {
		return nil, basketNotFound("no glovo approvals ledger")
	}
	_, binding, err := ledger.ForDecision(r.Context(), ref)
	switch {
	case errors.Is(err, workitems.ErrApprovalNotFound):
		return nil, basketNotFound("no binding")
	case err != nil:
		return nil, &basketRefusal{status: http.StatusServiceUnavailable, msg: "The approval cannot be read right now; try again later.", audit: "binding read failed"}
	}
	if !isGlovoOwnerDecider(user, binding) {
		return nil, basketNotFound("not the bound owner")
	}
	snap, err := d.opts.View.BasketApproval(r.Context(), ref)
	switch {
	case errors.Is(err, ErrGlovoBasketApprovalNotFound):
		return nil, basketNotFound("no basket snapshot")
	case err != nil:
		return nil, &basketRefusal{status: http.StatusServiceUnavailable, msg: "The basket cannot be read right now; try again later.", audit: "basket read failed"}
	}
	if snap == nil || snap.ApprovalRef != ref || snap.OwnerPrincipalID != user.PrincipalID() ||
		snap.OwnerPrincipalID != binding.OwnerPrincipalID || snap.Tenant != binding.Tenant {
		return nil, basketNotFound("basket snapshot names another owner or tenant")
	}
	// From here the caller is the owner: a refusal may say what is wrong.
	if snap.Fingerprint == "" || snap.Fingerprint != got.Approval.ArtifactHash {
		return nil, &basketRefusal{status: http.StatusConflict, msg: "The basket does not match what this approval is bound to; ask for a new approval.", audit: "fingerprint mismatch"}
	}
	table, err := basketTableOf(snap)
	if err != nil {
		return nil, &basketRefusal{status: http.StatusConflict, msg: "The basket's totals do not add up; it cannot be approved. Ask for a new approval.", audit: err.Error()}
	}
	return &basketShown{
		approvalRef: ref, state: got.Approval.State, expiresAt: got.Approval.ExpiresAt,
		contextDigest: got.Context.Digest, snap: snap, table: table,
	}, nil
}

// basketApprovalLedger is the ledger the decision handler decides a basket
// approval with (glovoDecisionsFor, the basket MCP's own decisions), so the
// page checks the very binding the decision will. Nil when the basket MCP is
// not configured: then the page finds nothing to decide.
func (h *Handlers) basketApprovalLedger() GlovoApprovalDecisions {
	return h.glovoDecisionsFor(workitems.ActionKindGlovoBasketApproval)
}

// basketTableOf checks a snapshot's arithmetic and formats it. A page that
// asks for a click on a total must not show one that the lines contradict.
func basketTableOf(s *GlovoBasketApprovalSnapshot) (*basketTable, error) {
	if len(s.Lines) == 0 {
		return nil, errors.New("empty basket")
	}
	if len(s.Lines) > basketMaxLines {
		return nil, errors.New("too many lines")
	}
	if !currencyRe.MatchString(s.Currency) {
		return nil, errors.New("malformed currency")
	}
	if s.FeesMinor < 0 || s.FeesMinor > basketMaxFeesMinor || s.TotalMinor < 0 {
		return nil, errors.New("negative or oversized fees or total")
	}
	t := &basketTable{Currency: s.Currency}
	// Every bound is checked before it is multiplied or added: a line is at
	// most 1e6 * 1e9 = 1e15, so 200 of them and the fees stay far below
	// MaxInt64, and the explicit check below holds even if a bound moves.
	var sum int64
	for _, l := range s.Lines {
		if l.Quantity <= 0 || l.UnitPriceMinor < 0 || l.LineTotalMinor < 0 {
			return nil, errors.New("negative or empty line")
		}
		if l.Quantity > 1_000_000 || l.UnitPriceMinor > 1_000_000_000 || l.Quantity*l.UnitPriceMinor != l.LineTotalMinor {
			return nil, errors.New("line total mismatch")
		}
		if sum > math.MaxInt64-l.LineTotalMinor {
			return nil, errors.New("basket total overflows")
		}
		sum += l.LineTotalMinor
		t.Lines = append(t.Lines, basketTableLine{Name: l.Name, Quantity: l.Quantity, Unit: formatMinor(l.UnitPriceMinor), Total: formatMinor(l.LineTotalMinor)})
	}
	if sum > math.MaxInt64-s.FeesMinor || sum+s.FeesMinor != s.TotalMinor {
		return nil, errors.New("basket total mismatch")
	}
	if s.FeesMinor > 0 {
		t.Fees = formatMinor(s.FeesMinor)
	}
	t.Total = formatMinor(s.TotalMinor)
	return t, nil
}

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

func formatMinor(v int64) string { return fmt.Sprintf("%d.%02d", v/100, v%100) }

// basketStateWord is the state as the owner is told it.
func basketStateWord(s string) string {
	switch s {
	case workitems.ApprovalDenied:
		return "rejected"
	case workitems.ApprovalConsumed, workitems.ApprovalExecuted, workitems.ApprovalInFlight:
		return "consumed"
	}
	return s
}

func (s *basketShown) lines(display string) []string {
	return []string{
		"Signed in as " + display + ".",
		"Team: " + s.snap.Tenant,
		"Basket: " + s.snap.BasketID + ", revision " + strconv.FormatInt(s.snap.Revision, 10),
		"Approval: " + s.approvalRef + " (" + basketStateWord(s.state) + ")",
		"Expires: " + s.expiresAt.UTC().Format(time.RFC3339),
		"Basket fingerprint: " + s.snap.Fingerprint,
		"Context digest: " + s.contextDigest,
	}
}

// signedInUser resolves the identity a sign-in proved as the middleware would
// resolve a bearer of it. No admin bit is asked for: the decision handler
// requires the bound owner, and gives an admin no pass.
func (d *basketDecider) signedInUser(ctx context.Context, id auth.Identity) (*auth.User, error) {
	return auth.UserForSignIn(ctx, id, d.opts.Principals, d.opts.Authz)
}

// handleGlovoBasketApprovalCallback: GET /glovo/basket/approvals/callback.
func (h *Handlers) handleGlovoBasketApprovalCallback(w http.ResponseWriter, r *http.Request) {
	d, ok := h.basketPageDecider(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	state, browser := q.Get("state"), basketBrowser(r)
	if state == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, basketUnknownSignIn)
		return
	}
	// Consumed now, on whichever replica the callback reached: a replayed
	// callback finds nothing.
	var c basketStartEntry
	found, err := d.take(r.Context(), basketKindStart, basketStartKey(state, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, basketUnknownSignIn)
		return
	}
	if q.Get("error") != "" {
		d.failed(w, http.StatusBadRequest, "ZITADEL refused the sign-in.")
		return
	}
	code := q.Get("code")
	if code == "" {
		d.failed(w, http.StatusBadRequest, "ZITADEL returned no code.")
		return
	}
	prov, err := d.oidcProvider(r.Context())
	if err != nil {
		d.failed(w, http.StatusBadGateway, "ZITADEL is not reachable right now.")
		return
	}
	tok, err := d.oauthConfig(prov).Exchange(r.Context(), code, oauth2.VerifierOption(c.Verifier))
	if err != nil {
		slog.Warn("glovo basket approval: ZITADEL code exchange failed", "error", err)
		d.failed(w, http.StatusBadGateway, "Could not complete the ZITADEL sign-in.")
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: d.opts.ClientID}).Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("glovo basket approval: ZITADEL ID token refused", "error", err)
		d.failed(w, http.StatusBadRequest, "The ZITADEL ID token was not valid.")
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		AuthTime          int64  `json:"auth_time"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.Nonce)) != 1 {
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this approval.")
		return
	}
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.StartedAt.Add(-time.Minute)) {
		d.failed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this approval.")
		return
	}
	display := claims.PreferredUsername
	if display == "" {
		display = idt.Subject
	}
	stored := basketIdentity{Provider: d.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display}
	id := stored.identity()
	user, err := d.signedInUser(r.Context(), id)
	if err != nil {
		h.auditBasketPage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, basketNotFoundMessage)
		return
	}
	shown, ref := h.readBasketApproval(r, d, user, c.ApprovalRef)
	if ref != nil {
		h.auditBasketPage(r, user, id, c.ApprovalRef, "denied", ref.audit)
		d.failed(w, ref.status, ref.msg)
		return
	}
	page := basketPageData{Basket: shown.table}
	switch {
	case shown.superseded():
		d.renderPage(w, http.StatusConflict, "This basket changed", append(shown.lines(display),
			"The basket has a newer revision ("+strconv.FormatInt(shown.snap.CurrentRevision, 10)+") than the one this approval froze. Ask for a new approval of the current basket."), page)
		return
	case !shown.decidable(d.now()):
		state := basketStateWord(shown.state)
		if shown.state == workitems.ApprovalPending {
			state = workitems.ApprovalExpired
		}
		d.renderPage(w, http.StatusOK, "This basket is "+state, append(shown.lines(display), "There is nothing left to decide."), page)
		return
	}
	// The decision handler requires live developer membership of the
	// binding's team. Asked here too, so a click that would be refused is
	// never offered.
	if mem := h.basketMembership(user, shown.snap.Tenant); mem.refused() {
		h.auditBasketPage(r, user, id, c.ApprovalRef, mem.auditStatus, "membership: "+mem.detail)
		if mem.status != http.StatusForbidden {
			d.failed(w, http.StatusServiceUnavailable, "Your membership of the team cannot be checked right now; try again later.")
			return
		}
		d.renderPage(w, http.StatusForbidden, "You cannot decide this basket", append(shown.lines(display),
			basketNotMemberMessage(shown.snap.Tenant)), page)
		return
	}
	left := d.remaining(c.StartedAt)
	challenge, err1 := randomLinkToken()
	csrf, err2 := randomLinkToken()
	if err := errors.Join(err1, err2); err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	if left <= 0 {
		d.failed(w, http.StatusBadRequest, "This approval page expired while ZITADEL was being verified.")
		return
	}
	entry := basketDecideEntry{ApprovalRef: c.ApprovalRef, StartedAt: c.StartedAt, Identity: stored, Shown: shown.binding()}
	if err := d.put(r.Context(), basketKindDecide, basketDecideKey(challenge, csrf, browser), entry, left); err != nil {
		d.storeDown(w, err)
		return
	}
	page.Decide = &struct{ Action, Challenge, CSRF string }{Action: basketConfirmPath, Challenge: challenge, CSRF: csrf}
	d.renderPage(w, http.StatusOK, "Approve or reject this basket", append(shown.lines(display),
		"Approving records your approval of exactly this revision. It orders, pays and sends nothing."), page)
}

const basketUnknownSignIn = "This sign-in is unknown, expired, already used, started in another browser, or replaced by a newer one started in this browser."

func basketNotMemberMessage(tenant string) string {
	return "You are not a developer of team " + tenant + " any more, so you cannot approve or reject this basket. Nothing was decided. Ask an admin of the team to restore your membership, then open the approval link again."
}

// basketMembership is the decision handler's live membership check
// (glovoOwnerCheck), asked by the page before it offers or passes on a
// click. It decides nothing the handler would not: the handler asks again.
func (h *Handlers) basketMembership(user *auth.User, tenant string) roleRefusal {
	var read func() ([][]string, error)
	if h.opts.TenantAuthzMode == TenantAuthzPrincipal && h.opts.PrincipalMembership != nil {
		prn := user.PrincipalID()
		read = func() ([][]string, error) { return h.opts.PrincipalMembership.MemberRolesForPrincipal(tenant, prn) }
	}
	return decideWrittenRole(user.PrincipalID(), "principal membership reader", tenant, glovoMinDeciderRole,
		"deciding a Glovo basket approval", read)
}

// handleGlovoBasketApprovalConfirm: POST /glovo/basket/approvals/confirm.
func (h *Handlers) handleGlovoBasketApprovalConfirm(w http.ResponseWriter, r *http.Request) {
	d, ok := h.basketPageDecider(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		d.failed(w, http.StatusBadRequest, "The request could not be read.")
		return
	}
	decision := r.PostForm.Get("decision")
	if decision != "approve" && decision != "reject" {
		d.failed(w, http.StatusBadRequest, "Choose Approve or Reject.")
		return
	}
	challenge, csrf, browser := r.PostForm.Get("challenge"), r.PostForm.Get("csrf"), basketBrowser(r)
	if challenge == "" || csrf == "" || browser == "" {
		d.failed(w, http.StatusBadRequest, basketUnknownConfirm)
		return
	}
	// Used once, whatever happens next, across every replica: the store's
	// Take hands the entry to exactly one confirm, so a double click, a
	// replayed form or a race on two replicas finds nothing. A forged or
	// cross-browser post names another key and spends nothing, and keeps
	// this browser's cookie.
	var c basketDecideEntry
	found, err := d.take(r.Context(), basketKindDecide, basketDecideKey(challenge, csrf, browser), &c)
	if err != nil {
		d.storeDown(w, err)
		return
	}
	if !found || d.remaining(c.StartedAt) <= 0 {
		d.failed(w, http.StatusBadRequest, basketUnknownConfirm)
		return
	}
	setBasketCookie(w, "", -1)
	id := c.Identity.identity()
	// Resolved and read again: a principal disabled, a membership lost or a
	// basket revised since the sign-in decides now.
	user, err := d.signedInUser(r.Context(), id)
	if err != nil {
		h.auditBasketPage(r, nil, id, c.ApprovalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, basketNotFoundMessage)
		return
	}
	shown, ref := h.readBasketApproval(r, d, user, c.ApprovalRef)
	if ref != nil {
		h.auditBasketPage(r, user, id, c.ApprovalRef, "denied", ref.audit)
		d.failed(w, ref.status, ref.msg)
		return
	}
	if shown.superseded() || shown.binding() != c.Shown {
		h.auditBasketPage(r, user, id, c.ApprovalRef, "denied", "basket changed since it was shown")
		d.failed(w, http.StatusConflict, "The basket or its approval changed after you were shown it; nothing was decided.")
		return
	}
	if !shown.decidable(d.now()) {
		h.auditBasketPage(r, user, id, c.ApprovalRef, "denied", "not pending")
		d.failed(w, http.StatusConflict, "This approval is already "+basketStateWord(shown.state)+" or has expired; nothing was decided.")
		return
	}
	if mem := h.basketMembership(user, shown.snap.Tenant); mem.refused() {
		h.auditBasketPage(r, user, id, c.ApprovalRef, mem.auditStatus, "membership: "+mem.detail)
		if mem.status != http.StatusForbidden {
			d.failed(w, http.StatusServiceUnavailable, "Your membership of the team cannot be checked right now; nothing was decided. Try again later.")
			return
		}
		d.failed(w, http.StatusForbidden, basketNotMemberMessage(shown.snap.Tenant))
		return
	}
	body := map[string]any{"decision": workitems.DecisionDeny, "reason": basketReasonReject}
	if decision == "approve" {
		body = map[string]any{"decision": workitems.DecisionApprove, "reason": basketReasonApprove, "binding": c.Shown}
	}
	status, resp := h.callAs(r, user, http.MethodPost, "id", c.ApprovalRef, body, h.DecideActionApproval)
	if status != http.StatusOK {
		h.auditBasketPage(r, user, id, c.ApprovalRef, "failed", decision+": "+errorText(resp))
		msg := "The " + decision + " was refused: " + errorText(resp) + "."
		if status == http.StatusForbidden {
			// The handler's one answer for every non-decider names admins,
			// which is not this page's audience. Its checks ran after ours:
			// what changed in between is the owner's standing.
			msg = "You may no longer decide this basket: your ownership or your membership of team " + shown.snap.Tenant + " changed. Nothing was decided."
		}
		d.failed(w, status, msg)
		return
	}
	var got struct {
		Approval struct {
			State string `json:"state"`
		} `json:"approval"`
	}
	_ = json.Unmarshal(resp, &got)
	h.auditBasketPage(r, user, id, c.ApprovalRef, "succeeded", decision)
	title := "Basket approved"
	if decision == "reject" {
		title = "Basket rejected"
	}
	shown.state = got.Approval.State
	d.renderPage(w, http.StatusOK, title, append(shown.lines(id.Display),
		"The assistant that asked can now read this result. Nothing was ordered or paid."), basketPageData{Basket: shown.table})
}

const basketUnknownConfirm = "This approval page is unknown, expired, already used, or was opened in another browser."

// auditBasketPage records what the page itself decided. Ids only: no
// product, price or basket content, no token. The decision handler writes
// its own entry too.
func (h *Handlers) auditBasketPage(r *http.Request, user *auth.User, id auth.Identity, approvalRef, status, msg string) {
	actor := id.Provider + ":" + id.Subject
	if user != nil {
		actor = user.ID
	}
	h.logAudit(r, audit.Entry{
		UserID:     actor,
		Operation:  basketAuditOp,
		Parameters: map[string]string{"approval_ref": approvalRef, "provider": id.Provider, "subject": id.Subject},
		Status:     status,
		RiskLevel:  string(operations.RiskMedium),
		Message:    msg,
	})
}
