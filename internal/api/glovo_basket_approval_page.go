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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
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
// State is this process's memory, like the decide page: mctl-api runs one
// replica, and a restart only means "open the link again".

// GlovoBasketApprovalKind is the action kind of a basket approval. The page
// serves no other kind: a Glovo order approval is not decided here.
const GlovoBasketApprovalKind = "glovo.basket_approval"

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

	// clock replaces time.Now in tests.
	clock func() time.Time
}

func (o *GlovoBasketApprovalPageOptions) enabled() bool {
	return o != nil && o.ProviderName != "" && o.Issuer != "" && o.ClientID != "" && o.ClientSecret != "" &&
		o.BaseURL != "" && o.Principals != nil && o.Authz != nil && o.View != nil
}

const (
	basketCookieName      = "__Host-mctl_glovo_basket"
	basketPagePrefix      = "/glovo/basket/approvals/"
	basketStartPath       = "/glovo/basket/approvals/start"
	basketCallbackPath    = "/glovo/basket/approvals/callback"
	basketConfirmPath     = "/glovo/basket/approvals/confirm"
	basketChallengeTTL    = 10 * time.Minute
	basketMaxChallenges   = 1000
	basketMaxPerIP        = 3
	basketReasonApprove   = "approved on the Glovo basket approval page"
	basketReasonReject    = "rejected on the Glovo basket approval page"
	basketAuditOp         = "glovo-basket-approval-page"
	basketNotFoundMessage = "There is no basket approval with this reference waiting for you."
)

// basketApprovalRefRe is an aar_ id as the store mints it.
var basketApprovalRefRe = regexp.MustCompile(`^aar_[0-9a-f]{32}$`)

type basketPhase int

const (
	basketStarted basketPhase = iota
	basketSignedIn
)

type basketChallenge struct {
	id          string
	browserHash [32]byte
	expiresAt   time.Time
	startedAt   time.Time
	phase       basketPhase
	clientIP    string

	approvalRef string

	state    string
	nonce    string
	verifier string

	identity auth.Identity
	csrfHash [32]byte
	// shown is the binding of what the person was shown at sign-in; the
	// decision is bound to it and to nothing read later.
	shown decisionBinding
}

type basketDecider struct {
	opts *GlovoBasketApprovalPageOptions

	mu      sync.Mutex
	byID    map[string]*basketChallenge
	byState map[string]*basketChallenge

	lazyOIDCProvider
	now func() time.Time
}

func newBasketDecider(opts *GlovoBasketApprovalPageOptions) *basketDecider {
	now := time.Now
	if opts.clock != nil {
		now = opts.clock
	}
	return &basketDecider{
		opts:             opts,
		lazyOIDCProvider: lazyOIDCProvider{issuer: opts.Issuer},
		byID:             map[string]*basketChallenge{},
		byState:          map[string]*basketChallenge{},
		now:              now,
	}
}

func (d *basketDecider) sweepLocked(now time.Time) {
	for id, c := range d.byID {
		if now.After(c.expiresAt) {
			d.dropLocked(id, c)
		}
	}
	for k, c := range d.byState {
		if d.byID[c.id] != c || now.After(c.expiresAt) {
			delete(d.byState, k)
		}
	}
}

func (d *basketDecider) liveLocked(c *basketChallenge, phase basketPhase, now time.Time) bool {
	return d.byID[c.id] == c && c.phase == phase && !now.After(c.expiresAt)
}

func (d *basketDecider) dropLocked(id string, c *basketChallenge) {
	delete(d.byID, id)
	delete(d.byState, c.state)
}

func (d *basketDecider) abandon(c *basketChallenge) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byID[c.id] == c {
		d.dropLocked(c.id, c)
	}
}

// capSourceLocked makes room for one more challenge from ip by dropping its
// oldest one still waiting for ZITADEL; false when all of ip's are signed in.
func (d *basketDecider) capSourceLocked(ip string) bool {
	for {
		mine := 0
		var oldest *basketChallenge
		for _, c := range d.byID {
			if c.clientIP != ip {
				continue
			}
			mine++
			if c.phase == basketStarted && (oldest == nil || c.startedAt.Before(oldest.startedAt)) {
				oldest = c
			}
		}
		if mine < basketMaxPerIP {
			return true
		}
		if oldest == nil {
			return false
		}
		d.dropLocked(oldest.id, oldest)
	}
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

func basketBrowserMatches(r *http.Request, c *basketChallenge) bool {
	ck, err := r.Cookie(basketCookieName)
	if err != nil || ck.Value == "" {
		return false
	}
	sum := sha256.Sum256([]byte(ck.Value))
	return subtle.ConstantTimeCompare(sum[:], c.browserHash[:]) == 1
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
	id, err2 := randomLinkToken()
	state, err3 := randomLinkToken()
	nonce, err4 := randomLinkToken()
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	now := d.now()
	ip, _ := keyByTrustedIP(r)
	c := &basketChallenge{
		id: id, browserHash: sha256.Sum256([]byte(browser)), expiresAt: now.Add(basketChallengeTTL),
		startedAt: now, clientIP: ip, approvalRef: ref,
		state: state, nonce: nonce, verifier: oauth2.GenerateVerifier(),
	}
	d.mu.Lock()
	d.sweepLocked(now)
	if !d.capSourceLocked(ip) {
		d.mu.Unlock()
		d.failed(w, http.StatusTooManyRequests, "Too many approvals in progress from your network; finish one or try again in a few minutes.")
		return
	}
	if len(d.byID) >= basketMaxChallenges {
		d.mu.Unlock()
		d.failed(w, http.StatusServiceUnavailable, "Too many approvals in progress; try again in a few minutes.")
		return
	}
	d.byID[c.id] = c
	d.byState[c.state] = c
	d.mu.Unlock()

	setBasketCookie(w, browser, int(basketChallengeTTL.Seconds()))
	// prompt=login: the person signs in now, in this browser. max_age=0
	// makes auth_time a REQUIRED claim (OIDC Core 3.1.2.1), checked below.
	authURL := d.oauthConfig(prov).AuthCodeURL(state, oauth2.S256ChallengeOption(c.verifier), oidc.Nonce(nonce),
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
	if h.opts.GlovoApprovals == nil {
		return nil, basketNotFound("no glovo approvals ledger")
	}
	_, binding, err := h.opts.GlovoApprovals.ForDecision(r.Context(), ref)
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

// basketTableOf checks a snapshot's arithmetic and formats it. A page that
// asks for a click on a total must not show one that the lines contradict.
func basketTableOf(s *GlovoBasketApprovalSnapshot) (*basketTable, error) {
	if len(s.Lines) == 0 {
		return nil, errors.New("empty basket")
	}
	if !currencyRe.MatchString(s.Currency) {
		return nil, errors.New("malformed currency")
	}
	t := &basketTable{Currency: s.Currency}
	var sum int64
	for _, l := range s.Lines {
		if l.Quantity <= 0 || l.UnitPriceMinor < 0 || l.LineTotalMinor < 0 {
			return nil, errors.New("negative or empty line")
		}
		if l.Quantity > 1_000_000 || l.UnitPriceMinor > 1_000_000_000 || l.Quantity*l.UnitPriceMinor != l.LineTotalMinor {
			return nil, errors.New("line total mismatch")
		}
		sum += l.LineTotalMinor
		t.Lines = append(t.Lines, basketTableLine{Name: l.Name, Quantity: l.Quantity, Unit: formatMinor(l.UnitPriceMinor), Total: formatMinor(l.LineTotalMinor)})
	}
	if s.FeesMinor < 0 || sum+s.FeesMinor != s.TotalMinor {
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
	d.mu.Lock()
	now := d.now()
	d.sweepLocked(now)
	c, ok := d.byState[q.Get("state")]
	valid := ok && d.liveLocked(c, basketStarted, now) && basketBrowserMatches(r, c)
	if valid {
		delete(d.byState, c.state)
	}
	d.mu.Unlock()
	if !valid {
		d.failed(w, http.StatusBadRequest, "This sign-in is unknown, expired, started in another browser, or replaced by a newer one started in this browser.")
		return
	}
	advanced := false
	defer func() {
		if !advanced {
			d.abandon(c)
		}
	}()
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
	tok, err := d.oauthConfig(prov).Exchange(r.Context(), code, oauth2.VerifierOption(c.verifier))
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
	if err := idt.Claims(&claims); err != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(c.nonce)) != 1 {
		d.failed(w, http.StatusBadRequest, "The ZITADEL sign-in does not belong to this approval.")
		return
	}
	if claims.AuthTime == 0 || time.Unix(claims.AuthTime, 0).Before(c.startedAt.Add(-time.Minute)) {
		d.failed(w, http.StatusBadRequest, "ZITADEL did not report a fresh sign-in for this approval.")
		return
	}
	display := claims.PreferredUsername
	if display == "" {
		display = idt.Subject
	}
	id := auth.Identity{Provider: d.opts.ProviderName, Issuer: idt.Issuer, Subject: idt.Subject, Display: display, Kind: auth.KindHuman}
	user, err := d.signedInUser(r.Context(), id)
	if err != nil {
		h.auditBasketPage(r, nil, id, c.approvalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, basketNotFoundMessage)
		return
	}
	shown, ref := h.readBasketApproval(r, d, user, c.approvalRef)
	if ref != nil {
		h.auditBasketPage(r, user, id, c.approvalRef, "denied", ref.audit)
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
	csrf, err := randomLinkToken()
	if err != nil {
		d.failed(w, http.StatusInternalServerError, "Internal error.")
		return
	}
	d.mu.Lock()
	live := d.liveLocked(c, basketStarted, d.now())
	if live {
		c.identity, c.csrfHash, c.phase, c.shown = id, sha256.Sum256([]byte(csrf)), basketSignedIn, shown.binding()
		advanced = true
	}
	d.mu.Unlock()
	if !live {
		d.failed(w, http.StatusBadRequest, "This approval page expired while ZITADEL was being verified.")
		return
	}
	page.Decide = &struct{ Action, Challenge, CSRF string }{Action: basketConfirmPath, Challenge: c.id, CSRF: csrf}
	d.renderPage(w, http.StatusOK, "Approve or reject this basket", append(shown.lines(display),
		"Approving records your approval of exactly this revision. It orders, pays and sends nothing."), page)
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
	sum := sha256.Sum256([]byte(r.PostForm.Get("csrf")))
	d.mu.Lock()
	now := d.now()
	d.sweepLocked(now)
	c, ok := d.byID[r.PostForm.Get("challenge")]
	valid := ok && d.liveLocked(c, basketSignedIn, now) && basketBrowserMatches(r, c) &&
		subtle.ConstantTimeCompare(sum[:], c.csrfHash[:]) == 1
	if valid {
		// Used once, whatever happens next: a double click or a replayed
		// form finds nothing.
		d.dropLocked(c.id, c)
	}
	d.mu.Unlock()
	setBasketCookie(w, "", -1)
	if !valid {
		d.failed(w, http.StatusBadRequest, "This approval page is unknown, expired, already used, or was opened in another browser.")
		return
	}
	// Resolved and read again: a principal disabled, a membership lost or a
	// basket revised since the sign-in decides now.
	user, err := d.signedInUser(r.Context(), c.identity)
	if err != nil {
		h.auditBasketPage(r, nil, c.identity, c.approvalRef, "denied", "sign-in refused")
		d.failed(w, http.StatusNotFound, basketNotFoundMessage)
		return
	}
	shown, ref := h.readBasketApproval(r, d, user, c.approvalRef)
	if ref != nil {
		h.auditBasketPage(r, user, c.identity, c.approvalRef, "denied", ref.audit)
		d.failed(w, ref.status, ref.msg)
		return
	}
	if shown.superseded() || shown.binding() != c.shown {
		h.auditBasketPage(r, user, c.identity, c.approvalRef, "denied", "basket changed since it was shown")
		d.failed(w, http.StatusConflict, "The basket or its approval changed after you were shown it; nothing was decided.")
		return
	}
	if !shown.decidable(d.now()) {
		h.auditBasketPage(r, user, c.identity, c.approvalRef, "denied", "not pending")
		d.failed(w, http.StatusConflict, "This approval is already "+basketStateWord(shown.state)+" or has expired; nothing was decided.")
		return
	}
	body := map[string]any{"decision": workitems.DecisionDeny, "reason": basketReasonReject}
	if decision == "approve" {
		body = map[string]any{"decision": workitems.DecisionApprove, "reason": basketReasonApprove, "binding": c.shown}
	}
	status, resp := h.callAs(r, user, http.MethodPost, "id", c.approvalRef, body, h.DecideActionApproval)
	if status != http.StatusOK {
		h.auditBasketPage(r, user, c.identity, c.approvalRef, "failed", decision+": "+errorText(resp))
		d.failed(w, status, "The "+decision+" was refused: "+errorText(resp)+".")
		return
	}
	var got struct {
		Approval struct {
			State string `json:"state"`
		} `json:"approval"`
	}
	_ = json.Unmarshal(resp, &got)
	h.auditBasketPage(r, user, c.identity, c.approvalRef, "succeeded", decision)
	title := "Basket approved"
	if decision == "reject" {
		title = "Basket rejected"
	}
	shown.state = got.Approval.State
	d.renderPage(w, http.StatusOK, title, append(shown.lines(c.identity.Display),
		"The assistant that asked can now read this result. Nothing was ordered or paid."), basketPageData{Basket: shown.table})
}

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
