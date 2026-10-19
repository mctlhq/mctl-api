package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

type SignupOptions struct {
	Store        *principals.Store
	SiteCall     func(context.Context, string, string, []byte) ([]byte, error)
	Cohort       map[string]bool
	GitHubClient *http.Client
	GitHubURL    string
}

var signupID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var signupLogin = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

func (h *Handlers) signupAdmin(w http.ResponseWriter, r *http.Request) bool {
	u := auth.UserFromContext(r.Context())
	delegated := false
	if u != nil {
		_, delegated = u.DelegatingAgent()
	}
	if u == nil || delegated || !isHumanAdmin(u) || u.IsAgent() || u.ViaPrincipalID() != "" || u.PrincipalID() == "" {
		writeError(w, 403, "direct human platform administrator required")
		return false
	}
	if h.opts.Signup == nil || h.opts.Signup.Store == nil || h.opts.Signup.SiteCall == nil {
		writeError(w, 503, "signup administration unavailable")
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}
func signupDecode(r *http.Request, value any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return errors.New("invalid signup payload")
	}
	return json.Unmarshal(raw, value)
}
func validSignup(r principals.SignupRequest) bool {
	_, err := uuid.Parse(r.ID)
	return err == nil && r.CreatedAt.Before(time.Now().Add(time.Minute)) && r.CreatedAt.After(time.Now().Add(-90*24*time.Hour)) && len(r.Name) > 0 && len(r.Name) <= 100 && len(r.Email) <= 254 && strings.Contains(r.Email, "@") && !strings.ContainsAny(r.Email, "\r\n") && len(r.Project) > 0 && len(r.Project) <= 1000 && (r.GitHub == "" || signupLogin.MatchString(r.GitHub))
}
func (h *Handlers) importSignup(ctx context.Context, id string) (principals.SignupDecision, error) {
	var r principals.SignupRequest
	raw, err := h.opts.Signup.SiteCall(ctx, "GET", "/api/internal/invitations/requests/"+url.PathEscape(id), nil)
	if err != nil {
		return principals.SignupDecision{}, err
	}
	if err = json.Unmarshal(raw, &r); err != nil || r.ID != id || !validSignup(r) {
		return principals.SignupDecision{}, errors.New("invalid invitation source")
	}
	if err := h.opts.Signup.Store.ImportSignup(ctx, r); err != nil {
		return principals.SignupDecision{}, err
	}
	return h.opts.Signup.Store.Signup(ctx, id)
}
func (h *Handlers) ListSignupRequests(w http.ResponseWriter, r *http.Request) {
	if !h.signupAdmin(w, r) {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 4096 {
		writeError(w, 400, "invalid cursor")
		return
	}
	raw, err := h.opts.Signup.SiteCall(r.Context(), "GET", "/api/internal/invitations/requests?cursor="+url.QueryEscape(cursor), nil)
	var page struct {
		Requests []principals.SignupRequest `json:"requests"`
		Cursor   string                     `json:"cursor"`
		Complete *bool                      `json:"complete"`
	}
	if err != nil || json.Unmarshal(raw, &page) != nil || page.Complete == nil || len(page.Requests) > 100 || len(page.Cursor) > 4096 || (!*page.Complete && page.Cursor == "") {
		writeError(w, 503, "invitation listing could not be observed")
		return
	}
	result := []principals.SignupDecision{}
	for _, item := range page.Requests {
		if !validSignup(item) || h.opts.Signup.Store.ImportSignup(r.Context(), item) != nil {
			writeError(w, 503, "invitation record could not be observed")
			return
		}
		d, e := h.opts.Signup.Store.Signup(r.Context(), item.ID)
		if e != nil {
			writeError(w, 503, "invitation decision unavailable")
			return
		}
		result = append(result, d)
	}
	writeJSON(w, 200, map[string]any{"requests": result, "cursor": page.Cursor, "complete": *page.Complete})
}
func (h *Handlers) GetSignupCapacity(w http.ResponseWriter, r *http.Request) {
	if !h.signupAdmin(w, r) {
		return
	}
	c, err := h.opts.Signup.Store.SignupCapacity(r.Context())
	if err != nil {
		writeError(w, 503, "capacity unavailable")
		return
	}
	writeJSON(w, 200, c)
}
func (h *Handlers) SetSignupCapacity(w http.ResponseWriter, r *http.Request) {
	if !h.signupAdmin(w, r) {
		return
	}
	var b struct {
		Slots   *int   `json:"slots"`
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if signupDecode(r, &b) != nil || b.Slots == nil || *b.Slots < 0 || *b.Slots > 1000 || b.Confirm != "yes" || len(strings.TrimSpace(b.Reason)) < 10 || len(b.Reason) > 1000 {
		writeError(w, 400, "confirmed capacity and resource assessment reason required")
		return
	}
	u := auth.UserFromContext(r.Context())
	err := h.opts.Signup.Store.SetSignupCapacity(r.Context(), *b.Slots, u.PrincipalID(), b.Reason)
	if errors.Is(err, principals.ErrSignupCapacity) {
		writeError(w, 409, "capacity cannot fall below reserved workspaces")
		return
	}
	if err != nil {
		writeError(w, 503, "capacity update failed")
		return
	}
	h.logAudit(r, audit.Entry{UserID: u.ID, Operation: "signup.capacity.set", Status: "succeeded", RiskLevel: "high", Parameters: map[string]string{"slots": strconv.Itoa(*b.Slots), "reason": b.Reason}})
	h.GetSignupCapacity(w, r)
}
func (h *Handlers) DecideSignupRequest(w http.ResponseWriter, r *http.Request) {
	if !h.signupAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, 400, "invalid invitation id")
		return
	}
	var b struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Confirm  string `json:"confirm"`
		GitHub   string `json:"github"`
	}
	if signupDecode(r, &b) != nil || (b.Decision != "approved" && b.Decision != "rejected") || b.Confirm != "yes" || len(strings.TrimSpace(b.Reason)) < 3 || len(b.Reason) > 1000 {
		writeError(w, 400, "confirmed decision and reason required")
		return
	}
	d, err := h.importSignup(r.Context(), id)
	if err != nil {
		writeError(w, 503, "saved request could not be verified")
		return
	}
	githubID, login := "", ""
	if b.Decision == "approved" {
		login = d.Request.GitHub
		if login == "" {
			login = b.GitHub
		}
		if !signupLogin.MatchString(login) {
			writeError(w, 400, "GitHub login required for identity-bound invitation")
			return
		}
		githubID, login, err = h.resolveSignupGitHub(r.Context(), login)
		if err != nil {
			writeError(w, 503, "GitHub identity could not be verified")
			return
		}
		if h.opts.Signup.Cohort[githubID] {
			writeError(w, 409, "GitHub identity already belongs to the existing pilot cohort")
			return
		}
	}
	u := auth.UserFromContext(r.Context())
	d, err = h.opts.Signup.Store.DecideSignup(r.Context(), id, b.Decision, githubID, login, u.PrincipalID(), b.Reason)
	if errors.Is(err, principals.ErrSignupCapacity) {
		writeError(w, 409, "signup_capacity_exhausted")
		return
	}
	if errors.Is(err, principals.ErrSignupConflict) {
		writeError(w, 409, "invitation already decided or identity reserved")
		return
	}
	if err != nil {
		writeError(w, 503, "decision could not be saved")
		return
	}
	h.logAudit(r, audit.Entry{UserID: u.ID, Operation: "signup.request." + b.Decision, Status: "succeeded", RiskLevel: "high", Parameters: map[string]string{"request_id": id, "github_id": githubID}})
	writeJSON(w, 200, d)
}
func (h *Handlers) resolveSignupGitHub(ctx context.Context, login string) (string, string, error) {
	base := h.opts.Signup.GitHubURL
	if base == "" {
		base = "https://api.github.com"
	}
	client := h.opts.Signup.GitHubClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/users/"+url.PathEscape(login), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MCTL-signup-administration")
	res, err := client.Do(req)
	if err != nil {
		return "", "", errors.New("GitHub lookup failed")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		return "", "", errors.New("GitHub lookup refused")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32769))
	if err != nil || len(raw) > 32768 {
		return "", "", errors.New("GitHub response invalid")
	}
	var body struct {
		ID    json.Number `json:"id"`
		Login string      `json:"login"`
	}
	if json.Unmarshal(raw, &body) != nil || !signupID.MatchString(string(body.ID)) || !strings.EqualFold(body.Login, login) {
		return "", "", errors.New("GitHub response invalid")
	}
	return string(body.ID), body.Login, nil
}

// The portal may claim only the reservation tied to an active GitHub identity.
// It is not allowed to approve a request or change capacity.
func (h *Handlers) ClaimSignup(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil || u.ID != "surface:portal" {
		writeError(w, 403, "portal surface required")
		return
	}
	o := h.opts.Signup
	if o == nil || o.Store == nil {
		writeError(w, 503, "signup admission unavailable")
		return
	}
	var b struct {
		Principal   string `json:"principal_id"`
		Tenant      string `json:"tenant"`
		Memory      string `json:"memory"`
		CPU         string `json:"cpu"`
		MemoryLimit string `json:"memory_limit"`
		CPULimit    string `json:"cpu_limit"`
		Pods        string `json:"pods"`
		PVCs        string `json:"pvcs"`
		Services    string `json:"services"`
	}
	if signupDecode(r, &b) != nil || !auth.ValidPrincipalID(b.Principal) || !customerDeletionTenantName.MatchString(b.Tenant) {
		writeError(w, 400, "invalid signup claim")
		return
	}
	if r.Header.Get(SurfaceActorHeader) != "principal:"+b.Principal {
		writeError(w, 403, "claim actor must match the customer principal")
		return
	}
	if status, message := h.claimSignupPrincipal(r.Context(), b.Principal, b.Tenant, b.Memory, b.CPU, b.MemoryLimit, b.CPULimit, b.Pods, b.PVCs, b.Services); status != 0 {
		writeError(w, status, message)
		return
	}
	writeJSON(w, 200, map[string]bool{"admitted": true})
}

func (h *Handlers) claimSignupPrincipal(ctx context.Context, pid, tenant, memory, cpu, memoryLimit, cpuLimit, pods, pvcs, services string) (int, string) {
	o := h.opts.Signup
	if o == nil || o.Store == nil {
		return 503, "signup admission unavailable"
	}
	principal, err := o.Store.Get(ctx, pid)
	if err != nil {
		return 503, "principal unreadable"
	}
	if principal == nil || principal.Status != principals.StatusActive || principal.Kind != auth.KindHuman {
		return 403, "active customer principal required"
	}
	identities, err := o.Store.Identities(ctx, pid)
	if err != nil {
		return 503, "identity unreadable"
	}
	githubID := ""
	for n := range identities {
		i := &identities[n]
		if i.Provider == "github" && i.RevokedAt == nil {
			if githubID != "" && githubID != i.Subject {
				return 409, "ambiguous GitHub identity"
			}
			githubID = i.Subject
		}
	}
	if !signupID.MatchString(githubID) {
		return 403, "GitHub customer identity required"
	}
	if o.Cohort[githubID] {
		return 0, ""
	}
	if (memory != "2Gi" && memory != "1280Mi") || (cpu != "1" && cpu != "500m") || memoryLimit != "3Gi" || cpuLimit != "2" || !signupBound(pods, 10) || !signupBound(pvcs, 5) || !signupBound(services, 10) {
		return 409, "workspace profile differs from reserved signup capacity"
	}
	err = o.Store.ClaimSignup(ctx, githubID, tenant, pid)
	if errors.Is(err, principals.ErrSignupNotAllowed) || errors.Is(err, principals.ErrSignupConflict) {
		return 409, "workspace reservation unavailable"
	}
	if err != nil {
		return 503, "workspace admission unreadable"
	}
	return 0, ""
}

// RunSignupDeliveries retries only durable decisions, with leases and stable
// provider idempotency. A delivery older than 23h stays pending for reconciliation.
func (o *SignupOptions) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		for n := 0; n < 10; n++ {
			lease := uuid.NewString()
			d, err := o.Store.LeaseSignupDelivery(ctx, lease)
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				slog.Error("signup: delivery observation failed")
				break
			}
			if d.Status == "claimed" {
				d.Status = "approved"
			}
			raw, _ := json.Marshal(d)
			data, err := o.SiteCall(ctx, "POST", "/api/internal/invitations/decision", raw)
			if err != nil {
				slog.Warn("signup: decision delivery pending", "request_id", d.Request.ID)
				continue
			}
			var receipt struct {
				ID         string `json:"id"`
				DeliveryID string `json:"delivery_id"`
			}
			if json.Unmarshal(data, &receipt) != nil || receipt.ID != d.Request.ID || receipt.DeliveryID == "" {
				slog.Warn("signup: malformed delivery receipt", "request_id", d.Request.ID)
				continue
			}
			if err = o.Store.AckSignupDelivery(ctx, d.Request.ID, lease, receipt.DeliveryID); err != nil {
				slog.Warn("signup: delivery acknowledgement pending", "request_id", d.Request.ID)
			}
		}
		if err := o.Store.CleanupSignupPII(ctx); err != nil {
			slog.Warn("signup: retention sweep failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func signupBound(value string, maximum int) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n > 0 && n <= maximum
}
