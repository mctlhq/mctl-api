package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mctlhq/mctl-api/internal/audit"
	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/gitops"
	"github.com/mctlhq/mctl-api/internal/operations"
	"github.com/mctlhq/mctl-api/internal/principals"
)

type SignupOptions struct {
	PublicFlow   bool
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
	if identity, proven := u.Identity(); !proven || identity.Kind != auth.KindHuman {
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
	return err == nil && r.CreatedAt.Before(time.Now().Add(time.Minute)) && r.CreatedAt.After(time.Now().Add(-90*24*time.Hour)) && len(r.Name) > 0 && utf8.RuneCountInString(r.Name) <= 100 && len(r.Email) <= 254 && strings.Contains(r.Email, "@") && !strings.ContainsAny(r.Email, "\r\n") && len(r.Project) > 0 && utf8.RuneCountInString(r.Project) <= 1000 && (r.GitHub == "" || signupLogin.MatchString(r.GitHub))
}
func (h *Handlers) importSignup(ctx context.Context, id string) (principals.SignupDecision, error) {
	var r principals.SignupRequest
	raw, err := h.opts.Signup.SiteCall(ctx, "GET", "/api/internal/invitations/requests/"+url.PathEscape(id), nil)
	if err != nil {
		return principals.SignupDecision{}, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return principals.SignupDecision{}, err
	}
	if r.ID != id || !validSignup(r) {
		return principals.SignupDecision{}, errSignupInvalidResponse
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
	type issue struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	var page struct {
		Requests          []json.RawMessage `json:"requests"`
		Issues            []issue           `json:"issues"`
		Cursor            string            `json:"cursor"`
		Complete          *bool             `json:"complete"`
		TraversalComplete *bool             `json:"traversal_complete"`
		Observation       string            `json:"observation"`
	}
	if err != nil {
		signupFailure(r.Context(), "request_list_read", err)
		writeError(w, 503, "invitation listing could not be observed")
		return
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		signupFailure(r.Context(), "request_list_decode", err)
		writeError(w, 503, "invitation listing could not be observed")
		return
	}
	if page.Requests == nil || (page.Complete == nil && page.TraversalComplete == nil) || len(page.Requests)+len(page.Issues) > 100 || len(page.Cursor) > 4096 {
		signupFailure(r.Context(), "request_list_contract", errSignupInvalidResponse)
		writeError(w, 503, "invitation listing could not be observed")
		return
	}
	issues := []issue{}
	traversal := page.TraversalComplete
	if traversal == nil {
		traversal = page.Complete
		issues = append(issues, issue{ID: "unknown", Error: "legacy_traversal_metadata"})
	}
	if !*traversal && (page.Cursor == "" || page.Cursor == cursor) {
		signupFailure(r.Context(), "request_list_pagination", errSignupInvalidResponse)
		writeError(w, 503, "invitation pagination could not be observed")
		return
	}
	if page.Issues == nil {
		issues = append(issues, issue{ID: "unknown", Error: "issue_inventory_unavailable"})
	}
	if page.Complete == nil {
		issues = append(issues, issue{ID: "unknown", Error: "completion_state_unavailable"})
	} else if *page.Complete != (*traversal && len(page.Issues) == 0) {
		issues = append(issues, issue{ID: "unknown", Error: "completion_state_conflict"})
	}
	for _, item := range page.Issues {
		if _, err := uuid.Parse(item.ID); err != nil {
			item.ID = "unknown"
		}
		if item.Error != "record_unreadable" {
			item.Error = "bridge_record_issue"
		}
		issues = append(issues, item)
	}
	if page.Observation != "" && page.Observation != "complete" && len(issues) == 0 {
		issues = append(issues, issue{ID: "unknown", Error: "bridge_observation_partial"})
	}
	result := []principals.SignupDecision{}
	expired := []string{}
	seen := map[string]bool{}
	for _, rawItem := range page.Requests {
		var item principals.SignupRequest
		if err := json.Unmarshal(rawItem, &item); err != nil {
			signupFailure(r.Context(), "request_record_decode", err)
			issues = append(issues, issue{ID: "unknown", Error: "invalid_record"})
			continue
		}
		if _, err := uuid.Parse(item.ID); err != nil {
			issues = append(issues, issue{ID: "unknown", Error: "invalid_record"})
			continue
		}
		if seen[item.ID] {
			issues = append(issues, issue{ID: item.ID, Error: "duplicate_record"})
			continue
		}
		seen[item.ID] = true
		if !item.CreatedAt.IsZero() && item.CreatedAt.Before(time.Now().Add(-90*24*time.Hour)) {
			expired = append(expired, item.ID)
			continue
		}
		if !validSignup(item) {
			signupFailure(r.Context(), "request_record_validate", errSignupInvalidResponse, "request_id", item.ID)
			issues = append(issues, issue{ID: item.ID, Error: "invalid_record"})
			continue
		}
		if err := h.opts.Signup.Store.ImportSignup(r.Context(), item); err != nil {
			signupFailure(r.Context(), "request_store_import", err, "request_id", item.ID)
			issues = append(issues, issue{ID: item.ID, Error: "record_unreadable"})
			continue
		}
		d, err := h.opts.Signup.Store.Signup(r.Context(), item.ID)
		if err != nil {
			signupFailure(r.Context(), "request_decision_read", err, "request_id", item.ID)
			issues = append(issues, issue{ID: item.ID, Error: "decision_unreadable"})
			continue
		}
		result = append(result, d)
	}
	observation := "complete"
	if len(issues) > 0 {
		observation = "partial"
	}
	writeJSON(w, 200, map[string]any{"requests": result, "issues": issues, "expired": expired, "cursor": page.Cursor, "traversal_complete": *traversal, "complete": *traversal && len(issues) == 0, "observation": observation})

}
func (h *Handlers) GetSignupCapacity(w http.ResponseWriter, r *http.Request) {
	if !h.signupAdmin(w, r) {
		return
	}
	c, err := h.opts.Signup.Store.SignupCapacity(r.Context())
	if err != nil {
		signupFailure(r.Context(), "capacity_read", err)
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
		signupFailure(r.Context(), "capacity_update", err)
		writeError(w, 503, "capacity update failed")
		return
	}
	h.logAudit(r, audit.Entry{UserID: u.ID, Operation: "signup.capacity.set", Status: "succeeded", RiskLevel: "high", Parameters: map[string]string{"slots": strconv.Itoa(*b.Slots), "reason": b.Reason}})
	h.GetSignupCapacity(w, r)
}

// Inspect all tenants before returning a membership result: an unreadable later
// tenant outranks a known match. Legacy login and team grants also count.
func (h *Handlers) signupExistingMembership(pid, login string) (bool, error) {
	strict, ok := h.opts.GitReader.(interface {
		ListTenantsStrict() ([]gitops.Tenant, error)
	})
	if !ok {
		return false, errors.New("strict tenant reader unavailable")
	}
	tenants, err := strict.ListTenantsStrict()
	if err != nil {
		return false, err
	}
	found := false
	for i := range tenants {
		t := &tenants[i]
		if err := t.PrincipalKeysErr(); err != nil {
			return false, err
		}
		all := append([]gitops.TenantMember{}, t.Members...)
		for _, team := range t.Teams {
			all = append(all, team.Members...)
		}
		for _, m := range all {
			if (pid != "" && m.PrincipalID == pid) || (login != "" && strings.EqualFold(m.UserID, login)) {
				found = true
			}
		}
	}
	return found, nil
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
		signupFailure(r.Context(), "request_import", err, "request_id", id)
		writeError(w, 503, "saved request could not be verified")
		return
	}
	githubID, login := "", ""
	if b.Decision == "approved" {
		login = d.Request.GitHub
		if b.GitHub != "" {
			login = b.GitHub
		}
		if !signupLogin.MatchString(login) {
			writeError(w, 400, "GitHub login required for identity-bound invitation")
			return
		}
		githubID, login, err = h.resolveSignupGitHub(r.Context(), login)
		if err != nil {
			signupFailure(r.Context(), "github_lookup", err, "request_id", id)
			writeError(w, 503, "GitHub identity could not be verified")
			return
		}
		if h.opts.Signup.Cohort[githubID] {
			writeError(w, 409, "GitHub identity already belongs to the existing pilot cohort")
			return
		}
		existing, revoked, err := h.opts.Signup.Store.LookupIdentity(r.Context(), auth.ProviderGitHub, "", githubID)
		if err != nil && !errors.Is(err, principals.ErrNotFound) {
			signupFailure(r.Context(), "existing_identity_read", err, "request_id", id)
			writeError(w, 503, "existing identity unreadable")
			return
		}
		pid := ""
		if existing != nil {
			if revoked || existing.Status != principals.StatusActive {
				writeError(w, 409, "GitHub identity is not active")
				return
			}
			pid = existing.ID
		}
		member, err := h.signupExistingMembership(pid, login)
		if err != nil {
			signupFailure(r.Context(), "existing_workspace_read", err, "request_id", id)
			writeError(w, 503, "existing workspace ownership unreadable")
			return
		}
		if member {
			writeError(w, 409, "GitHub identity already belongs to an existing workspace")
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
		signupFailure(r.Context(), "decision_save", err, "request_id", id)
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
		return "", "", &signupProviderError{stage: "request_build", cause: err}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "MCTL-signup-administration")
	res, err := client.Do(req)
	if err != nil {
		return "", "", &signupProviderError{stage: "request", cause: err}
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 {
		return "", "", &signupProviderError{stage: "response", status: res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32769))
	if err != nil || len(raw) > 32768 {
		return "", "", &signupProviderError{stage: "response_decode", status: res.StatusCode, cause: errSignupInvalidResponse}
	}
	var body struct {
		ID    json.Number `json:"id"`
		Login string      `json:"login"`
	}
	if json.Unmarshal(raw, &body) != nil || !signupID.MatchString(string(body.ID)) || !strings.EqualFold(body.Login, login) {
		return "", "", &signupProviderError{stage: "response_decode", status: res.StatusCode, cause: errSignupInvalidResponse}
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
		Profile     string `json:"workspace_profile"`
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
	if operations.IsReservedTenantName(b.Tenant) {
		writeError(w, 400, "workspace name is reserved")
		return
	}
	if h.opts.GitReader == nil {
		writeError(w, 503, "workspace existence unavailable")
		return
	}
	exists, err := h.opts.GitReader.TenantExists(b.Tenant)
	if err != nil {
		signupFailure(r.Context(), "tenant_existence", err, "tenant", b.Tenant)
		writeError(w, 503, "workspace existence unreadable")
		return
	}
	if exists {
		bound, err := o.Store.SignupClaimMatches(r.Context(), b.Principal, b.Tenant)
		if err != nil {
			signupFailure(r.Context(), "claim_retry_read", err, "tenant", b.Tenant)
			writeError(w, 503, "workspace reservation unreadable")
			return
		}
		if !bound {
			writeError(w, 409, "workspace already exists")
			return
		}
		tenant, err := h.opts.GitReader.GetTenant(b.Tenant)
		if err != nil || tenant == nil {
			if err == nil {
				err = errSignupInvalidResponse
			}
			signupFailure(r.Context(), "retry_owner_read", err, "tenant", b.Tenant)
			writeError(w, 503, "workspace ownership unreadable")
			return
		}
		owned := false
		for n := range tenant.Members {
			member := &tenant.Members[n]
			if member.PrincipalID == b.Principal && member.Role == "owner" {
				owned = true
			}
		}
		if !owned {
			writeError(w, 409, "existing workspace belongs to another principal")
			return
		}
	}
	if status, message := h.checkTenantNameCollision(b.Tenant); status != 0 {
		writeError(w, status, message)
		return
	}
	if !h.guardCustomerTenantCreation(w, r, operations.Operation{Name: "create-tenant"}, map[string]string{"tenant_name": b.Tenant}) {
		return
	}
	if status, message := h.claimSignupPrincipal(r.Context(), b.Principal, b.Tenant, b.Memory, b.CPU, b.MemoryLimit, b.CPULimit, b.Pods, b.PVCs, b.Services, b.Profile); status != 0 {
		h.logAudit(r, audit.Entry{UserID: u.ID, Operation: "signup.claim", Status: "denied", RiskLevel: "medium", Message: message, Parameters: map[string]string{"principal_id": b.Principal, "tenant": b.Tenant}})
		writeError(w, status, message)
		return
	}
	writeJSON(w, 200, map[string]bool{"admitted": true})
}

func (h *Handlers) claimSignupPrincipal(ctx context.Context, pid, tenant, memory, cpu, memoryLimit, cpuLimit, pods, pvcs, services, profile string) (int, string) {
	o := h.opts.Signup
	if o == nil || o.Store == nil {
		return 503, "signup admission unavailable"
	}
	principal, err := o.Store.Get(ctx, pid)
	if errors.Is(err, principals.ErrNotFound) {
		return 403, "active customer principal required"
	}
	if err != nil {
		signupFailure(ctx, "claim_principal_read", err, "principal_id", pid)
		return 503, "principal unreadable"
	}
	if principal == nil || principal.Status != principals.StatusActive || principal.Kind != auth.KindHuman {
		return 403, "active customer principal required"
	}
	identities, err := o.Store.Identities(ctx, pid)
	if err != nil {
		signupFailure(ctx, "claim_identity_read", err, "principal_id", pid)
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
	if profile != "starter" || memory != "512Mi" || cpu != "500m" || memoryLimit != "1Gi" || cpuLimit != "2" || !signupBound(pods, 5) || !signupBound(pvcs, 1) || !signupBound(services, 5) {
		return 409, "workspace profile exceeds funded admission: use workspace_profile=starter (production 500m/512Mi, limits 2 CPU/1Gi, preview 100m/256Mi; PVC storage 10Gi production, no persistent preview disk)"
	}

	if o.PublicFlow {
		err = o.Store.ClaimPublicSignup(ctx, githubID, tenant, pid)
	} else {
		err = o.Store.ClaimSignup(ctx, githubID, tenant, pid)
	}
	if errors.Is(err, principals.ErrSignupCapacity) {
		return 409, "signup_capacity_exhausted"
	}
	if errors.Is(err, principals.ErrSignupNotAllowed) || errors.Is(err, principals.ErrSignupConflict) {
		return 409, "workspace reservation unavailable"
	}
	if err != nil {
		signupFailure(ctx, "claim_commit", err, "principal_id", pid, "tenant", tenant)
		return 503, "workspace admission unreadable"
	}
	return 0, ""
}

// Run retries only durable decisions, with leases and stable
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
				signupFailure(ctx, "delivery_lease_read", err)
				break
			}
			if d.Status == "claimed" {
				d.Status = "approved"
			}
			raw, err := json.Marshal(d)
			if err != nil {
				signupFailure(ctx, "delivery_encode", err, "request_id", d.Request.ID)
				continue
			}
			data, err := o.SiteCall(ctx, "POST", "/api/internal/invitations/decision", raw)
			if err != nil {
				signupFailure(ctx, "delivery_bridge", err, "request_id", d.Request.ID)
				continue
			}
			var receipt struct {
				ID         string `json:"id"`
				DeliveryID string `json:"delivery_id"`
			}
			if err := json.Unmarshal(data, &receipt); err != nil {
				signupFailure(ctx, "delivery_receipt_decode", err, "request_id", d.Request.ID)
				continue
			}
			if receipt.ID != d.Request.ID || receipt.DeliveryID == "" {
				signupFailure(ctx, "delivery_receipt_contract", errSignupInvalidResponse, "request_id", d.Request.ID)
				continue
			}
			if err = o.Store.AckSignupDelivery(ctx, d.Request.ID, lease, receipt.DeliveryID); err != nil {
				signupFailure(ctx, "delivery_acknowledge", err, "request_id", d.Request.ID)
			}
		}
		if err := o.Store.CleanupSignupPII(ctx); err != nil {
			signupFailure(ctx, "retention_sweep", err)
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
