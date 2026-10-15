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

// Package zitadelhook is the identity hook for the ZITADEL org "customers"
// (mctl-web site onboarding, stage B1). ZITADEL Actions v2 calls three
// restCall targets here:
//
//   - Intent: a response execution on
//     zitadel.user.v2.UserService/RetrieveIdentityProviderIntent. For the
//     customers GitHub IdP it fetches the person's primary verified email
//     from GitHub, refuses reserved and non-user logins, and replaces the
//     user action with a fully specified createUser (organization set
//     explicitly) or updateUser. Interrupts on error.
//   - CreateGate: a request execution on every user-creating method. A user
//     can enter "customers" only through v2 CreateUser called by the Login V2
//     service user with exactly the shape Intent produces; every other path
//     into the org is refused. Other orgs pass through. Interrupts on error.
//   - TokenClaims: the preuserinfo and preaccesstoken functions. Appends
//     mctl:* claims for listed clients only. Does NOT interrupt on error:
//     a token without mctl:github_id is refused by mctl-api (C0), so a hook
//     outage never blocks admin tokens or burns refresh tokens (B0 item 5).
//
// Every decision here fails closed: an unreadable payload, an unreachable
// GitHub or gitops checkout, or an unknown method refuses, never allows.
package zitadelhook

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/gitops"
)

// Metadata keys written on customers accounts.
const (
	MetaGitHubID    = "github_id"
	MetaGitHubLogin = "github_login"
)

// Claims appended to tokens of customers accounts.
const (
	ClaimOrg         = "mctl:org"
	ClaimIdP         = "mctl:idp"
	ClaimGitHubID    = "mctl:github_id"
	ClaimGitHubLogin = "mctl:github_login"
	ClaimRefused     = "mctl:refused"
)

// Refusal reasons put into ClaimRefused.
const (
	RefusedNoGitHubIdentity = "no_github_identity"
	RefusedLoginReserved    = "login_reserved"
)

// Full gRPC method names of the user-creating methods in ZITADEL v4.19.2.
// The list is the inventory the CreateGate execution must be bound to; it is
// re-checked on every ZITADEL upgrade (docs/zitadel-identity-hook.md).
const (
	MethodV2CreateUser        = "/zitadel.user.v2.UserService/CreateUser"
	MethodV2AddHumanUser      = "/zitadel.user.v2.UserService/AddHumanUser"
	MethodV2BetaAddHumanUser  = "/zitadel.user.v2beta.UserService/AddHumanUser"
	MethodV3AlphaCreateUser   = "/zitadel.resources.user.v3alpha.ZITADELUsers/CreateUser"
	MethodMgmtAddHumanUser    = "/zitadel.management.v1.ManagementService/AddHumanUser"
	MethodMgmtImportHumanUser = "/zitadel.management.v1.ManagementService/ImportHumanUser"
	MethodMgmtAddMachineUser  = "/zitadel.management.v1.ManagementService/AddMachineUser"
	MethodAdminImportData     = "/zitadel.admin.v1.AdminService/ImportData"
	// Linking an IdP to an existing user does not create one, but a GitHub
	// link added to an arbitrary user would let a GitHub account sign in as
	// that user, so these are gated as well. Management v1 has no
	// add-link RPC in v4.19.2.
	MethodV2AddIDPLink                     = "/zitadel.user.v2.UserService/AddIDPLink"
	MethodV2BetaAddIDPLink                 = "/zitadel.user.v2beta.UserService/AddIDPLink"
	MethodV3AlphaAddIDPAuthenticator       = "/zitadel.resources.user.v3alpha.ZITADELUsers/AddIDPAuthenticator"
	MethodIntentRetrieve                   = "/zitadel.user.v2.UserService/RetrieveIdentityProviderIntent"
	functionPreUserinfo                    = "preuserinfo"
	functionPreAccessToken                 = "preaccesstoken"
	defaultGitHubAPIURL                    = "https://api.github.com"
	defaultUsernameDomain                  = "mctl.ai"
	githubRequestTimeout                   = 5 * time.Second
	maxGitHubResponseBytes           int64 = 1 << 20
)

// GatedMethods is the method inventory the CreateGate execution is bound to.
// A request for any method outside this list is refused, so binding the gate
// to a method this code does not understand fails closed.
var GatedMethods = []string{
	MethodV2CreateUser,
	MethodV2AddHumanUser,
	MethodV2BetaAddHumanUser,
	MethodV3AlphaCreateUser,
	MethodMgmtAddHumanUser,
	MethodMgmtImportHumanUser,
	MethodMgmtAddMachineUser,
	MethodAdminImportData,
	MethodV2AddIDPLink,
	MethodV2BetaAddIDPLink,
	MethodV3AlphaAddIDPAuthenticator,
}

// githubLoginRE is GitHub's login syntax: alphanumerics and single inner
// hyphens, at most 39 characters.
var githubLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9]|-[A-Za-z0-9]){0,38}$`)

var digitsRE = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// Config is the hook's static configuration. Every ID is required; New
// refuses an incomplete config so a half-wired hook never runs.
type Config struct {
	// CustomersOrgID is the ZITADEL org ID of "customers".
	CustomersOrgID string
	// GitHubIdPID is the ID of the GitHub IdP configured on that org.
	GitHubIdPID string
	// LoginClientUserID is the user ID of the Login V2 service user, the
	// only caller allowed to create a customers account.
	LoginClientUserID string
	// UsernameDomain is the suffix of customers usernames (<login>@domain).
	UsernameDomain string
	// ClaimClientIDs lists the OIDC client IDs that receive mctl:* claims.
	ClaimClientIDs []string
	// ReservedLogins are GitHub logins that may never own a customers
	// account: admins (ADMIN_USERS) and service logins. Compared
	// case-insensitively.
	ReservedLogins []string
	// GitHubAPIURL overrides https://api.github.com (tests only).
	GitHubAPIURL string
}

// TenantLister reads tenant membership from the gitops checkout. A read
// failure is an error, never an empty list.
type TenantLister interface {
	ListTenantsStrict() ([]gitops.Tenant, error)
}

// Hook evaluates the three ZITADEL executions.
type Hook struct {
	cfg      Config
	reserved map[string]bool
	clients  map[string]bool
	tenants  TenantLister
	http     *http.Client
}

// New validates cfg and returns a Hook. tenants may not be nil: reserving
// existing tenant members' logins at creation is part of the contract.
func New(cfg Config, tenants TenantLister, client *http.Client) (*Hook, error) {
	var missing []string
	if cfg.CustomersOrgID == "" {
		missing = append(missing, "CustomersOrgID")
	}
	if cfg.GitHubIdPID == "" {
		missing = append(missing, "GitHubIdPID")
	}
	if cfg.LoginClientUserID == "" {
		missing = append(missing, "LoginClientUserID")
	}
	if len(cfg.ClaimClientIDs) == 0 {
		missing = append(missing, "ClaimClientIDs")
	}
	if tenants == nil {
		missing = append(missing, "TenantLister")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("zitadelhook: missing %s", strings.Join(missing, ", "))
	}
	if cfg.UsernameDomain == "" {
		cfg.UsernameDomain = defaultUsernameDomain
	}
	if cfg.GitHubAPIURL == "" {
		cfg.GitHubAPIURL = defaultGitHubAPIURL
	}
	if client == nil {
		client = &http.Client{Timeout: githubRequestTimeout}
	}
	h := &Hook{cfg: cfg, reserved: map[string]bool{}, clients: map[string]bool{}, tenants: tenants, http: client}
	for _, l := range cfg.ReservedLogins {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" {
			h.reserved[l] = true
		}
	}
	for _, c := range cfg.ClaimClientIDs {
		if c = strings.TrimSpace(c); c != "" {
			h.clients[c] = true
		}
	}
	return h, nil
}

// Result is what a handler writes back to ZITADEL.
//
// Status 200 with an empty Body passes the call through unchanged. Status
// 200 with a Body replaces the request (request execution), the response
// (response execution) or carries the function response. A refusal is a
// 200 whose body sets forwardedStatusCode/forwardedErrorMessage, which
// ZITADEL turns into a gRPC error of that class (internal/execution in
// v4.19.2). Status 503 is an internal failure: ZITADEL reports
// Errors.Execution.Failed, which blocks only where the target interrupts.
type Result struct {
	Status int
	Body   []byte
	// Reason is a short machine-readable tag for logs; never secret.
	Reason string
}

func pass(reason string) Result { return Result{Status: http.StatusOK, Reason: reason} }

func refuse(code int, reason, message string) Result {
	body, _ := json.Marshal(map[string]any{
		"forwardedStatusCode":   code,
		"forwardedErrorMessage": message,
	})
	return Result{Status: http.StatusOK, Body: body, Reason: reason}
}

func failure(reason string) Result {
	return Result{Status: http.StatusServiceUnavailable, Body: []byte(`{"error":"identity hook unavailable"}`), Reason: reason}
}

func replace(reason string, v any) Result {
	body, err := json.Marshal(v)
	if err != nil {
		return failure("marshal_failed")
	}
	return Result{Status: http.StatusOK, Body: body, Reason: reason}
}

// Message shown to a person refused for lack of a verified email. Login V2
// only puts it into the failure page URL (B0 item 3); D1 covers the page.
const msgNoVerifiedEmail = "Verify an email address in GitHub, then sign in again."

const msgNotAllowed = "This GitHub account cannot create an MCTL account."

// ---------------------------------------------------------------- intent

type intentPayload struct {
	FullMethod string                     `json:"fullMethod"`
	Response   map[string]json.RawMessage `json:"response"`
}

type idpInformation struct {
	OAuth *struct {
		AccessToken string `json:"accessToken"`
	} `json:"oauth"`
	IDPID          string         `json:"idpId"`
	UserID         string         `json:"userId"`
	UserName       string         `json:"userName"`
	RawInformation map[string]any `json:"rawInformation"`
}

// Intent handles the RetrieveIdentityProviderIntent response execution.
func (h *Hook) Intent(ctx context.Context, body []byte) Result {
	var p intentPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Response == nil {
		return failure("intent_unparsable")
	}
	if p.FullMethod != MethodIntentRetrieve {
		return failure("intent_wrong_method")
	}
	rawInfo, ok := p.Response["idpInformation"]
	if !ok {
		return failure("intent_no_idp_information")
	}
	var info idpInformation
	if err := json.Unmarshal(rawInfo, &info); err != nil {
		return failure("intent_unparsable_idp_information")
	}
	if info.IDPID != h.cfg.GitHubIdPID {
		return pass("intent_other_idp")
	}
	if !digitsRE.MatchString(info.UserID) || !githubLoginRE.MatchString(info.UserName) {
		return refuse(http.StatusForbidden, "intent_bad_github_identity", msgNotAllowed)
	}
	// GitHub's /user body always carries type, id and login. Each must be
	// present and agree with what ZITADEL projected; an absent field is not
	// a pass.
	if t, _ := info.RawInformation["type"].(string); t != "User" {
		return refuse(http.StatusForbidden, "intent_not_a_user", msgNotAllowed)
	}
	if rawID, ok := info.RawInformation["id"]; !ok || jsonNumberString(rawID) != info.UserID {
		return refuse(http.StatusForbidden, "intent_id_mismatch", msgNotAllowed)
	}
	if rawLogin, _ := info.RawInformation["login"].(string); !strings.EqualFold(rawLogin, info.UserName) {
		return refuse(http.StatusForbidden, "intent_login_mismatch", msgNotAllowed)
	}
	if info.OAuth == nil || info.OAuth.AccessToken == "" {
		return failure("intent_no_access_token")
	}

	login := info.UserName
	name, _ := info.RawInformation["name"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		name = login
	}

	var existingUserID string
	if raw, ok := p.Response["userId"]; ok {
		if err := json.Unmarshal(raw, &existingUserID); err != nil {
			return failure("intent_unparsable_user_id")
		}
	}

	// At creation the login is checked before GitHub is asked anything, so
	// a reserved login is always a 403, never a 503 from a GitHub outage.
	if existingUserID == "" {
		reserved, rErr := h.loginReservedAtCreation(login)
		if rErr != nil {
			return failure("intent_reserved_unreadable")
		}
		if reserved {
			return refuse(http.StatusForbidden, "intent_login_reserved", msgNotAllowed)
		}
	}

	email, err := h.primaryVerifiedEmail(ctx, info.OAuth.AccessToken)
	if err != nil && !errors.Is(err, errNoVerifiedEmail) {
		if existingUserID == "" {
			return failure("intent_github_emails_unavailable")
		}
		// An existing account does not need the address to sign in; a
		// GitHub outage keeps the stored one instead of locking everyone out.
	}

	resp := make(map[string]json.RawMessage, len(p.Response))
	for k, v := range p.Response {
		switch k {
		case "addHumanUser", "updateHumanUser", "createUser", "updateUser",
			"add_human_user", "update_human_user", "create_user", "update_user":
			// Replaced below: the hook alone decides the user action.
		default:
			resp[k] = v
		}
	}

	profile := map[string]any{"givenName": name, "familyName": "-", "displayName": name}
	if existingUserID != "" {
		update := map[string]any{
			"userId":   existingUserID,
			"metadata": []map[string]string{metadataEntry(MetaGitHubLogin, login)},
		}
		human := map[string]any{"profile": profile}
		if err == nil {
			// A person who later loses every verified address keeps the
			// stored one; the account is not rewritten to an unverified one.
			human["email"] = map[string]any{"email": email, "isVerified": true}
		}
		update["human"] = human
		raw, mErr := json.Marshal(update)
		if mErr != nil {
			return failure("marshal_failed")
		}
		resp["updateUser"] = raw
		return replace("intent_update", resp)
	}

	if err != nil {
		return refuse(http.StatusPreconditionFailed, "intent_no_verified_email", msgNoVerifiedEmail)
	}

	create := map[string]any{
		"organizationId": h.cfg.CustomersOrgID,
		"username":       h.username(login),
		"human": map[string]any{
			"profile": profile,
			"email":   map[string]any{"email": email, "isVerified": true},
			"idpLinks": []map[string]string{{
				"idpId":    h.cfg.GitHubIdPID,
				"userId":   info.UserID,
				"userName": login,
			}},
		},
		"metadata": []map[string]string{
			metadataEntry(MetaGitHubID, info.UserID),
			metadataEntry(MetaGitHubLogin, login),
		},
	}
	raw, mErr := json.Marshal(create)
	if mErr != nil {
		return failure("marshal_failed")
	}
	resp["createUser"] = raw
	return replace("intent_create", resp)
}

func (h *Hook) username(login string) string {
	return strings.ToLower(login) + "@" + h.cfg.UsernameDomain
}

func metadataEntry(key, value string) map[string]string {
	return map[string]string{"key": key, "value": base64.StdEncoding.EncodeToString([]byte(value))}
}

// jsonNumberString renders a decoded JSON number without an exponent, so a
// numeric id of 10+ digits compares as written.
func jsonNumberString(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case string:
		return n
	case json.Number:
		return n.String()
	default:
		return fmt.Sprint(v)
	}
}

var errNoVerifiedEmail = errors.New("no primary verified email")

// primaryVerifiedEmail returns the GitHub address that is both primary and
// verified. The public profile email is never used: ZITADEL's GitHub
// provider reports every address as verified (section 4 of the plan).
func (h *Hook) primaryVerifiedEmail(ctx context.Context, token string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, githubRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(h.cfg.GitHubAPIURL, "/")+"/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "mctl-api-zitadel-hook")
	resp, err := h.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github /user/emails: status %d", resp.StatusCode)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxGitHubResponseBytes))
	if err := dec.Decode(&emails); err != nil {
		return "", fmt.Errorf("github /user/emails: %w", err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified && validEmail(e.Email) {
			return e.Email, nil
		}
	}
	return "", errNoVerifiedEmail
}

func validEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n")
}

// loginReservedAtCreation reports whether a new customers account may not
// take login: an admin or service login, or the login of any member of any
// tenant in the gitops checkout. It is checked only when an account is
// created, never on later sign-ins or at token time, because a customer
// becomes a tenant member under their own login once their workspace exists.
func (h *Hook) loginReservedAtCreation(login string) (bool, error) {
	if h.reserved[strings.ToLower(login)] {
		return true, nil
	}
	tenants, err := h.tenants.ListTenantsStrict()
	if err != nil {
		return false, err
	}
	for i := range tenants {
		t := &tenants[i]
		if strings.EqualFold(t.Name, login) {
			// Not a member, but a login equal to a workspace name is kept
			// out to avoid confusing the two in support.
			return true, nil
		}
		for _, m := range t.Members {
			if strings.EqualFold(m.UserID, login) {
				return true, nil
			}
		}
		for _, team := range t.Teams {
			for _, m := range team.Members {
				if strings.EqualFold(m.UserID, login) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// ----------------------------------------------------------- create gate

type requestPayload struct {
	FullMethod string          `json:"fullMethod"`
	OrgID      string          `json:"orgID"`
	UserID     string          `json:"userID"`
	Request    json.RawMessage `json:"request"`
}

type createUserRequest struct {
	OrganizationID string `json:"organizationId"`
	Username       string `json:"username"`
	Human          *struct {
		Email *struct {
			Email      string `json:"email"`
			IsVerified bool   `json:"isVerified"`
		} `json:"email"`
		IDPLinks []struct {
			IDPID    string `json:"idpId"`
			UserID   string `json:"userId"`
			UserName string `json:"userName"`
		} `json:"idpLinks"`
		Password       json.RawMessage `json:"password"`
		HashedPassword json.RawMessage `json:"hashedPassword"`
		TOTPSecret     *string         `json:"totpSecret"`
		Metadata       []metadataJSON  `json:"metadata"`
	} `json:"human"`
	Machine  json.RawMessage `json:"machine"`
	Metadata []metadataJSON  `json:"metadata"`
}

type metadataJSON struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CreateGate handles the request execution on every user-creating method.
func (h *Hook) CreateGate(_ context.Context, body []byte) Result {
	var p requestPayload
	if err := json.Unmarshal(body, &p); err != nil || len(p.Request) == 0 {
		return failure("gate_unparsable")
	}
	switch p.FullMethod {
	case MethodV2CreateUser:
		return h.gateCreateUser(p)
	case MethodV2AddHumanUser, MethodV2BetaAddHumanUser, MethodV3AlphaCreateUser,
		MethodMgmtAddHumanUser, MethodMgmtImportHumanUser, MethodMgmtAddMachineUser,
		MethodAdminImportData,
		MethodV2AddIDPLink, MethodV2BetaAddIDPLink, MethodV3AlphaAddIDPAuthenticator:
		if h.touchesCustomers(p) {
			return refuse(http.StatusForbidden, "gate_path_closed", "Customer accounts are created only through GitHub sign-in.")
		}
		return pass("gate_other_org")
	default:
		return refuse(http.StatusForbidden, "gate_unknown_method", "User creation method not covered by the identity hook.")
	}
}

// touchesCustomers reports whether a non-CreateUser creation request could
// put a user into customers or link one to its GitHub IdP. It is
// deliberately coarse: the org resolved from the call's context, or the
// customers org ID, the GitHub IdP ID or the customers domain anywhere in
// the request. A false positive refuses an admin call; it never lets a user
// in.
func (h *Hook) touchesCustomers(p requestPayload) bool {
	if p.OrgID == h.cfg.CustomersOrgID {
		return true
	}
	raw := string(p.Request)
	if strings.Contains(raw, h.cfg.CustomersOrgID) || strings.Contains(raw, h.cfg.GitHubIdPID) {
		return true
	}
	var anyReq any
	if err := json.Unmarshal(p.Request, &anyReq); err != nil {
		return true
	}
	return containsOrgDomain(anyReq)
}

// containsOrgDomain reports whether a decoded request names its organization
// by domain (v2 AddHumanUser's organization.orgDomain and similar). Any such
// field counts, whatever its value: customers has more than one domain (its
// generated <org>.<instance> one besides mctl.ai), and the hook cannot
// resolve a domain to an organization, so it refuses rather than guess.
func containsOrgDomain(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "orgDomain" || k == "org_domain" {
				return true
			}
			if containsOrgDomain(val) {
				return true
			}
		}
	case []any:
		for _, val := range t {
			if containsOrgDomain(val) {
				return true
			}
		}
	}
	return false
}

func (h *Hook) gateCreateUser(p requestPayload) Result {
	var req createUserRequest
	if err := json.Unmarshal(p.Request, &req); err != nil {
		return failure("gate_unparsable_request")
	}
	linksGitHub := false
	if req.Human != nil {
		for _, l := range req.Human.IDPLinks {
			if l.IDPID == h.cfg.GitHubIdPID {
				linksGitHub = true
			}
		}
	}
	// Passing requires positive evidence: a request whose fields this code
	// does not recognise (a renamed field after an upgrade, another
	// spelling) is refused, never read as "not about customers". The raw
	// check catches the customers org or IdP named in any field.
	if req.Human == nil && len(req.Machine) == 0 {
		return refuse(http.StatusForbidden, "gate_unrecognised_request", "User creation request not understood by the identity hook.")
	}
	raw := string(p.Request)
	intoCustomers := req.OrganizationID == h.cfg.CustomersOrgID ||
		(req.OrganizationID == "" && p.OrgID == h.cfg.CustomersOrgID) ||
		strings.Contains(raw, h.cfg.CustomersOrgID)
	if !intoCustomers && !linksGitHub && !strings.Contains(raw, h.cfg.GitHubIdPID) {
		return pass("gate_other_org")
	}
	no := func(reason string) Result {
		return refuse(http.StatusForbidden, reason, "Customer accounts are created only through GitHub sign-in.")
	}
	// A GitHub-linked user outside customers would skip every rule below.
	if req.OrganizationID != h.cfg.CustomersOrgID {
		return no("gate_github_link_outside_customers")
	}
	if p.UserID != h.cfg.LoginClientUserID {
		// The caller id is logged so the configured value can be checked
		// against what ZITADEL sends (a System API user's id is its name).
		return no("gate_caller_not_login_client:" + p.UserID)
	}
	if req.Human == nil || len(req.Machine) > 0 {
		return no("gate_not_human")
	}
	if len(req.Human.Password) > 0 || len(req.Human.HashedPassword) > 0 || req.Human.TOTPSecret != nil {
		return no("gate_local_credentials")
	}
	if len(req.Human.IDPLinks) != 1 || req.Human.IDPLinks[0].IDPID != h.cfg.GitHubIdPID {
		return no("gate_idp_links")
	}
	link := req.Human.IDPLinks[0]
	if !digitsRE.MatchString(link.UserID) || !githubLoginRE.MatchString(link.UserName) {
		return no("gate_bad_link")
	}
	meta, ok := decodeMetadata(append(append([]metadataJSON{}, req.Metadata...), req.Human.Metadata...))
	if !ok {
		return no("gate_bad_metadata")
	}
	if meta[MetaGitHubID] != link.UserID || !strings.EqualFold(meta[MetaGitHubLogin], link.UserName) {
		return no("gate_metadata_mismatch")
	}
	if req.Human.Email == nil || !req.Human.Email.IsVerified || !validEmail(req.Human.Email.Email) {
		return no("gate_email_not_verified")
	}
	if req.Username != h.username(link.UserName) {
		return no("gate_username")
	}
	reserved, err := h.loginReservedAtCreation(link.UserName)
	if err != nil {
		return failure("gate_reserved_unreadable")
	}
	if reserved {
		return no("gate_login_reserved")
	}
	return pass("gate_customer_create")
}

// decodeMetadata decodes protojson bytes values. A key given twice with
// different values is malformed.
func decodeMetadata(entries []metadataJSON) (map[string]string, bool) {
	out := map[string]string{}
	for _, e := range entries {
		v, err := base64.StdEncoding.DecodeString(e.Value)
		if err != nil {
			if v, err = base64.URLEncoding.DecodeString(e.Value); err != nil {
				return nil, false
			}
		}
		if prev, dup := out[e.Key]; dup && prev != string(v) {
			return nil, false
		}
		out[e.Key] = string(v)
	}
	return out, true
}

// ---------------------------------------------------------- token claims

type functionPayload struct {
	Function string `json:"function"`
	User     *struct {
		ID            string `json:"id"`
		ResourceOwner string `json:"resource_owner"`
	} `json:"user"`
	UserMetadata []struct {
		Key   string `json:"key"`
		Value []byte `json:"value"`
	} `json:"user_metadata"`
	Application *struct {
		ClientID string `json:"client_id"`
	} `json:"application"`
}

type appendClaim struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// TokenClaims handles the preuserinfo and preaccesstoken functions.
func (h *Hook) TokenClaims(_ context.Context, body []byte) Result {
	var p functionPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return failure("token_unparsable")
	}
	fn := p.Function[strings.LastIndex(p.Function, "/")+1:]
	if fn != functionPreUserinfo && fn != functionPreAccessToken {
		return failure("token_unknown_function")
	}
	empty := func(reason string) Result { return Result{Status: http.StatusOK, Body: []byte(`{}`), Reason: reason} }
	if p.User == nil || p.User.ResourceOwner != h.cfg.CustomersOrgID {
		return empty("token_other_org")
	}
	if p.Application == nil || !h.clients[p.Application.ClientID] {
		return empty("token_client_not_listed")
	}
	meta := map[string]string{}
	for _, m := range p.UserMetadata {
		meta[m.Key] = string(m.Value)
	}
	id, login := meta[MetaGitHubID], meta[MetaGitHubLogin]
	refused := func(reason string) Result {
		return replace("token_refused_"+reason, map[string]any{
			"append_claims": []appendClaim{{Key: ClaimRefused, Value: reason}},
		})
	}
	if !digitsRE.MatchString(id) || !githubLoginRE.MatchString(login) {
		return refused(RefusedNoGitHubIdentity)
	}
	// Only the static list here: tenant members are reserved at creation
	// only (see loginReservedAtCreation). This catches a customer who
	// renames their GitHub account to an admin login.
	if h.reserved[strings.ToLower(login)] {
		return refused(RefusedLoginReserved)
	}
	return replace("token_claims", map[string]any{
		"append_claims": []appendClaim{
			{Key: ClaimOrg, Value: "customers"},
			{Key: ClaimIdP, Value: "github"},
			{Key: ClaimGitHubID, Value: id},
			{Key: ClaimGitHubLogin, Value: login},
		},
	})
}
