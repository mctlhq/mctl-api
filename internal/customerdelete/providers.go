// Package customerdelete implements narrow external effects for the customer
// teardown manifest. Provider failures are errors, never proof of absence.
package customerdelete

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-api/internal/principals"
)

type Providers struct {
	Issuer, CustomerOrg, GitHubIDP string
	ClientID, ClientSecret         string
	SiteBase, SessionAudience      string
	PortalBase, PortalToken        string
	HTTP                           *http.Client
}

func (p *Providers) Configured() bool {
	return p.Issuer != "" && p.CustomerOrg != "" && p.GitHubIDP != "" && p.ClientID != "" && p.ClientSecret != "" &&
		p.SiteBase != "" && p.SessionAudience != "" && p.PortalBase != "" && p.PortalToken != ""
}

func (p *Providers) request(ctx context.Context, method, path, token, contentType string, body []byte) (int, []byte, error) {
	client := p.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	req, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if strings.HasPrefix(token, "Basic ") {
		req.Header.Set("Authorization", token)
	} else if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("provider request failed: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil {
		return res.StatusCode, nil, err
	}
	if len(data) > 2*1024*1024 {
		return res.StatusCode, nil, fmt.Errorf("provider response too large")
	}
	return res.StatusCode, data, nil
}

func (p *Providers) zitadelToken(ctx context.Context) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"urn:zitadel:iam:org:project:id:zitadel:aud urn:zitadel:iam:org:project:id:" + p.SessionAudience + ":aud"}}
	status, data, err := p.request(ctx, "POST", strings.TrimRight(p.Issuer, "/")+"/oauth/v2/token", "Basic "+base64.StdEncoding.EncodeToString([]byte(p.ClientID+":"+p.ClientSecret)), "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", &serviceAuthenticationError{status: status}
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &body); err != nil || body.AccessToken == "" {
		return "", fmt.Errorf("IdP service token malformed")
	}
	return body.AccessToken, nil
}

func (p *Providers) verifyCustomer(ctx context.Context, d *principals.CustomerDeletion, token string, allowAbsent bool) (bool, error) {
	status, data, err := p.request(ctx, "GET", strings.TrimRight(p.Issuer, "/")+"/v2/users/"+url.PathEscape(d.Subject), token, "", nil)
	if err != nil {
		return false, err
	}
	if status == 404 && allowAbsent {
		return false, nil
	}
	if status != 200 {
		return false, fmt.Errorf("IdP user observation HTTP %d", status)
	}
	var user struct {
		User struct {
			ID       string          `json:"userId"`
			Username string          `json:"username"`
			Human    json.RawMessage `json:"human"`
			Details  struct {
				Owner string `json:"resourceOwner"`
			} `json:"details"`
		} `json:"user"`
	}
	if err := json.Unmarshal(data, &user); err != nil {
		return false, err
	}
	if user.User.ID != d.Subject || user.User.Details.Owner != p.CustomerOrg || len(user.User.Human) == 0 || string(user.User.Human) == "null" {
		return false, fmt.Errorf("target is not a human in the customer organization")
	}
	status, data, err = p.request(ctx, "POST", strings.TrimRight(p.Issuer, "/")+"/v2/users/"+url.PathEscape(d.Subject)+"/links/_search", token, "application/json", []byte(`{"query":{"limit":2}}`))
	if err != nil {
		return false, err
	}
	if status != 200 {
		return false, fmt.Errorf("IdP link observation HTTP %d", status)
	}
	var links struct {
		Details struct {
			Total json.RawMessage `json:"totalResult"`
		} `json:"details"`
		Result []struct {
			IDP  string `json:"idpId"`
			User string `json:"userId"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return false, err
	}
	if (string(links.Details.Total) != "1" && string(links.Details.Total) != `"1"`) || len(links.Result) != 1 || links.Result[0].IDP != p.GitHubIDP || links.Result[0].User != d.GitHubID {
		return false, fmt.Errorf("customer GitHub identity link mismatch")
	}
	return true, nil
}

func (p *Providers) VerifyCustomer(ctx context.Context, d *principals.CustomerDeletion) error {
	token, err := p.zitadelToken(ctx)
	if err != nil {
		return err
	}
	_, err = p.verifyCustomer(ctx, d, token, false)
	return err
}

func (p *Providers) DeleteCustomer(ctx context.Context, d *principals.CustomerDeletion) error {
	token, err := p.zitadelToken(ctx)
	if err != nil {
		return err
	}
	present, err := p.verifyCustomer(ctx, d, token, true)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	path := strings.TrimRight(p.Issuer, "/") + "/v2/users/" + url.PathEscape(d.Subject)
	status, _, err := p.request(ctx, "DELETE", path, token, "", nil)
	if err != nil {
		return err
	}
	if status != 200 && status != 404 {
		return fmt.Errorf("IdP user deletion HTTP %d", status)
	}
	status, _, err = p.request(ctx, "GET", path, token, "", nil)
	if err != nil {
		return err
	}
	if status != 404 {
		return fmt.Errorf("IdP user absence not observed (HTTP %d)", status)
	}
	return nil
}

// The Worker owns its KV binding. The API needs only the narrow lifecycle
// machine credential, never a Cloudflare account-level KV administration token.
func (p *Providers) RevokeSiteSessions(ctx context.Context, d *principals.CustomerDeletion) error {
	token, err := p.zitadelToken(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"github_id": d.GitHubID, "subject": d.Subject})
	status, data, err := p.request(ctx, "POST", strings.TrimRight(p.SiteBase, "/")+"/api/internal/customer-sessions/revoke", token, "application/json", body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("site session revocation not complete (HTTP %d)", status)
	}
	var result struct {
		GitHubID string `json:"github_id"`
		Subject  string `json:"subject"`
		Complete bool   `json:"complete"`
	}
	if json.Unmarshal(data, &result) != nil || result.GitHubID != d.GitHubID || result.Subject != d.Subject || !result.Complete {
		return fmt.Errorf("site session revocation response malformed")
	}
	return nil
}

func (p *Providers) CleanPortal(ctx context.Context, d *principals.CustomerDeletion) error {
	body, _ := json.Marshal(map[string]string{"principal_id": d.PrincipalID, "login": d.Login})
	status, data, err := p.request(ctx, "POST", strings.TrimRight(p.PortalBase, "/")+"/api/tenant-management/internal/tenants/"+url.PathEscape(d.Tenant)+"/cleanup", p.PortalToken, "application/json", body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("portal cleanup HTTP %d", status)
	}
	var result struct {
		Tenant  string `json:"tenant"`
		Cleaned bool   `json:"cleaned"`
		Scope   string `json:"scope"`
	}
	if json.Unmarshal(data, &result) != nil || result.Tenant != d.Tenant || !result.Cleaned || result.Scope != "customer" {
		return fmt.Errorf("portal cleanup response malformed")
	}
	return nil
}

func (p *Providers) portalLifecycle(ctx context.Context, d *principals.CustomerDeletion, stage string) error {
	body, _ := json.Marshal(map[string]string{"principal_id": d.PrincipalID, "login": d.Login})
	status, data, err := p.request(ctx, "POST", strings.TrimRight(p.PortalBase, "/")+"/api/tenant-management/internal/tenants/"+url.PathEscape(d.Tenant)+"/customer-deletion/"+stage, p.PortalToken, "application/json", body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("portal lifecycle %s HTTP %d", stage, status)
	}
	var result struct {
		Tenant      string `json:"tenant"`
		PrincipalID string `json:"principal_id"`
		Stage       string `json:"stage"`
		Complete    bool   `json:"complete"`
	}
	if json.Unmarshal(data, &result) != nil || result.Tenant != d.Tenant || result.PrincipalID != d.PrincipalID || result.Stage != stage || !result.Complete {
		return fmt.Errorf("portal lifecycle response malformed")
	}
	return nil
}
func (p *Providers) FreezePortal(ctx context.Context, d *principals.CustomerDeletion) error {
	return p.portalLifecycle(ctx, d, "prepare")
}
func (p *Providers) ReleasePortal(ctx context.Context, d *principals.CustomerDeletion) error {
	return p.portalLifecycle(ctx, d, "release")
}

func (p *Providers) CancelPortal(ctx context.Context, d *principals.CustomerDeletion) error {
	return p.portalLifecycle(ctx, d, "cancel")
}

type serviceAuthenticationError struct{ status int }

func (e *serviceAuthenticationError) Error() string {
	return fmt.Sprintf("IdP service authentication HTTP %d", e.status)
}

// SignupSiteError exposes only safe stage/status diagnostics to callers.
type SignupSiteError struct {
	Stage  string
	Status int
	Cause  error
}

func (e *SignupSiteError) Error() string { return "invitation bridge unavailable" }
func (e *SignupSiteError) Unwrap() error { return e.Cause }

// SignupSite reaches only the Worker's private invitation bridge, authenticated
// as the existing customer-lifecycle machine. It cannot call arbitrary URLs.
func (p *Providers) SignupSite(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if !strings.HasPrefix(path, "/api/internal/invitations/") {
		return nil, fmt.Errorf("invalid invitation bridge path")
	}
	token, err := p.zitadelToken(ctx)
	if err != nil {
		failure := &SignupSiteError{Stage: "service_authentication", Cause: err}
		var status *serviceAuthenticationError
		if errors.As(err, &status) {
			failure.Status = status.status
		}
		return nil, failure
	}
	status, data, err := p.request(ctx, method, strings.TrimRight(p.SiteBase, "/")+path, token, "application/json", body)
	if err != nil {
		return nil, &SignupSiteError{Stage: "site_request", Status: status, Cause: err}
	}
	if status != 200 {
		return nil, &SignupSiteError{Stage: "site_response", Status: status}
	}
	return data, nil
}
