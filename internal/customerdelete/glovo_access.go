package customerdelete

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-api/internal/auth"
	"github.com/mctlhq/mctl-api/internal/principals"
)

// Glovo access notifications (mctl-glovo#82, stage C). mctl-api keeps no
// email address of a principal, so the requester's address is read from the
// IdP at the moment a mail is sent and handed to the Worker with it. Nothing
// here stores or logs it.

// GlovoAccessNotifyPath is the Worker's private Glovo access bridge.
const GlovoAccessNotifyPath = "/api/internal/glovo-access/notify"

// ErrNoCustomerEmail is the documented absence of a usable address: the IdP
// answered, and it has no such customer or no verified email for them. A
// failed or ambiguous read is another error, never this one.
var ErrNoCustomerEmail = errors.New("no verified customer email on record")

// GlovoAccessConfigured reports whether the notify bridge and the email
// lookup can work at all.
func (p *Providers) GlovoAccessConfigured() bool {
	// verifyCustomer refuses a customer whose provider has no IdP id here, so
	// a missing one would fail every email of that provider instead of once
	// at boot.
	return p.GlovoAccessBridgeConfigured() && p.CustomerOrg != "" && p.GitHubIDP != "" && p.GoogleIDP != ""
}

// GlovoAccessBridgeConfigured reports whether the Worker bridge alone can
// work: the machine's credentials and the Worker's audience. It is all the
// owner card needs; the email lookup needs GlovoAccessConfigured.
func (p *Providers) GlovoAccessBridgeConfigured() bool {
	return p != nil && p.Issuer != "" && p.ClientID != "" && p.ClientSecret != "" &&
		p.SiteBase != "" && p.SessionAudience != ""
}

// GlovoAccessSite posts one notification to the Worker's Glovo access bridge
// as the customer-lifecycle machine. The path is fixed.
func (p *Providers) GlovoAccessSite(ctx context.Context, body []byte) ([]byte, error) {
	return p.siteCall(ctx, "POST", GlovoAccessNotifyPath, body)
}

// CustomerEmail reads the verified email of the customer whose proven
// external identity is (provider, subject) and whose IdP username is
// username. The user is found by username inside the customers
// organization, then held to the same proof a deletion needs: a human of
// that organization with exactly one IdP link, to that provider, naming that
// subject. Only then is the address used.
func (p *Providers) CustomerEmail(ctx context.Context, provider, subject, username string) (string, error) {
	d := &principals.CustomerDeletion{}
	switch provider {
	case auth.ProviderGoogle:
		d.GoogleSub = subject
	case auth.ProviderGitHub:
		d.GitHubID = subject
	default:
		return "", fmt.Errorf("customer email: unsupported provider")
	}
	if subject == "" || username == "" || strings.ContainsAny(username, "\"\\\r\n") {
		return "", fmt.Errorf("customer email: identity incomplete")
	}
	token, err := p.zitadelToken(ctx)
	if err != nil {
		return "", err
	}
	query, err := json.Marshal(map[string]any{
		"query": map[string]any{"limit": 2},
		"queries": []map[string]any{
			{"organizationIdQuery": map[string]string{"organizationId": p.CustomerOrg}},
			{"userNameQuery": map[string]string{"userName": username, "method": "TEXT_QUERY_METHOD_EQUALS"}},
		},
	})
	if err != nil {
		return "", err
	}
	status, data, err := p.request(ctx, "POST", strings.TrimRight(p.Issuer, "/")+"/v2/users", token, "application/json", query)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("IdP user search HTTP %d", status)
	}
	var found struct {
		Details *json.RawMessage `json:"details"`
		Result  *[]struct {
			ID       string `json:"userId"`
			Username string `json:"username"`
			Details  struct {
				Owner string `json:"resourceOwner"`
			} `json:"details"`
			Human *struct {
				Email struct {
					Email    string `json:"email"`
					Verified bool   `json:"isVerified"`
				} `json:"email"`
			} `json:"human"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &found); err != nil {
		return "", fmt.Errorf("IdP user search malformed: %w", err)
	}
	// A listing always carries its details; a body without them is not a
	// listing and proves nothing. With them, an absent or empty result is
	// the IdP's "no such user". More than one is ambiguous, never a pick.
	if found.Details == nil || string(*found.Details) == "null" {
		return "", fmt.Errorf("IdP user search malformed: no listing details")
	}
	if found.Result == nil || len(*found.Result) == 0 {
		return "", ErrNoCustomerEmail
	}
	if len(*found.Result) != 1 {
		return "", fmt.Errorf("IdP user search ambiguous")
	}
	u := (*found.Result)[0]
	if u.ID == "" || !strings.EqualFold(u.Username, username) || u.Details.Owner != p.CustomerOrg || u.Human == nil {
		return "", fmt.Errorf("IdP user search returned another user")
	}
	d.Subject = u.ID
	if _, err := p.verifyCustomer(ctx, d, token, false); err != nil {
		return "", err
	}
	email := u.Human.Email.Email
	if !u.Human.Email.Verified || !plainEmail(email) {
		return "", ErrNoCustomerEmail
	}
	return email, nil
}

// plainEmail accepts one bare address: no display name, list or header
// tricks.
func plainEmail(s string) bool {
	if len(s) < 3 || len(s) > 254 || strings.Count(s, "@") != 1 || strings.HasPrefix(s, "@") || strings.HasSuffix(s, "@") {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("<>,;:\"()[]\\", r) {
			return false
		}
	}
	return true
}
