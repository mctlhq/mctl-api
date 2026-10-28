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

package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

// ErrSupportResourceDisabled: OAUTH_SUPPORT_RESOURCE is empty.
var ErrSupportResourceDisabled = errors.New("support_audience_not_configured")

// ErrSupportTokenRefused: the caller may not be given a support token.
var ErrSupportTokenRefused = errors.New("support_token_refused")

// MaxSupportTokenTTL bounds the lifetime of a minted support token.
const MaxSupportTokenTTL = 15 * time.Minute

// SupportToken is a freshly minted support-audience access token. It is
// never renewable and never persisted.
type SupportToken struct {
	Token     string
	JTI       string
	Audience  string
	ExpiresAt time.Time
}

var supportTokenMints = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "mctl_support_token_mints_total",
	Help: "Support-audience tokens minted for the MCP support tools, by result (ok, disabled, refused, error).",
}, []string{"result"})

func init() { prometheus.MustRegister(supportTokenMints) }

// IssueSupportToken mints one short-lived access token for u whose audience
// is the support resource. It adds no authority: the token carries only the
// caller's principal, no groups and no refresh token, and a support-audience
// token reaches only the routes mctl-support relays. Every refusal is an
// error and mints nothing.
func (s *OAuthServer) IssueSupportToken(u *User, ttl time.Duration) (SupportToken, error) {
	tok, err := s.issueSupportToken(u, ttl)
	switch {
	case err == nil:
		supportTokenMints.WithLabelValues("ok").Inc()
	case errors.Is(err, ErrSupportResourceDisabled):
		supportTokenMints.WithLabelValues("disabled").Inc()
	case errors.Is(err, ErrSupportTokenRefused):
		supportTokenMints.WithLabelValues("refused").Inc()
	default:
		supportTokenMints.WithLabelValues("error").Inc()
	}
	return tok, err
}

func (s *OAuthServer) issueSupportToken(u *User, ttl time.Duration) (SupportToken, error) {
	if s.SupportResource == "" {
		return SupportToken{}, ErrSupportResourceDisabled
	}
	refuse := func(why string) (SupportToken, error) {
		return SupportToken{}, fmt.Errorf("%w: %s", ErrSupportTokenRefused, why)
	}
	if u == nil {
		return refuse("no caller")
	}
	if u.IsAgent() {
		return refuse("agent run principals are not given support tokens")
	}
	if _, ok := u.Surface(); ok || u.IsService() {
		return refuse("service and surface principals are not given support tokens")
	}
	if u.IsSupportAudience() {
		return refuse("a support-audience token cannot mint another")
	}
	if u.ViaPrincipalID() != "" {
		return refuse("relayed requests are not given support tokens")
	}
	if u.PrincipalUnresolved() {
		return refuse("the caller's principal is unresolved")
	}
	pid := u.PrincipalID()
	if pid == "" || !ValidPrincipalID(pid) {
		return refuse("the caller has no principal")
	}
	if ttl <= 0 || ttl > MaxSupportTokenTTL {
		return SupportToken{}, fmt.Errorf("support token ttl %s must be between 0 and %s", ttl, MaxSupportTokenTTL)
	}
	if err := s.checkMintPrincipal(pid); err != nil {
		// The checker's verdict (disabled, or no such principal) is a
		// refusal; a principal that could not be read stays an error.
		if errors.Is(err, ErrPrincipalDisabled) || errors.Is(err, ErrIdentityRefused) {
			return SupportToken{}, fmt.Errorf("%w: %w", ErrSupportTokenRefused, err)
		}
		return SupportToken{}, err
	}
	subject := pid
	if login, ok := u.GitHubLogin(); ok {
		subject = login
	} else if !s.PrincipalMode {
		return refuse("the caller has no GitHub login")
	}
	now := time.Now()
	exp := now.Add(ttl)
	jti := uuid.NewString()
	token, err := s.signAccessToken(jwtPayload{
		Issuer:    s.BaseURL,
		Subject:   subject,
		Audience:  audience{s.SupportResource},
		PID:       pid,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		ID:        jti,
	})
	if err != nil {
		return SupportToken{}, fmt.Errorf("sign support token: %w", err)
	}
	return SupportToken{Token: token, JTI: jti, Audience: s.SupportResource, ExpiresAt: exp}, nil
}
