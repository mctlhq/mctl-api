package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

func TestOAuthServerExchangeCodeReturnsRefreshToken(t *testing.T) {
	server := NewOAuthServer(
		"https://api.mctl.ai",
		"github-client",
		"github-secret",
		[]byte("jwt-secret"),
		[]string{"https://client.example/callback"},
		NewGitHubValidator(nil),
	)
	server.AccessTokenTTL = time.Hour
	server.RefreshTokenTTL = 24 * time.Hour

	code, err := server.IssueCode(
		"dmitrii",
		"client-1",
		"https://client.example/callback",
		testPKCEChallenge(t, "verifier-1"),
		[]string{"my-team"},
	)
	if err != nil {
		t.Fatalf("IssueCode failed: %v", err)
	}

	accessToken, refreshToken, err := server.ExchangeCode(
		code,
		"verifier-1",
		"client-1",
		"https://client.example/callback",
	)
	if err != nil {
		t.Fatalf("ExchangeCode failed: %v", err)
	}
	if accessToken == "" {
		t.Fatal("expected access token")
	}
	if refreshToken == "" {
		t.Fatal("expected refresh token")
	}

	user, err := server.ValidateJWT(accessToken)
	if err != nil {
		t.Fatalf("ValidateJWT failed: %v", err)
	}
	if user.ID != "dmitrii" {
		t.Fatalf("unexpected user id %q", user.ID)
	}
}

func TestOAuthServerRefreshRotatesToken(t *testing.T) {
	server := NewOAuthServer(
		"https://api.mctl.ai",
		"github-client",
		"github-secret",
		[]byte("jwt-secret"),
		[]string{"https://client.example/callback"},
		NewGitHubValidator(nil),
	)

	refreshToken, err := server.IssueRefreshToken("dmitrii", []string{"my-team"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	accessToken, rotatedRefreshToken, err := server.RefreshAccessToken(refreshToken, "client-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}
	if accessToken == "" {
		t.Fatal("expected access token")
	}
	if rotatedRefreshToken == "" {
		t.Fatal("expected rotated refresh token")
	}
	if rotatedRefreshToken == refreshToken {
		t.Fatal("expected refresh token rotation")
	}

	if _, _, err := server.RefreshAccessToken(refreshToken, "client-1"); err == nil {
		t.Fatal("expected rotated-out refresh token to fail")
	}
}

func TestOAuthServerRevokeRefreshToken(t *testing.T) {
	server := NewOAuthServer(
		"https://api.mctl.ai",
		"github-client",
		"github-secret",
		[]byte("jwt-secret"),
		[]string{"https://client.example/callback"},
		NewGitHubValidator(nil),
	)

	refreshToken, err := server.IssueRefreshToken("dmitrii", []string{"my-team"}, "client-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}
	server.RevokeRefreshToken(refreshToken)

	if _, _, err := server.RefreshAccessToken(refreshToken, "client-1"); err == nil {
		t.Fatal("expected revoked refresh token to fail")
	}
}

func testPKCEChallenge(t *testing.T, verifier string) string {
	t.Helper()
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
